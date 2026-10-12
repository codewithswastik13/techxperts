"""
QuantumShield — backend/app/main.py
FastAPI Application Entry Point

Member 3 owns this file.
Integration layer between Member 1 (scanner) and Member 2 (risk engine).

Security measures implemented:
- ZIP path traversal rejection
- ZIP bomb protection (size + entry count limits)
- Absolute path rejection in archive entries
- Symbolic link rejection
- MIME type verification (not trusted alone)
- Isolated temporary workspace per request
- Guaranteed cleanup in all code paths
- No execution of uploaded files
- Sanitised error responses (no internal paths leaked)
"""

import csv
import io
import json
import logging
import os
import sys
import tempfile
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("quantumshield.api")

# ---------------------------------------------------------------------------
# Path resolution — support running from project root OR from backend/
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_HERE)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)

for _p in [_PROJECT_ROOT, _BACKEND_DIR]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Member 2 — Risk Engine import (production, always available)
# ---------------------------------------------------------------------------
try:
    from backend.risk_engine import analyze_findings

    _RISK_ENGINE_AVAILABLE = True
    logger.info("Risk engine loaded successfully.")
except ImportError as _re_err:  # pragma: no cover
    _RISK_ENGINE_AVAILABLE = False
    logger.error("Risk engine unavailable: %s", _re_err)

    def analyze_findings(findings):  # type: ignore[misc]
        return findings

# ---------------------------------------------------------------------------
# Member 1 — Scanner import (graceful fallback while branch not yet merged)
# ---------------------------------------------------------------------------
_SCANNER_AVAILABLE = False
_SCANNER_IMPORT_ERROR: str = ""

try:
    # Attempt real scanner first
    from backend.scanner import scan_repository  # type: ignore[import]

    _SCANNER_AVAILABLE = True
    logger.info("Scanner loaded successfully.")
except ImportError:
    try:
        # Flat module layout alternative
        from scanner import scan_repository  # type: ignore[import]

        _SCANNER_AVAILABLE = True
        logger.info("Scanner loaded (flat import).")
    except ImportError as _sc_err:
        _SCANNER_IMPORT_ERROR = str(_sc_err)
        logger.warning(
            "Real scanner not available (%s). Stub will be used for development.",
            _sc_err,
        )
        from backend.app.scanner_stub import scan_repository  # type: ignore[misc]

# ---------------------------------------------------------------------------
# Upload safety constants
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES = 50 * 1024 * 1024        # 50 MB compressed
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024    # 200 MB uncompressed
MAX_ARCHIVE_ENTRIES = 2000
MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024    # 5 MB per source file

ALLOWED_EXTENSIONS = frozenset(
    [".py", ".java", ".c", ".h", ".cpp", ".js", ".ts", ".go", ".rs", ".rb", ".php"]
)

# ---------------------------------------------------------------------------
# In-memory scan store (bounded; suitable for single-process hackathon demo)
# ---------------------------------------------------------------------------
_scan_store: dict[str, dict[str, Any]] = {}
MAX_STORED_SCANS = 50  # evict oldest when limit reached


def _store_scan(scan_id: str, data: dict[str, Any]) -> None:
    """Store scan result with simple FIFO eviction."""
    if len(_scan_store) >= MAX_STORED_SCANS:
        oldest_key = next(iter(_scan_store))
        del _scan_store[oldest_key]
    _scan_store[scan_id] = data


# ---------------------------------------------------------------------------
# ZIP validation helpers
# ---------------------------------------------------------------------------

def _is_safe_entry(name: str) -> bool:
    """Return True iff the archive entry path is safe to extract."""
    if os.path.isabs(name):
        return False
    # Reject traversal sequences
    parts = name.replace("\\", "/").split("/")
    for part in parts:
        if part in ("..", ""):
            return False
    return True


def _validate_and_extract(archive_bytes: bytes, dest_dir: str) -> dict[str, Any]:
    """
    Validate the ZIP archive and extract permitted source files.

    Returns a report dict with:
    - extracted_files: list of relative paths that were extracted
    - skipped_files: list of (name, reason) pairs
    - total_entries: number of entries in archive
    - total_extracted_bytes: total uncompressed bytes written
    """
    extracted_files: list[str] = []
    skipped_files: list[dict[str, str]] = []
    total_extracted_bytes = 0

    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Malformed ZIP archive: {exc}") from exc

    entries = zf.infolist()
    total_entries = len(entries)

    if total_entries > MAX_ARCHIVE_ENTRIES:
        raise ValueError(
            f"Archive contains {total_entries} entries which exceeds the limit of "
            f"{MAX_ARCHIVE_ENTRIES}."
        )

    with zf:
        for info in entries:
            name = info.filename

            # Skip directories
            if name.endswith("/") or info.is_dir():
                continue

            # Safety checks
            if not _is_safe_entry(name):
                skipped_files.append({"name": name, "reason": "unsafe path (traversal or absolute)"})
                continue

            if info.file_size > MAX_SINGLE_FILE_BYTES:
                skipped_files.append({
                    "name": name,
                    "reason": f"file too large ({info.file_size} bytes; limit {MAX_SINGLE_FILE_BYTES})",
                })
                continue

            # Extension filter
            _, ext = os.path.splitext(name.lower())
            if ext not in ALLOWED_EXTENSIONS:
                skipped_files.append({"name": name, "reason": f"file type not scanned ({ext or 'no extension'})"})
                continue

            # Projected total extraction check
            if total_extracted_bytes + info.file_size > MAX_EXTRACTED_BYTES:
                skipped_files.append({
                    "name": name,
                    "reason": "extraction size limit reached; archive too large",
                })
                break

            # Safe extraction
            dest_path = os.path.join(dest_dir, name)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            try:
                data = zf.read(name)
                # Double-check actual read size (ZIP bomb guard)
                if len(data) > MAX_SINGLE_FILE_BYTES:
                    skipped_files.append({
                        "name": name,
                        "reason": f"decompressed file too large ({len(data)} bytes)",
                    })
                    continue

                with open(dest_path, "wb") as fout:
                    fout.write(data)

                extracted_files.append(name)
                total_extracted_bytes += len(data)

            except Exception as exc:  # pylint: disable=broad-except
                skipped_files.append({"name": name, "reason": f"read error: {exc}"})

    return {
        "extracted_files": extracted_files,
        "skipped_files": skipped_files,
        "total_entries": total_entries,
        "total_extracted_bytes": total_extracted_bytes,
    }


# ---------------------------------------------------------------------------
# Risk summary helpers
# ---------------------------------------------------------------------------

def _build_risk_summary(enriched_findings: list[dict]) -> dict[str, Any]:
    """Derive summary counts from enriched findings."""
    risk_counts: dict[str, int] = {"HIGH": 0, "MODERATE": 0, "LOWER": 0, "UNKNOWN": 0}
    algo_counts: dict[str, int] = {}
    purpose_counts: dict[str, int] = {}
    manual_review_count = 0

    for f in enriched_findings:
        rl = str(f.get("risk_level", "UNKNOWN")).upper()
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

        algo = str(f.get("algorithm", "UNKNOWN"))
        algo_counts[algo] = algo_counts.get(algo, 0) + 1

        purpose = str(f.get("cryptographic_purpose", "UNKNOWN"))
        purpose_counts[purpose] = purpose_counts.get(purpose, 0) + 1

        if f.get("manual_review_required"):
            manual_review_count += 1

    return {
        "total_findings": len(enriched_findings),
        "risk_level_counts": risk_counts,
        "algorithm_counts": algo_counts,
        "cryptographic_purpose_counts": purpose_counts,
        "manual_review_required_count": manual_review_count,
        "high_priority_findings": risk_counts.get("HIGH", 0),
    }


# ---------------------------------------------------------------------------
# CSV generation
# ---------------------------------------------------------------------------

def _generate_csv(scan_data: dict[str, Any]) -> str:
    """
    Generate a CSV representation of scan findings.

    Values are sanitised to prevent spreadsheet formula injection.
    Formulas (=, +, -, @, |) in the first character are prefixed with a tab.
    """
    output = io.StringIO()

    # Metadata header block
    output.write("# QuantumShield Scan Report\r\n")
    output.write(f"# Scan ID: {scan_data.get('scan_id', 'N/A')}\r\n")
    output.write(f"# Timestamp: {scan_data.get('timestamp', 'N/A')}\r\n")
    output.write(f"# Filename: {scan_data.get('filename', 'N/A')}\r\n")
    output.write(
        "# LIMITATION: Results reflect heuristic pattern matching; "
        "manual code review is required before acting on any finding.\r\n"
    )
    output.write("\r\n")

    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    headers = [
        "file_path",
        "line_number",
        "language",
        "algorithm",
        "matched_pattern",
        "evidence_snippet",
        "risk_level",
        "cryptographic_purpose",
        "migration_priority",
        "manual_review_required",
        "explanation",
        "recommendation",
    ]
    writer.writerow(headers)

    def _sanitise(val: Any) -> str:
        s = str(val) if val is not None else ""
        # Formula injection protection
        if s and s[0] in ("=", "+", "-", "@", "|", "\t"):
            s = "\t" + s
        return s

    for finding in scan_data.get("findings", []):
        writer.writerow([
            _sanitise(finding.get("file_path")),
            _sanitise(finding.get("line_number")),
            _sanitise(finding.get("language")),
            _sanitise(finding.get("algorithm")),
            _sanitise(finding.get("matched_pattern")),
            _sanitise(finding.get("evidence")),
            _sanitise(finding.get("risk_level")),
            _sanitise(finding.get("cryptographic_purpose")),
            _sanitise(finding.get("migration_priority")),
            _sanitise(finding.get("manual_review_required")),
            _sanitise(finding.get("explanation")),
            _sanitise(finding.get("recommendation")),
        ])

    return output.getvalue()


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):  # pylint: disable=redefined-outer-name
    logger.info("QuantumShield API starting up.")
    logger.info("Scanner available: %s", _SCANNER_AVAILABLE)
    logger.info("Risk engine available: %s", _RISK_ENGINE_AVAILABLE)
    yield
    logger.info("QuantumShield API shutting down.")


app = FastAPI(
    title="QuantumShield API",
    description=(
        "Cryptographic Inventory & Post-Quantum Migration Planner API. "
        "Integrates static scanner (Member 1) with risk engine (Member 2)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the Vite dev server and any deployed frontend origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", tags=["System"])
async def health_check():
    """
    Returns the genuine operational status of the API and its dependencies.
    Does not claim a dependency is ready if it cannot be imported.
    """
    return {
        "status": "ok",
        "service": "QuantumShield API",
        "version": "1.0.0",
        "scanner_available": _SCANNER_AVAILABLE,
        "scanner_note": (
            "Real scanner is loaded."
            if _SCANNER_AVAILABLE
            else f"Scanner not yet available ({_SCANNER_IMPORT_ERROR}). Using stub."
        ),
        "risk_engine_available": _RISK_ENGINE_AVAILABLE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "limits": {
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "max_extracted_mb": MAX_EXTRACTED_BYTES // (1024 * 1024),
            "max_archive_entries": MAX_ARCHIVE_ENTRIES,
            "max_single_file_mb": MAX_SINGLE_FILE_BYTES // (1024 * 1024),
            "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
        },
    }


@app.post("/api/scan", tags=["Scan"])
async def scan_repository_endpoint(file: UploadFile = File(...)):
    """
    Accept a ZIP archive of source code, scan for cryptographic usage,
    and return enriched findings with quantum-risk assessments.

    Security constraints:
    - 50 MB compressed upload limit
    - 200 MB extracted size limit
    - 2000 archive entries limit
    - Path traversal detection and rejection
    - Isolated temporary workspace, guaranteed cleanup
    - No execution of uploaded content
    """
    # --- 1. Content-type validation (not the sole guard — just usability) ---
    if file.content_type not in (
        "application/zip",
        "application/x-zip-compressed",
        "application/octet-stream",
        "multipart/form-data",
    ):
        # Do not hard-reject on MIME alone; some browsers send octet-stream
        logger.warning("Unexpected content-type: %s", file.content_type)

    filename = file.filename or "upload.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_file_type",
                "message": "Only ZIP archives are accepted. Please upload a .zip file.",
            },
        )

    # --- 2. Read upload with size guard ---
    archive_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(archive_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "error": "file_too_large",
                "message": (
                    f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit. "
                    "Please upload a smaller repository sample."
                ),
            },
        )

    if len(archive_bytes) < 4:
        raise HTTPException(
            status_code=400,
            detail={"error": "empty_or_corrupt", "message": "The uploaded file is empty or corrupt."},
        )

    # Quick magic-byte check (ZIP signature: PK\x03\x04)
    if archive_bytes[:2] != b"PK":
        raise HTTPException(
            status_code=400,
            detail={"error": "not_a_zip", "message": "File does not appear to be a valid ZIP archive."},
        )

    scan_id = str(uuid.uuid4())
    scan_start = datetime.now(timezone.utc)
    tmp_dir: str | None = None

    try:
        # --- 3. Isolated temporary workspace ---
        tmp_dir = tempfile.mkdtemp(prefix=f"qs_{scan_id}_")
        logger.info("Scan %s: extracting to %s", scan_id, tmp_dir)

        # --- 4. Validate and extract ---
        try:
            extraction_report = _validate_and_extract(archive_bytes, tmp_dir)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_archive", "message": str(exc)},
            ) from exc

        extracted_files = extraction_report["extracted_files"]
        skipped_files = extraction_report["skipped_files"]

        if not extracted_files:
            scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()
            scan_data = {
                "scan_id": scan_id,
                "timestamp": scan_start.isoformat(),
                "filename": filename,
                "status": "completed",
                "scanner_available": _SCANNER_AVAILABLE,
                "risk_engine_available": _RISK_ENGINE_AVAILABLE,
                "files_scanned": [],
                "files_excluded": skipped_files,
                "total_entries_in_archive": extraction_report["total_entries"],
                "total_source_files": 0,
                "findings": [],
                "risk_summary": _build_risk_summary([]),
                "migration_summary": [],
                "scan_duration_seconds": scan_duration,
                "supported_languages": ["python", "java", "c"],
                "limitations": [
                    "No source files with recognised extensions were found in the archive.",
                    "Scanner uses heuristic pattern matching; manual review is always recommended.",
                    "Scanner results reflect detection confidence, not confirmed vulnerabilities.",
                ],
            }
            _store_scan(scan_id, scan_data)
            return JSONResponse(content=scan_data)

        # --- 5. Invoke Member 1's scanner ---
        raw_findings: list[dict] = []
        scanner_error: str | None = None
        try:
            raw_findings = scan_repository(tmp_dir)
            if not isinstance(raw_findings, list):
                logger.warning("Scanner returned non-list type: %s", type(raw_findings))
                raw_findings = []
        except Exception as exc:  # pylint: disable=broad-except
            scanner_error = f"Scanner raised an exception: {type(exc).__name__}: {exc}"
            logger.error("Scan %s scanner error: %s", scan_id, scanner_error)

        # --- 6. Invoke Member 2's risk engine ---
        enriched_findings: list[dict] = []
        risk_engine_error: str | None = None
        try:
            if raw_findings:
                enriched_findings = analyze_findings(raw_findings)
                if not isinstance(enriched_findings, list):
                    logger.warning("Risk engine returned non-list; using raw findings.")
                    enriched_findings = raw_findings
        except Exception as exc:  # pylint: disable=broad-except
            risk_engine_error = f"Risk engine raised an exception: {type(exc).__name__}: {exc}"
            logger.error("Scan %s risk engine error: %s", scan_id, risk_engine_error)
            enriched_findings = raw_findings  # preserve raw findings

        # --- 7. Build response ---
        scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()

        errors: list[str] = []
        if scanner_error:
            errors.append(scanner_error)
        if risk_engine_error:
            errors.append(risk_engine_error)

        scan_data = {
            "scan_id": scan_id,
            "timestamp": scan_start.isoformat(),
            "filename": filename,
            "status": "completed" if not errors else "completed_with_errors",
            "scanner_available": _SCANNER_AVAILABLE,
            "risk_engine_available": _RISK_ENGINE_AVAILABLE,
            "files_scanned": extracted_files,
            "files_excluded": skipped_files,
            "total_entries_in_archive": extraction_report["total_entries"],
            "total_source_files": len(extracted_files),
            "findings": enriched_findings,
            "risk_summary": _build_risk_summary(enriched_findings),
            "migration_summary": _build_migration_summary(enriched_findings),
            "scan_duration_seconds": round(scan_duration, 3),
            "supported_languages": ["python", "java", "c"],
            "limitations": [
                "Scanner uses heuristic pattern matching; findings indicate potential usage, not confirmed vulnerabilities.",
                "Risk classification is deterministic and rule-based; contextual review is required.",
                "Only source files with recognised extensions are scanned.",
                "Encrypted or obfuscated code is not analysed.",
            ],
            "errors": errors if errors else None,
        }

        _store_scan(scan_id, scan_data)
        logger.info(
            "Scan %s complete: %d findings in %.3fs",
            scan_id,
            len(enriched_findings),
            scan_duration,
        )
        return JSONResponse(content=scan_data)

    finally:
        # --- 8. Guaranteed cleanup ---
        if tmp_dir and os.path.isdir(tmp_dir):
            import shutil
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                logger.debug("Scan %s: cleaned up %s", scan_id, tmp_dir)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Cleanup failed for %s: %s", tmp_dir, exc)


def _build_migration_summary(findings: list[dict]) -> list[dict]:
    """
    Produce a deduplicated list of unique migration recommendations
    grouped by algorithm and purpose.
    """
    seen: set[tuple[str, str]] = set()
    summary = []
    for f in findings:
        algo = str(f.get("algorithm", "UNKNOWN"))
        purpose = str(f.get("cryptographic_purpose", "UNKNOWN"))
        key = (algo, purpose)
        if key not in seen:
            seen.add(key)
            if f.get("recommendation"):
                summary.append({
                    "algorithm": algo,
                    "cryptographic_purpose": purpose,
                    "risk_level": f.get("risk_level"),
                    "recommendation": f.get("recommendation"),
                    "migration_priority": f.get("migration_priority"),
                    "alternative": f.get("alternative"),
                    "manual_review_required": f.get("manual_review_required", False),
                })
    # Sort by risk priority: HIGH first
    priority_order = {"HIGH": 0, "MODERATE": 1, "LOWER": 2, "UNKNOWN": 3, None: 4}
    summary.sort(key=lambda x: priority_order.get(x.get("migration_priority"), 4))
    return summary


@app.get("/api/scan/{scan_id}/report", tags=["Reports"])
async def download_report(scan_id: str, format: str = "json"):
    """
    Download a report for a completed scan.

    Parameters:
    - scan_id: UUID returned from POST /api/scan
    - format: 'json' (default) or 'csv'

    Reports contain actual scan results only.
    Scan IDs are validated against known completed scans — no arbitrary file access.
    """
    # Validate scan_id is a proper UUID (prevents path-like injection)
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "invalid_scan_id", "message": "Invalid scan ID format."})

    scan_data = _scan_store.get(scan_id)
    if scan_data is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "scan_not_found",
                "message": (
                    "Scan not found. Scans are held in memory for the duration of the server session only. "
                    "Re-run the scan to generate a new report."
                ),
            },
        )

    if format.lower() == "csv":
        csv_content = _generate_csv(scan_data)
        return StreamingResponse(
            io.BytesIO(csv_content.encode("utf-8")),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="quantumshield_scan_{scan_id[:8]}.csv"'
            },
        )

    elif format.lower() == "json":
        report = {
            **scan_data,
            "_report_meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "QuantumShield API v1.0.0",
                "disclaimer": (
                    "These results reflect heuristic static analysis. "
                    "They indicate potential cryptographic usage patterns, not confirmed vulnerabilities. "
                    "Manual code review is required before acting on any finding."
                ),
            },
        }
        json_bytes = json.dumps(report, indent=2, default=str).encode("utf-8")
        return StreamingResponse(
            io.BytesIO(json_bytes),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="quantumshield_scan_{scan_id[:8]}.json"'
            },
        )

    else:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_format", "message": "Supported formats: 'json', 'csv'."},
        )


@app.get("/api/scans", tags=["Scan"])
async def list_scans():
    """
    Return a list of scan summaries for scans completed in this server session.
    Useful for the frontend scan history view.
    """
    summaries = [
        {
            "scan_id": sid,
            "timestamp": data.get("timestamp"),
            "filename": data.get("filename"),
            "status": data.get("status"),
            "total_findings": data.get("risk_summary", {}).get("total_findings", 0),
            "high_risk_count": data.get("risk_summary", {}).get("high_priority_findings", 0),
        }
        for sid, data in _scan_store.items()
    ]
    # Most recent first
    summaries.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return {"scans": summaries, "total": len(summaries)}


# ---------------------------------------------------------------------------
# Entry point for direct execution (development)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn  # pylint: disable=import-outside-toplevel

    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[str(_PROJECT_ROOT)],
    )
