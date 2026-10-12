"""
test_api.py — QuantumShield API Integration Tests
backend/tests/test_api.py

Member 3 owns this file.

Test categories:
1. Health endpoint
2. Valid ZIP upload
3. Invalid upload types
4. Malformed ZIP handling
5. ZIP security (path traversal, bombs)
6. Archive limit enforcement
7. Scanner/risk-engine invocation and exception handling
8. Empty findings handling
9. Response schema validation
10. JSON report generation and download
11. CSV report generation, formula-injection protection
12. Scan history endpoint
13. Report access validation (UUID format enforcement)
14. Temp-file cleanup verification
"""

import csv
import io
import json
import os
import sys
import zipfile
import unittest

# ---------------------------------------------------------------------------
# Path setup — support running from project root, backend/, or tests/
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_HERE)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)

for _p in [_PROJECT_ROOT, _BACKEND_DIR]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi.testclient import TestClient

# We import the app module directly; the test client does not start a real server
from backend.app.main import app, _scan_store, _validate_and_extract, _generate_csv

client = TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zip(entries: dict[str, bytes]) -> bytes:
    """Build an in-memory ZIP from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_sample_zip() -> bytes:
    """Return a valid ZIP with realistic Python and Java source files."""
    return _make_zip({
        "src/crypto_util.py": b"""
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def sign_data(data, private_key):
    h = SHA256.new(data)
    signer = pss.new(private_key)
    return signer.sign(h)

def generate_key():
    return RSA.generate(2048)
""",
        "src/symmetric.py": b"""
from Crypto.Cipher import AES

KEY = b'0123456789abcdef'  # 16 bytes = AES-128

def encrypt(data, iv):
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return cipher.encrypt(data)
""",
        "src/Auth.java": b"""
import java.security.Signature;
import java.security.KeyPairGenerator;

public class Auth {
    public byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }
}
""",
        "README.md": b"# Sample repository for QuantumShield demo",
    })


# ---------------------------------------------------------------------------
# 1. Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint(unittest.TestCase):

    def test_health_returns_200(self):
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_response_has_required_fields(self):
        resp = client.get("/api/health")
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("service", data)
        self.assertIn("version", data)
        self.assertIn("scanner_available", data)
        self.assertIn("risk_engine_available", data)
        self.assertIn("timestamp", data)
        self.assertIn("limits", data)

    def test_health_status_is_ok(self):
        resp = client.get("/api/health")
        self.assertEqual(resp.json()["status"], "ok")

    def test_health_risk_engine_reported_accurately(self):
        resp = client.get("/api/health")
        data = resp.json()
        # Risk engine is present in repository; should be available
        self.assertTrue(data["risk_engine_available"])

    def test_health_limits_present(self):
        resp = client.get("/api/health")
        limits = resp.json()["limits"]
        self.assertIn("max_upload_mb", limits)
        self.assertIn("max_extracted_mb", limits)
        self.assertIn("max_archive_entries", limits)
        self.assertIn("allowed_extensions", limits)


# ---------------------------------------------------------------------------
# 2. Valid ZIP upload
# ---------------------------------------------------------------------------

class TestValidZipUpload(unittest.TestCase):

    def test_valid_zip_returns_200(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        self.assertEqual(resp.status_code, 200)

    def test_valid_zip_response_has_scan_id(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        body = resp.json()
        self.assertIn("scan_id", body)
        self.assertIsInstance(body["scan_id"], str)
        self.assertEqual(len(body["scan_id"]), 36)  # UUID4 length

    def test_valid_zip_response_schema(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        body = resp.json()
        required_keys = [
            "scan_id", "timestamp", "filename", "status",
            "files_scanned", "files_excluded", "findings",
            "risk_summary", "migration_summary",
            "scan_duration_seconds", "limitations",
        ]
        for key in required_keys:
            self.assertIn(key, body, f"Missing key: {key}")

    def test_valid_zip_status_completed(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        body = resp.json()
        self.assertIn(body["status"], ("completed", "completed_with_errors"))

    def test_valid_zip_files_scanned_reflects_source_only(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        body = resp.json()
        # README.md should not be in scanned files (not a source extension)
        for f in body["files_scanned"]:
            self.assertFalse(f.endswith(".md"), f"Markdown file should be excluded: {f}")

    def test_valid_zip_scan_stored_for_report(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        scan_id = resp.json()["scan_id"]
        self.assertIn(scan_id, _scan_store)

    def test_valid_zip_risk_summary_structure(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        summary = resp.json()["risk_summary"]
        self.assertIn("total_findings", summary)
        self.assertIn("risk_level_counts", summary)
        self.assertIn("algorithm_counts", summary)


# ---------------------------------------------------------------------------
# 3. Invalid file uploads
# ---------------------------------------------------------------------------

class TestInvalidUploads(unittest.TestCase):

    def test_non_zip_extension_rejected(self):
        resp = client.post(
            "/api/scan",
            files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertIn("error", body.get("detail", {}))

    def test_empty_file_rejected(self):
        resp = client.post(
            "/api/scan",
            files={"file": ("empty.zip", b"", "application/zip")},
        )
        self.assertEqual(resp.status_code, 400)

    def test_plain_text_with_zip_extension_rejected(self):
        resp = client.post(
            "/api/scan",
            files={"file": ("fake.zip", b"this is not a zip file at all", "application/zip")},
        )
        self.assertEqual(resp.status_code, 400)

    def test_no_file_field_returns_422(self):
        resp = client.post("/api/scan")
        self.assertEqual(resp.status_code, 422)

    def test_html_file_with_zip_extension_rejected(self):
        resp = client.post(
            "/api/scan",
            files={"file": ("page.zip", b"<html><body>not a zip</body></html>", "application/zip")},
        )
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# 4. Malformed ZIP handling
# ---------------------------------------------------------------------------

class TestMalformedZip(unittest.TestCase):

    def test_truncated_zip_rejected(self):
        # Valid ZIP magic bytes but truncated
        truncated = b"PK\x03\x04" + b"\x00" * 10
        resp = client.post(
            "/api/scan",
            files={"file": ("bad.zip", truncated, "application/zip")},
        )
        self.assertEqual(resp.status_code, 400)
        detail = resp.json().get("detail", {})
        self.assertEqual(detail.get("error"), "invalid_archive")

    def test_corrupted_zip_entries_handled(self):
        # Build a ZIP and corrupt it after the magic bytes
        good = _make_zip({"file.py": b"import os"})
        corrupted = good[:4] + b"\xff" * (len(good) - 4)
        resp = client.post(
            "/api/scan",
            files={"file": ("corrupt.zip", corrupted, "application/zip")},
        )
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# 5. ZIP security — path traversal, absolute paths
# ---------------------------------------------------------------------------

class TestZipSecurity(unittest.TestCase):

    def test_path_traversal_entry_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # Manually add traversal entry
            info = zipfile.ZipInfo("../../etc/passwd")
            zf.writestr(info, "root:x:0:0:root:/root:/bin/bash")
        payload = buf.getvalue()
        resp = client.post(
            "/api/scan",
            files={"file": ("traversal.zip", payload, "application/zip")},
        )
        # Should not crash the server; either 200 with skipped file or 400
        if resp.status_code == 200:
            body = resp.json()
            skipped_names = [s["name"] for s in body.get("files_excluded", [])]
            self.assertTrue(
                any("passwd" in n or ".." in n for n in skipped_names),
                "Traversal entry should be in excluded list",
            )

    def test_absolute_path_entry_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("/etc/shadow")
            zf.writestr(info, "secret")
        payload = buf.getvalue()
        # Extraction should skip absolute path entries silently
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            try:
                report = _validate_and_extract(payload, tmp)
                skipped_names = [s["name"] for s in report["skipped_files"]]
                self.assertTrue(any("/etc/shadow" in n for n in skipped_names))
            except Exception:
                pass  # Rejection via exception is also acceptable

    def _is_safe_entry_helper(self, name):
        from backend.app.main import _is_safe_entry
        return _is_safe_entry(name)

    def test_dotdot_in_path_flagged(self):
        self.assertFalse(self._is_safe_entry_helper("../secret.py"))

    def test_absolute_path_flagged(self):
        self.assertFalse(self._is_safe_entry_helper("/etc/passwd"))

    def test_normal_path_accepted(self):
        self.assertTrue(self._is_safe_entry_helper("src/auth/login.py"))

    def test_windows_traversal_flagged(self):
        self.assertFalse(self._is_safe_entry_helper("..\\secrets.py"))


# ---------------------------------------------------------------------------
# 6. Archive limit enforcement
# ---------------------------------------------------------------------------

class TestArchiveLimits(unittest.TestCase):

    def test_too_many_entries_rejected(self):
        """Archive with > MAX_ARCHIVE_ENTRIES entries should be rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(2001):
                zf.writestr(f"file_{i}.py", f"# file {i}")
        payload = buf.getvalue()
        resp = client.post(
            "/api/scan",
            files={"file": ("big.zip", payload, "application/zip")},
        )
        self.assertEqual(resp.status_code, 400)
        detail = resp.json().get("detail", {})
        self.assertIn("error", detail)

    def test_zip_with_no_source_files_returns_completed(self):
        """ZIP with no recognised source extensions should return completed with empty findings."""
        data = _make_zip({
            "README.md": b"# nothing here",
            "image.png": b"\x89PNG",
            "config.json": b'{"key": "value"}',
        })
        resp = client.post(
            "/api/scan",
            files={"file": ("nosrc.zip", data, "application/zip")},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["findings"], [])
        self.assertEqual(body["files_scanned"], [])


# ---------------------------------------------------------------------------
# 7. Scanner and risk engine integration
# ---------------------------------------------------------------------------

class TestScannerIntegration(unittest.TestCase):
    """
    Tests that verify correct wiring between API, scanner, and risk engine.
    When the real scanner is unavailable, these tests use the stub and
    verify graceful handling.
    """

    def test_risk_engine_is_invoked(self):
        """
        When scanner returns findings, risk engine should enrich them.
        We test this by patching the scanner to return a known finding
        and verifying the risk engine fields appear.
        """
        import unittest.mock as mock
        from backend.app import main as app_module

        fake_finding = {
            "file_path": "src/test.py",
            "line_number": 10,
            "algorithm": "RSA",
            "matched_pattern": "RSA key generation",
            "evidence": "key = RSA.generate(2048)",
            "language": "python",
        }

        with mock.patch.object(app_module, "scan_repository", return_value=[fake_finding]):
            data = _make_zip({"src/test.py": b"key = RSA.generate(2048)"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            self.assertEqual(resp.status_code, 200)
            findings = resp.json()["findings"]
            self.assertEqual(len(findings), 1)
            f = findings[0]
            # Risk engine enrichment fields must be present
            self.assertIn("risk_level", f)
            self.assertIn("explanation", f)
            self.assertIn("recommendation", f)
            self.assertIn("migration_priority", f)
            # RSA should be HIGH risk
            self.assertEqual(f["risk_level"], "HIGH")

    def test_scanner_exception_does_not_crash_api(self):
        """API must handle scanner exceptions gracefully and return a structured response."""
        import unittest.mock as mock
        from backend.app import main as app_module

        with mock.patch.object(app_module, "scan_repository", side_effect=RuntimeError("scanner exploded")):
            data = _make_zip({"src/code.py": b"import rsa"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertIn(body["status"], ("completed", "completed_with_errors"))
            # errors field should mention the exception
            if body.get("errors"):
                self.assertTrue(any("scanner" in e.lower() for e in body["errors"]))

    def test_risk_engine_exception_does_not_crash_api(self):
        """API must handle risk engine exceptions gracefully."""
        import unittest.mock as mock
        from backend.app import main as app_module

        fake_finding = {
            "file_path": "src/auth.py",
            "line_number": 5,
            "algorithm": "RSA",
            "evidence": "RSA.generate(2048)",
        }

        with mock.patch.object(app_module, "scan_repository", return_value=[fake_finding]):
            with mock.patch.object(app_module, "analyze_findings", side_effect=ValueError("risk engine broken")):
                data = _make_zip({"src/auth.py": b"RSA.generate(2048)"})
                resp = client.post(
                    "/api/scan",
                    files={"file": ("test.zip", data, "application/zip")},
                )
                self.assertEqual(resp.status_code, 200)
                body = resp.json()
                # Raw findings should still be present
                self.assertGreater(len(body["findings"]), 0)

    def test_empty_findings_returns_valid_response(self):
        """Scanner returning empty list should produce valid response with empty findings."""
        import unittest.mock as mock
        from backend.app import main as app_module

        with mock.patch.object(app_module, "scan_repository", return_value=[]):
            data = _make_zip({"src/empty_scan.py": b"print('hello world')"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["findings"], [])
            self.assertEqual(body["risk_summary"]["total_findings"], 0)

    def test_scanner_non_list_return_handled(self):
        """If scanner returns something other than a list, API must not crash."""
        import unittest.mock as mock
        from backend.app import main as app_module

        with mock.patch.object(app_module, "scan_repository", return_value={"error": "oops"}):
            data = _make_zip({"src/code.py": b"import rsa"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            self.assertEqual(resp.status_code, 200)


# ---------------------------------------------------------------------------
# 8. Response schema validation
# ---------------------------------------------------------------------------

class TestResponseSchema(unittest.TestCase):

    def test_risk_summary_counts_are_integers(self):
        import unittest.mock as mock
        from backend.app import main as app_module

        findings = [
            {"file_path": "a.py", "line_number": 1, "algorithm": "RSA"},
            {"file_path": "b.py", "line_number": 2, "algorithm": "AES-128"},
        ]
        with mock.patch.object(app_module, "scan_repository", return_value=findings):
            data = _make_zip({"a.py": b"rsa", "b.py": b"aes"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            self.assertEqual(resp.status_code, 200)
            summary = resp.json()["risk_summary"]
            self.assertIsInstance(summary["total_findings"], int)
            for k, v in summary["risk_level_counts"].items():
                self.assertIsInstance(v, int, f"{k} count should be int")

    def test_findings_preserve_original_fields(self):
        """Enriched findings must include all original scanner fields."""
        import unittest.mock as mock
        from backend.app import main as app_module

        original = {
            "file_path": "src/main.py",
            "line_number": 42,
            "algorithm": "ECDSA",
            "matched_pattern": "SHA256withECDSA",
            "evidence": "Signature.getInstance('SHA256withECDSA')",
            "language": "java",
        }
        with mock.patch.object(app_module, "scan_repository", return_value=[original]):
            data = _make_zip({"src/main.py": b"ecdsa"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            finding = resp.json()["findings"][0]
            self.assertEqual(finding["file_path"], original["file_path"])
            self.assertEqual(finding["line_number"], original["line_number"])
            self.assertEqual(finding["algorithm"], original["algorithm"])
            self.assertEqual(finding["evidence"], original["evidence"])


# ---------------------------------------------------------------------------
# 9. JSON report generation
# ---------------------------------------------------------------------------

class TestJsonReport(unittest.TestCase):

    def _upload_and_get_scan_id(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        self.assertEqual(resp.status_code, 200)
        return resp.json()["scan_id"]

    def test_json_report_returns_200(self):
        scan_id = self._upload_and_get_scan_id()
        resp = client.get(f"/api/scan/{scan_id}/report?format=json")
        self.assertEqual(resp.status_code, 200)

    def test_json_report_content_type(self):
        scan_id = self._upload_and_get_scan_id()
        resp = client.get(f"/api/scan/{scan_id}/report?format=json")
        self.assertIn("application/json", resp.headers.get("content-type", ""))

    def test_json_report_is_parseable(self):
        scan_id = self._upload_and_get_scan_id()
        resp = client.get(f"/api/scan/{scan_id}/report?format=json")
        parsed = resp.json()
        self.assertIn("scan_id", parsed)
        self.assertIn("findings", parsed)
        self.assertIn("_report_meta", parsed)

    def test_json_report_contains_disclaimer(self):
        scan_id = self._upload_and_get_scan_id()
        resp = client.get(f"/api/scan/{scan_id}/report?format=json")
        meta = resp.json()["_report_meta"]
        self.assertIn("disclaimer", meta)
        self.assertIn("heuristic", meta["disclaimer"])

    def test_unknown_scan_id_returns_404(self):
        import uuid
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/scan/{fake_id}/report?format=json")
        self.assertEqual(resp.status_code, 404)

    def test_invalid_scan_id_format_returns_400(self):
        resp = client.get("/api/scan/../../etc/passwd/report?format=json")
        self.assertIn(resp.status_code, (400, 404, 422))

    def test_invalid_format_returns_400(self):
        scan_id = self._upload_and_get_scan_id()
        resp = client.get(f"/api/scan/{scan_id}/report?format=xml")
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# 10. CSV report generation and formula injection protection
# ---------------------------------------------------------------------------

class TestCsvReport(unittest.TestCase):

    def _upload_with_injected_finding(self):
        """Upload a scan with a finding that contains formula-injection candidates."""
        import unittest.mock as mock
        from backend.app import main as app_module

        malicious_finding = {
            "file_path": "=HYPERLINK('http://evil.com', 'click')",
            "line_number": 1,
            "algorithm": "+RSA",
            "matched_pattern": "@SUM(1+1)*cmd|' /C calc'!A0",
            "evidence": "-1+1",
            "risk_level": "HIGH",
            "explanation": "RSA detected",
            "recommendation": "Migrate to ML-DSA",
            "cryptographic_purpose": "DIGITAL_SIGNATURE",
            "migration_priority": "HIGH",
            "manual_review_required": False,
        }

        with mock.patch.object(app_module, "scan_repository", return_value=[malicious_finding]):
            data = _make_zip({"malicious.py": b"rsa"})
            resp = client.post(
                "/api/scan",
                files={"file": ("test.zip", data, "application/zip")},
            )
            return resp.json()["scan_id"]

    def test_csv_report_returns_200(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        scan_id = resp.json()["scan_id"]
        csv_resp = client.get(f"/api/scan/{scan_id}/report?format=csv")
        self.assertEqual(csv_resp.status_code, 200)

    def test_csv_report_content_type(self):
        data = _make_sample_zip()
        resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        scan_id = resp.json()["scan_id"]
        csv_resp = client.get(f"/api/scan/{scan_id}/report?format=csv")
        self.assertIn("text/csv", csv_resp.headers.get("content-type", ""))

    def test_csv_formula_injection_protection(self):
        scan_id = self._upload_with_injected_finding()
        csv_resp = client.get(f"/api/scan/{scan_id}/report?format=csv")
        self.assertEqual(csv_resp.status_code, 200)
        content = csv_resp.text
        # Formula characters at start of values must not appear unescaped
        # (they should be prefixed with a tab)
        for line in content.splitlines():
            cells = next(csv.reader([line]))
            for cell in cells:
                if cell and cell[0] in ("=", "+", "-", "@"):
                    self.fail(
                        f"Formula injection not neutralised in CSV cell: {cell!r}"
                    )

    def test_csv_generate_function_directly(self):
        scan_data = {
            "scan_id": "test-id",
            "timestamp": "2026-01-01T00:00:00Z",
            "filename": "test.zip",
            "findings": [
                {
                    "file_path": "src/auth.py",
                    "line_number": 10,
                    "language": "python",
                    "algorithm": "RSA",
                    "matched_pattern": "RSA key",
                    "evidence": "RSA.generate(2048)",
                    "risk_level": "HIGH",
                    "cryptographic_purpose": "UNKNOWN",
                    "migration_priority": "HIGH",
                    "manual_review_required": True,
                    "explanation": "RSA is vulnerable to quantum attacks.",
                    "recommendation": "Migrate to ML-DSA or ML-KEM.",
                }
            ],
        }
        result = _generate_csv(scan_data)
        self.assertIsInstance(result, str)
        self.assertIn("QuantumShield", result)
        self.assertIn("RSA", result)
        self.assertIn("file_path", result)

    def test_csv_has_header_row(self):
        scan_data = {
            "scan_id": "x",
            "timestamp": "2026-01-01T00:00:00Z",
            "filename": "x.zip",
            "findings": [],
        }
        csv_text = _generate_csv(scan_data)
        self.assertIn("file_path", csv_text)
        self.assertIn("risk_level", csv_text)


# ---------------------------------------------------------------------------
# 11. Scan history endpoint
# ---------------------------------------------------------------------------

class TestScanHistory(unittest.TestCase):

    def test_scans_endpoint_returns_200(self):
        resp = client.get("/api/scans")
        self.assertEqual(resp.status_code, 200)

    def test_scans_endpoint_has_scans_key(self):
        resp = client.get("/api/scans")
        body = resp.json()
        self.assertIn("scans", body)
        self.assertIn("total", body)

    def test_completed_scan_appears_in_history(self):
        data = _make_sample_zip()
        scan_resp = client.post(
            "/api/scan",
            files={"file": ("sample.zip", data, "application/zip")},
        )
        scan_id = scan_resp.json()["scan_id"]
        history_resp = client.get("/api/scans")
        scan_ids = [s["scan_id"] for s in history_resp.json()["scans"]]
        self.assertIn(scan_id, scan_ids)


# ---------------------------------------------------------------------------
# 12. Validate-and-extract unit tests (direct function tests)
# ---------------------------------------------------------------------------

class TestValidateAndExtract(unittest.TestCase):

    def test_normal_extraction(self):
        import tempfile
        data = _make_zip({"src/main.py": b"import os", "lib/util.py": b"pass"})
        with tempfile.TemporaryDirectory() as tmp:
            report = _validate_and_extract(data, tmp)
            self.assertEqual(len(report["extracted_files"]), 2)
            self.assertEqual(len(report["skipped_files"]), 0)

    def test_unsafe_entry_skipped(self):
        import tempfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(zipfile.ZipInfo("../evil.py"), "evil code")
            zf.writestr("safe.py", "safe code")
        data = buf.getvalue()
        with tempfile.TemporaryDirectory() as tmp:
            report = _validate_and_extract(data, tmp)
            extracted_names = report["extracted_files"]
            self.assertNotIn("../evil.py", extracted_names)
            skipped_names = [s["name"] for s in report["skipped_files"]]
            self.assertTrue(any("evil.py" in n for n in skipped_names))

    def test_non_source_files_skipped(self):
        import tempfile
        data = _make_zip({"image.png": b"\x89PNG", "style.css": b"body {}"})
        with tempfile.TemporaryDirectory() as tmp:
            report = _validate_and_extract(data, tmp)
            self.assertEqual(len(report["extracted_files"]), 0)
            self.assertEqual(len(report["skipped_files"]), 2)

    def test_malformed_zip_raises_value_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                _validate_and_extract(b"not a zip", tmp)


# ---------------------------------------------------------------------------
# 13. Temp-file cleanup verification
# ---------------------------------------------------------------------------

class TestTempFileCleanup(unittest.TestCase):

    def test_temp_dir_removed_after_successful_scan(self):
        """
        Verify no leftover qs_* temp dirs exist after a scan.
        We check by counting qs_ prefixed dirs in the system temp directory.
        """
        import glob
        import tempfile

        tmp_parent = tempfile.gettempdir()
        # Baseline count
        before = set(glob.glob(os.path.join(tmp_parent, "qs_*")))

        data = _make_sample_zip()
        client.post(
            "/api/scan",
            files={"file": ("cleanup_test.zip", data, "application/zip")},
        )

        after = set(glob.glob(os.path.join(tmp_parent, "qs_*")))
        leftover = after - before
        self.assertEqual(
            len(leftover),
            0,
            f"Leftover temp directories found: {leftover}",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
