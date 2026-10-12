"""QuantumShield Core Cryptographic Scanner.

Statically inspects source code in Python, Java, and C to identify classical
and asymmetric cryptographic algorithm usage (RSA, ECC, ECDH, ECDSA, AES, SHA-256).

Never executes, compiles, or imports scanned code.
"""

from pathlib import Path
import os
import re
from typing import Dict, List, Optional, Set, Tuple, Union

from .rules import EXTENSION_TO_LANGUAGE, RULES, DetectionRule


# Default configuration limits
MAX_FILE_SIZE_BYTES: int = 1_000_000  # 1 MB limit per file
MAX_FILE_COUNT: int = 5_000            # Repository file scan cap
BINARY_HEADER_SAMPLE_SIZE: int = 1024 # Bytes to inspect for null byte

# Excluded directory names (exact matches or dot-directories)
EXCLUDED_DIR_NAMES: Set[str] = {
    ".git",
    ".venv",
    "venv",
    "env",
    "ENV",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".coverage",
    "htmlcov",
}


def is_binary_file(file_path: Path) -> bool:
    """Check if a file appears to be binary by inspecting for null bytes."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(BINARY_HEADER_SAMPLE_SIZE)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


def strip_python_line_comments(
    line: str,
    in_docstring: Optional[str]
) -> Tuple[str, Optional[str]]:
    """
    Remove comments and docstrings from Python source, respecting string literals.

    Returns:
        (code_line, updated_in_docstring_state)
    """
    cleaned = line

    # If currently inside a multi-line docstring
    if in_docstring:
        closing_idx = cleaned.find(in_docstring)
        if closing_idx != -1:
            cleaned = cleaned[closing_idx + len(in_docstring):]
            in_docstring = None
        else:
            return "", in_docstring

    res: List[str] = []
    i = 0
    n = len(cleaned)
    in_quote: Optional[str] = None

    while i < n:
        # Check docstring delimiter when not inside a regular string
        if not in_quote:
            matched_delim = False
            for delimiter in ('"""', "'''"):
                if cleaned[i:i + 3] == delimiter:
                    close_idx = cleaned.find(delimiter, i + 3)
                    if close_idx != -1:
                        # Delimiter starts and closes on the same line
                        i = close_idx + 3
                        matched_delim = True
                        break
                    else:
                        # Multi-line docstring begins here
                        in_docstring = delimiter
                        return "".join(res), in_docstring
            if matched_delim:
                continue

        if i >= n:
            break

        ch = cleaned[i]

        # Handle escaped characters inside strings
        if in_quote and ch == "\\":
            res.append(ch)
            if i + 1 < n:
                res.append(cleaned[i + 1])
                i += 2
                continue
            i += 1
            continue

        if not in_quote:
            if ch == "#":
                # Real comment begins; ignore remainder of line
                break
            elif ch in ("'", '"'):
                in_quote = ch
                res.append(ch)
            else:
                res.append(ch)
        else:
            if ch == in_quote:
                in_quote = None
            res.append(ch)
        i += 1

    return "".join(res), in_docstring


def strip_c_java_line_comments(
    line: str,
    in_block_comment: bool
) -> Tuple[str, bool]:
    """
    Remove comments from C or Java source (handles // and /* ... */, respecting strings).

    Returns:
        (code_line, updated_in_block_comment_state)
    """
    cleaned = line

    # If inside a multi-line block comment
    if in_block_comment:
        closing_idx = cleaned.find("*/")
        if closing_idx != -1:
            cleaned = cleaned[closing_idx + 2:]
            in_block_comment = False
        else:
            return "", True

    res: List[str] = []
    i = 0
    n = len(cleaned)
    in_quote: Optional[str] = None

    while i < n:
        # Check block and line comments when not inside quotes
        if not in_quote:
            if cleaned[i:i + 2] == "/*":
                closing_idx = cleaned.find("*/", i + 2)
                if closing_idx != -1:
                    i = closing_idx + 2
                    continue
                else:
                    in_block_comment = True
                    return "".join(res), True
            elif cleaned[i:i + 2] == "//":
                # Single-line comment starts; ignore remainder of line
                break

        ch = cleaned[i]

        # Handle escaped characters inside quotes
        if in_quote and ch == "\\":
            res.append(ch)
            if i + 1 < n:
                res.append(cleaned[i + 1])
                i += 2
                continue
            i += 1
            continue

        if not in_quote:
            if ch in ("'", '"'):
                in_quote = ch
                res.append(ch)
            else:
                res.append(ch)
        else:
            if ch == in_quote:
                in_quote = None
            res.append(ch)
        i += 1

    return "".join(res), in_block_comment


def is_index_in_string(line: str, index: int) -> bool:
    """Check if a character position in line falls within a string literal."""
    in_quote: Optional[str] = None
    i = 0
    while i < index and i < len(line):
        ch = line[i]
        if in_quote and ch == "\\":
            i += 2
            continue
        if not in_quote:
            if ch in ('"', "'"):
                in_quote = ch
        elif ch == in_quote:
            in_quote = None
        i += 1
    return in_quote is not None


def scan_file(
    file_path: Path,
    relative_path: str,
    language: str
) -> List[dict]:
    """
    Inspect a single source-code file for cryptographic patterns.

    Returns findings matching the QuantumShield schema.
    """
    findings: List[dict] = []
    rules = RULES.get(language, [])
    if not rules:
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return findings

    in_docstring: Optional[str] = None
    in_block_comment: bool = False

    for line_idx, raw_line in enumerate(lines, start=1):
        # Strip comments while preserving raw_line for evidence
        if language == "python":
            code_line, in_docstring = strip_python_line_comments(raw_line, in_docstring)
        else:  # java or c
            code_line, in_block_comment = strip_c_java_line_comments(raw_line, in_block_comment)

        if not code_line.strip():
            continue

        # Prevent duplicate findings for the same algorithm on the same line
        matched_algorithms_for_line: Set[str] = set()

        for rule in rules:
            for match in rule.pattern.finditer(code_line):
                # Ensure the pattern does not start within an arbitrary string literal
                if is_index_in_string(code_line, match.start()):
                    continue

                if rule.algorithm in matched_algorithms_for_line:
                    break
                matched_algorithms_for_line.add(rule.algorithm)

                # Format evidence: clean whitespace, cap at 160 characters
                evidence = raw_line.strip()
                if len(evidence) > 160:
                    evidence = evidence[:157] + "..."

                findings.append({
                    "file_path": relative_path,
                    "line_number": line_idx,
                    "language": language,
                    "algorithm": rule.algorithm,
                    "matched_pattern": rule.matched_pattern,
                    "evidence": evidence,
                })
                break

    return findings


def scan_repository(
    path: Union[str, Path],
    max_file_size_bytes: int = MAX_FILE_SIZE_BYTES,
    max_file_count: int = MAX_FILE_COUNT
) -> List[dict]:
    """
    Statically scan a local repository directory for cryptographic algorithm usage.

    Args:
        path: Path to the repository root directory.
        max_file_size_bytes: Maximum size of an individual file to scan (bytes).
        max_file_count: Maximum total files to scan before stopping.

    Returns:
        A list of structured findings adhering to the QuantumShield schema:
        [
            {
                "file_path": "src/auth.py",
                "line_number": 25,
                "language": "python",
                "algorithm": "RSA",
                "matched_pattern": "RSA key generation (cryptography)",
                "evidence": "private_key = rsa.generate_private_key(...)"
            },
            ...
        ]
    """
    repo_path = Path(path).resolve()

    # Graceful handling of invalid or non-directory paths
    if not repo_path.exists() or not repo_path.is_dir():
        return []

    all_findings: List[dict] = []
    scanned_file_count = 0

    for root_dir, dir_names, file_names in os.walk(repo_path, followlinks=False):
        # Exclude directories in-place to prevent os.walk from recursing into them
        dir_names[:] = [
            d for d in dir_names
            if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")
        ]

        # Sort for deterministic directory traversal order
        dir_names.sort()
        file_names.sort()

        for filename in file_names:
            if scanned_file_count >= max_file_count:
                break

            full_file_path = Path(root_dir) / filename

            # Boundary safeguard: skip symlinks pointing outside the repository root
            try:
                resolved_file_path = full_file_path.resolve()
                if not resolved_file_path.is_relative_to(repo_path):
                    continue
            except (ValueError, RuntimeError, OSError):
                continue

            # Check supported file extension
            extension = full_file_path.suffix.lower()
            language = EXTENSION_TO_LANGUAGE.get(extension)
            if not language:
                continue

            # File size limit safeguard
            try:
                if full_file_path.stat().st_size > max_file_size_bytes:
                    continue
            except (OSError, PermissionError):
                continue

            # Binary file safeguard
            if is_binary_file(full_file_path):
                continue

            # Normalize relative path with standard forward slashes
            try:
                relative_path = full_file_path.relative_to(repo_path).as_posix()
            except ValueError:
                continue

            file_findings = scan_file(full_file_path, relative_path, language)
            all_findings.extend(file_findings)
            scanned_file_count += 1

    # Deterministic output sorting by file_path, line_number, algorithm, pattern
    all_findings.sort(
        key=lambda item: (
            item["file_path"],
            item["line_number"],
            item["algorithm"],
            item["matched_pattern"]
        )
    )

    return all_findings
