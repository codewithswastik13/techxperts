"""QuantumShield Scanner Test Suite.

Tests detection accuracy, schema conformance, language support,
false-positive prevention, and security boundaries.
"""

from pathlib import Path
import os
import pytest

from backend.scanner import scan_repository

REQUIRED_SCHEMA_KEYS = {
    "file_path",
    "line_number",
    "language",
    "algorithm",
    "matched_pattern",
    "evidence",
}

SUPPORTED_ALGORITHMS = {
    "RSA",
    "ECC",
    "ECDH",
    "ECDSA",
    "AES",
    "SHA-256",
}

SUPPORTED_LANGUAGES = {"python", "java", "c"}

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_schema_conformance():
    """Verify that every finding contains the exact 6 required schema keys and valid types."""
    sample_dir = REPO_ROOT / "sample_data"
    findings = scan_repository(sample_dir)
    assert len(findings) > 0, "Expected findings from sample_data"

    for finding in findings:
        assert set(finding.keys()) == REQUIRED_SCHEMA_KEYS, f"Schema mismatch: {finding.keys()}"
        assert isinstance(finding["file_path"], str)
        assert not finding["file_path"].startswith("/"), "file_path must be relative"
        assert "\\" not in finding["file_path"], "file_path must use forward slashes"
        assert isinstance(finding["line_number"], int)
        assert finding["line_number"] >= 1, "line_number must be 1-based"
        assert finding["language"] in SUPPORTED_LANGUAGES
        assert finding["algorithm"] in SUPPORTED_ALGORITHMS
        assert isinstance(finding["matched_pattern"], str)
        assert len(finding["matched_pattern"]) > 0
        assert isinstance(finding["evidence"], str)
        assert len(finding["evidence"]) > 0


def test_python_crypto_detection():
    """Verify detection of RSA, ECC, ECDH, ECDSA, AES, and SHA-256 in Python."""
    py_dir = REPO_ROOT / "sample_data" / "python"
    findings = scan_repository(py_dir)
    crypto_sample_findings = [f for f in findings if "crypto_sample.py" in f["file_path"]]

    detected_algos = {f["algorithm"] for f in crypto_sample_findings}
    for algo in SUPPORTED_ALGORITHMS:
        assert algo in detected_algos, f"Expected {algo} to be detected in Python crypto sample"


def test_java_crypto_detection():
    """Verify detection of RSA, ECC, ECDH, ECDSA, AES, and SHA-256 in Java."""
    java_dir = REPO_ROOT / "sample_data" / "java"
    findings = scan_repository(java_dir)
    crypto_sample_findings = [f for f in findings if "CryptoSample.java" in f["file_path"]]

    detected_algos = {f["algorithm"] for f in crypto_sample_findings}
    for algo in SUPPORTED_ALGORITHMS:
        assert algo in detected_algos, f"Expected {algo} to be detected in Java crypto sample"


def test_c_crypto_detection():
    """Verify detection of RSA, ECC, ECDH, ECDSA, AES, and SHA-256 in C (.c and .h)."""
    c_dir = REPO_ROOT / "sample_data" / "c"
    findings = scan_repository(c_dir)
    crypto_sample_findings = [f for f in findings if "crypto_sample.c" in f["file_path"]]

    detected_algos = {f["algorithm"] for f in crypto_sample_findings}
    for algo in SUPPORTED_ALGORITHMS:
        assert algo in detected_algos, f"Expected {algo} to be detected in C crypto sample"

    # Verify .h header detection as well
    header_findings = [f for f in findings if "crypto_sample.h" in f["file_path"]]
    assert len(header_findings) > 0, "Expected findings from C header file"


def test_clean_samples_produce_no_findings():
    """Verify that comments, docstrings, and non-crypto code do not trigger false positives."""
    sample_dir = REPO_ROOT / "sample_data"
    findings = scan_repository(sample_dir)

    clean_findings = [
        f for f in findings
        if "clean_sample" in f["file_path"].lower() or "cleansample" in f["file_path"].lower()
    ]
    assert clean_findings == [], f"Expected 0 findings in clean files, got: {clean_findings}"


def test_line_number_accuracy(tmp_path):
    """Verify that reported line numbers match the exact line of code."""
    test_file = tmp_path / "test_auth.py"
    test_file.write_text(
        "# Header comment line 1\n"
        "# Header comment line 2\n"
        "import os\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"  # Line 4
        "def keygen():\n"
        "    return rsa.generate_private_key(65537, 2048)\n"          # Line 6
    )

    findings = scan_repository(tmp_path)
    line_numbers = [f["line_number"] for f in findings if f["algorithm"] == "RSA"]
    assert 4 in line_numbers
    assert 6 in line_numbers


def test_deterministic_output():
    """Verify that scanning the same repository twice produces identical, ordered results."""
    sample_dir = REPO_ROOT / "sample_data"
    run_1 = scan_repository(sample_dir)
    run_2 = scan_repository(sample_dir)
    assert run_1 == run_2


def test_empty_repository(tmp_path):
    """Verify that scanning an empty repository directory returns an empty list without error."""
    findings = scan_repository(tmp_path)
    assert findings == []


def test_invalid_and_nonexistent_paths(tmp_path):
    """Verify graceful handling of nonexistent paths and file paths."""
    nonexistent = tmp_path / "does_not_exist"
    assert scan_repository(nonexistent) == []

    file_path = tmp_path / "regular_file.txt"
    file_path.write_text("Hello world")
    assert scan_repository(file_path) == []


def test_file_size_limit(tmp_path):
    """Verify that files exceeding max_file_size_bytes are safely skipped."""
    oversized_file = tmp_path / "big_crypto.py"
    # Write 100 bytes containing RSA
    oversized_file.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")

    # With 50-byte limit, file should be skipped
    findings = scan_repository(tmp_path, max_file_size_bytes=50)
    assert len(findings) == 0


def test_binary_file_skipped(tmp_path):
    """Verify that binary files with .py extensions are ignored."""
    binary_file = tmp_path / "compiled_mock.py"
    # Write binary content with null byte and some text
    binary_file.write_bytes(b"\x00\x01\x02from cryptography.hazmat.primitives.asymmetric import rsa")

    findings = scan_repository(tmp_path)
    assert findings == []


def test_excluded_directories_ignored(tmp_path):
    """Verify that excluded directories (.git, node_modules, etc.) are not scanned."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "crypto.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")

    node_dir = tmp_path / "node_modules"
    node_dir.mkdir()
    (node_dir / "crypto.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")

    findings = scan_repository(tmp_path)
    assert findings == []


def test_symlink_outside_repository_ignored(tmp_path):
    """Verify that symlinks pointing outside the repository root are ignored for security."""
    outside_dir = tmp_path / "outside_secret"
    outside_dir.mkdir()
    outside_target = outside_dir / "secret_crypto.py"
    outside_target.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")

    repo_dir = tmp_path / "repo_root"
    repo_dir.mkdir()

    symlink_path = repo_dir / "linked_secret.py"
    try:
        os.symlink(outside_target, symlink_path)
    except OSError:
        pytest.skip("Symlink creation not supported in this test environment")

    findings = scan_repository(repo_dir)
    assert findings == []


def test_comment_stripping_with_quotes(tmp_path):
    """Verify comments following strings containing '#' or '//' are correctly stripped."""
    py_file = tmp_path / "test_quotes.py"
    py_file.write_text('url = "https://example.com/#tag"  # rsa.generate_private_key(65537, 2048)\n')

    c_file = tmp_path / "test_quotes.c"
    c_file.write_text('const char *u = "https://api.com"; // RSA_generate_key_ex(r, 2048, b, NULL);\n')

    findings = scan_repository(tmp_path)
    assert findings == [], f"Expected 0 findings from commented code, got: {findings}"


def test_same_line_algorithm_deduplication(tmp_path):
    """Verify that multiple patterns for the same algorithm on the same line are deduplicated."""
    test_file = tmp_path / "dedup.py"
    # ec.ECDH() and .exchange(ec.ECDH()) are on the same line
    test_file.write_text("shared = private_key.exchange(ec.ECDH(), peer_key)\n")

    findings = scan_repository(tmp_path)
    ecdh_findings = [f for f in findings if f["algorithm"] == "ECDH"]
    assert len(ecdh_findings) == 1, f"Expected 1 ECDH finding for line, got: {len(ecdh_findings)}"


def test_string_literals_do_not_trigger_false_positives(tmp_path):
    """Verify that string literals mentioning algorithm types do not trigger false positives."""
    java_file = tmp_path / "Strings.java"
    java_file.write_text(
        'public class Strings {\n'
        '    public static void main(String[] args) {\n'
        '        String info = "Missing RSAPublicKey or ECPublicKey config";\n'
        '        System.out.println(info);\n'
        '    }\n'
        '}\n'
    )

    c_file = tmp_path / "strings.c"
    c_file.write_text(
        '#include <stdio.h>\n'
        'int main() {\n'
        '    printf("EVP_PKEY_RSA and EVP_PKEY_EC in string\\n");\n'
        '    return 0;\n'
        '}\n'
    )

    findings = scan_repository(tmp_path)
    assert findings == [], f"Expected 0 findings from string literals, got: {findings}"


def test_legitimate_crypto_detected_after_filtering(tmp_path):
    """Verify legitimate crypto calls alongside strings are still detected."""
    test_file = tmp_path / "valid.py"
    test_file.write_text(
        'endpoint = "https://vault.internal/api/v1"\n'
        'key = rsa.generate_private_key(65537, 2048)  # Legitimate generation\n'
    )

    findings = scan_repository(tmp_path)
    assert len(findings) == 1
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["line_number"] == 2


def test_ecdh_and_ecdsa_not_classified_as_generic_ecc(tmp_path):
    """Verify ECDH and ECDSA are not incorrectly classified as generic ECC."""
    ecdh_file = tmp_path / "ecdh_client.py"
    ecdh_file.write_text("shared = private_key.exchange(ec.ECDH(), peer_key)\n")

    ecdsa_file = tmp_path / "ecdsa_signer.py"
    ecdsa_file.write_text("signature = signer.sign(payload, ec.ECDSA(hashes.SHA256()))\n")

    findings = scan_repository(tmp_path)
    ecdh_matches = [f for f in findings if f["file_path"] == "ecdh_client.py"]
    assert len(ecdh_matches) == 1
    assert ecdh_matches[0]["algorithm"] == "ECDH"

    ecdsa_matches = [f for f in findings if f["file_path"] == "ecdsa_signer.py" and f["algorithm"] == "ECDSA"]
    assert len(ecdsa_matches) == 1
    assert ecdsa_matches[0]["algorithm"] == "ECDSA"


def test_multiple_different_algorithms_on_one_line(tmp_path):
    """Verify that multiple different algorithms on the same line are both preserved."""
    test_file = tmp_path / "combo.py"
    test_file.write_text("sig = key.sign(data, ec.ECDSA(hashes.SHA256()))\n")

    findings = scan_repository(tmp_path)
    algos = {f["algorithm"] for f in findings}
    assert algos == {"ECDSA", "SHA-256"}
    # Both should have the same line number 1
    line_numbers = {f["line_number"] for f in findings}
    assert line_numbers == {1}
