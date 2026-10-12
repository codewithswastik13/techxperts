# QuantumShield — Cryptographic Inventory & Migration Planner
**QFF 2026 | PS-P2: Post-Quantum Cryptography**

QuantumShield statically scans source code repositories to identify classical cryptographic algorithm usage, creates a structured inventory of cryptographic assets, estimates quantum risk, and assists in post-quantum migration planning.

---

## Member 1 — Core Cryptographic Scanner

The scanner is the static discovery module of QuantumShield. It scans Python, Java, and C code without ever compiling, executing, or importing the scanned source files.

### 1. Supported Languages & File Types
- **Python**: `.py`
- **Java**: `.java`
- **C**: `.c`, `.h`

### 2. Supported Cryptographic Algorithms
- **RSA**: Key generation, padding schemes (OAEP, PKCS1v15), encryption/decryption APIs.
- **ECC**: Elliptic-curve key generation, parameter curves (SECP, Brainpool).
- **ECDH**: Elliptic-curve Diffie–Hellman key exchange and agreement APIs.
- **ECDSA**: Elliptic-curve digital signature algorithms and operations.
- **AES**: AES cipher instantiation, mode setup, key specifications, and encryption/decryption calls.
- **SHA-256**: Message digest, hash functions, and hashing primitive instantiations.

---

## Public Interface Contract

```python
from backend.scanner import scan_repository

findings = scan_repository(path="path/to/target_repository")
```

### Finding Schema
Each item in the returned list conforms to the agreed 6-field schema:

```json
{
  "file_path": "sample_data/python/crypto_sample.py",
  "line_number": 20,
  "language": "python",
  "algorithm": "RSA",
  "matched_pattern": "RSA private key generation (cryptography)",
  "evidence": "private_key = rsa.generate_private_key("
}
```

- `file_path` (*str*): Relative path from the repository root (normalized with forward slashes `/`).
- `line_number` (*int*): 1-based source line number.
- `language` (*str*): `"python"`, `"java"`, or `"c"`.
- `algorithm` (*str*): `"RSA"`, `"ECC"`, `"ECDH"`, `"ECDSA"`, `"AES"`, or `"SHA-256"`.
- `matched_pattern` (*str*): Concise explanation of the triggered detection rule.
- `evidence` (*str*): Sanitized source line excerpt (stripped of excess indentation, max 160 characters).

---

## Security & Filesystem Protections

1. **Zero Execution**: The scanner performs static regex and token analysis. It never runs, imports, or executes scanned code.
2. **Symlink Boundary Enforcement**: Resolves canonical paths and rejects symbolic links that attempt to escape the repository root.
3. **Directory Exclusions**: Automatically excludes `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `dist`, `build`, and hidden directories.
4. **File Size Capping**: Automatically skips files exceeding 1 MB (`MAX_FILE_SIZE_BYTES = 1_000_000`) to prevent denial-of-service.
5. **Scan Volume Cap**: Enforces a repository-level cap of 5,000 files (`MAX_FILE_COUNT = 5_000`).
6. **Binary Detection**: Scans the first 1,024 bytes for null bytes (`\x00`) and skips binary or compiled assets.
7. **Encoding Resilience**: Reads source files with `utf-8` using `replace` fallback to prevent encoding crashes.

---

## False Positive & Negative Handling

- **Comment Stripping**: The scanner strips single-line (`#`, `//`) and multi-line (`/* ... */`, docstrings) comments before matching patterns. References to algorithms inside comments do not trigger findings.
- **Pattern Context**: Avoids bare-word substring matches (e.g., matching a variable named `aes` or `rsa`), requiring library-qualified calls or imports.
- **Known Limitations**:
  - Dynamically constructed algorithm strings (e.g., `Cipher.getInstance(algo_var)`) cannot be statically resolved without semantic analysis.
  - Custom internal wrappers or aliased imports (e.g., `import cryptography.hazmat.primitives.asymmetric.rsa as r`) may require extended alias tracking.
  - Code obscured by heavy macro expansions in C or reflection in Java is not evaluated.

---

## Running the Scanner & Tests

### Setup Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
```

### Run Tests
```bash
PYTHONPATH=. pytest -v
```

### Run Sample Scan
```python
import json
from backend.scanner import scan_repository

results = scan_repository("sample_data")
print(f"Detected {len(results)} cryptographic findings.")
print(json.dumps(results[:2], indent=2))
```
