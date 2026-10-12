# QuantumShield — Cryptographic Inventory & Migration Planner

**QFF 2026 Hackathon | PS-P2: Crypto Inventory & Migration Planner**  
**Track:** Cryptography / Post-Quantum Cryptography (PQC)  
**Repository:** https://github.com/codewithswastik13/techxperts

QuantumShield statically scans source code repositories to identify cryptographic algorithm usage, creates a structured cryptographic inventory, assesses potential quantum risk, and assists teams with post-quantum cryptography (PQC) migration planning.

The system is designed to analyze source code without executing it and to provide transparent, NIST-aligned recommendations for human review.

---

## 1. Architecture and Team Ownership

The project consists of three independently developed modules.

- **Member 1 — Cryptographic Scanner:** Detects cryptographic algorithm usage in source repositories.
- **Member 2 — Risk Engine:** Classifies findings, explains quantum-related risks, and provides migration recommendations.
- **Member 3 — API, Frontend and Reporting:** Integrates the modules through FastAPI and provides the React dashboard and report downloads.

### Project structure

```text
techxperts/
├── backend/
│   ├── scanner/
│   │   ├── scanner.py
│   │   ├── rules.py
│   │   └── README.md
│   ├── risk_engine/
│   │   ├── __init__.py
│   │   ├── rules.py
│   │   └── risk_engine.py
│   ├── app/
│   │   ├── main.py
│   │   └── scanner_stub.py
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
├── sample/
├── sample_data/
└── README.md
```

The exact files may evolve as the team integrates and tests the application.

---

## 2. Key Features

- Static cryptographic discovery across supported source languages.
- Structured findings with file paths, line numbers, evidence and algorithm information.
- Risk classification and purpose-aware migration recommendations.
- Separation of risk severity from migration priority.
- Manual-review flags for ambiguous or incomplete cryptographic usage.
- Secure ZIP upload and temporary extraction for repository analysis.
- Interactive dashboard with search, filtering and risk visualizations.
- JSON and CSV report downloads, where supported by the API.
- Automated scanner, risk-engine and API tests.

---

## 3. Security Principles

QuantumShield is designed to inspect source code as data.

- Uploaded source files must never be executed, imported or compiled during scanning.
- ZIP extraction must defend against path traversal, oversized archives and excessive entry counts.
- Temporary files must be isolated and cleaned up.
- Binary and irrelevant files should be excluded from source scanning.
- File size and repository scanning limits should be enforced.
- CSV exports should sanitize formula-like values.
- Static pattern matching may miss dynamically constructed or aliased cryptographic calls; findings require appropriate human review.

---

## 4. Post-Quantum Migration Guidance

Recommendations depend on the algorithm's actual purpose and deployment context.

| Classical cryptographic use | Potential migration direction |
|---|---|
| RSA or elliptic-curve key establishment | Evaluate NIST FIPS 203 ML-KEM for the applicable key-establishment workflow |
| RSA or ECDSA digital signatures | Evaluate NIST FIPS 204 ML-DSA for the applicable signature workflow |
| AES-128 | Evaluate AES-256 where a larger symmetric security margin is appropriate |
| AES-256 | Retain an appropriate symmetric-cryptography assessment; do not automatically replace it with a PQC public-key algorithm |
| SHA-256 | Assess hash-function requirements separately from encryption and signature migration |

These are planning directions, not automatic replacements. Compatibility, protocol design, key management, interoperability and operational requirements must be evaluated before migration.

---

## 5. Quickstart

### Prerequisites

- Python 3.10 or later
- Node.js and npm compatible with the frontend project
- Git

### Clone the repository

```bash
git clone https://github.com/codewithswastik13/techxperts.git
cd techxperts
```

Use the branch agreed upon by the team for the integrated application.

### Backend setup

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install the backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Start the API:

```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```

API documentation should be available at:

`http://localhost:8000/docs`

### Frontend setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite in the terminal.

Build the frontend for production:

```bash
npm run build
```

---

## 6. API Endpoints

The API implementation provides or is intended to provide the following endpoints. Confirm the current implementation before relying on any endpoint.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Check API health and module availability |
| POST | `/api/scan` | Upload a ZIP archive and analyze its source files |
| GET | `/api/scans` | List available scan sessions |
| GET | `/api/scan/{scan_id}/report?format=json` | Retrieve a JSON report |
| GET | `/api/scan/{scan_id}/report?format=csv` | Retrieve a CSV report |

---

## 7. Running Tests

Run the backend test suite from the repository root:

```bash
python -m pytest backend/tests/ -v
```

Run an individual test module:

```bash
python -m pytest backend/tests/test_scanner.py -v
python -m pytest backend/tests/test_risk_engine.py -v
python -m pytest backend/tests/test_api.py -v
```

Build the frontend:

```bash
npm --prefix frontend run build
```

Run only the test commands relevant to the files currently present in the repository.

---

## 8. Scanner Documentation

### Supported languages and file types

- Python: `.py`
- Java: `.java`
- C: `.c`, `.h`

Additional language support depends on the implemented scanner rules.

### Cryptographic patterns

The scanner identifies supported patterns associated with:

- RSA
- ECC
- ECDH
- ECDSA
- AES
- SHA-256

Detection depends on the available source context and implemented patterns. The scanner is a static heuristic tool, not a complete proof of all cryptographic usage.

### Scanner interface

```python
from backend.scanner import scan_repository

findings = scan_repository("sample_data")
```

### Finding schema

Each finding is expected to contain:

```json
{
  "file_path": "sample_data/python/crypto_sample.py",
  "line_number": 20,
  "language": "python",
  "algorithm": "RSA",
  "matched_pattern": "RSA-related usage",
  "evidence": "synthetic cryptographic API call"
}
```

The fields identify where a pattern was found and provide concise evidence for the risk engine.

### Scanner safeguards

- No execution of scanned source code.
- Exclusion of irrelevant directories and binary files.
- File-size and repository-size limits.
- Protection against symbolic links escaping the repository root, where implemented.
- Resilient source decoding.
- Deterministic findings where supported.

### Known limitations

- Dynamically constructed algorithm names may not be detected.
- Aliased imports and custom wrappers can complicate detection.
- Reflection, macro expansion and runtime-generated code may require additional analysis.
- Static findings should be reviewed before production migration decisions.

---

## 9. Reporting and Evaluation

Reports should preserve scanner metadata and include risk classification, cryptographic purpose, explanations, migration recommendations, priority and manual-review status where available.

Synthetic evaluation data can help test expected behavior, but it does not establish real-world detection accuracy. Official benchmark results must be measured against the applicable evaluation dataset and protocol.

---

## 10. Team Workflow

The team uses separate feature branches:

- `feature/scanner`
- `feature/risk-engine`
- `feature/frontend-api`

Developers should work on their own branches, preserve the shared Git history, test their changes, and use pull requests for integration.

Avoid force-pushing, overwriting another member's work, or creating unrelated Git histories.

---

## 11. Limitations and Future Work

- Improve static analysis for aliases and complex cryptographic API usage.
- Expand language and library coverage.
- Evaluate against a ground-truth dataset.
- Improve protocol-aware migration recommendations.
- Add deployment-specific validation and operational guidance.

QuantumShield is a migration-planning aid. Its recommendations are not a substitute for a complete cryptographic architecture review.
