# QuantumShield: Crypto Inventory & Migration Planner

> **QFF 2026 Hackathon | PS-P2: Crypto Inventory & Migration Planner**  
> **Track:** Cryptography / Post-Quantum Cryptography (PQC)  
> **Shared Repository:** [github.com/codewithswastik13/techxperts](https://github.com/codewithswastik13/techxperts)

QuantumShield is an enterprise-grade automated scanning and migration planning tool that audits multi-language source repositories for classical cryptographic algorithms vulnerable to quantum computing attacks (Shor's and Grover's algorithms) and produces actionable, NIST-aligned post-quantum cryptographic (PQC) migration roadmaps.

---

## 1. Architecture & Team Ownership

QuantumShield is architected into three specialized, decoupled modules developed concurrently:

```
quantumshield/
├── backend/
│   ├── scanner/              # [Member 1] Static analysis scanner (AST/regex crypto discovery)
│   ├── risk_engine/          # [Member 2] NIST-aligned quantum vulnerability & risk assessment
│   │   ├── classifier.py     # Algorithm classification, risk levels (HIGH/MODERATE/LOWER)
│   │   ├── rules.py          # NIST FIPS 203/204/205 replacement guidance & parameters
│   │   └── models.py         # Structured data models & typing
│   ├── app/                  # [Member 3] FastAPI integration layer, validation & report generation
│   │   ├── main.py           # REST endpoints, archive security, ZIP extraction & cleanup
│   │   └── scanner_stub.py   # Graceful fallback test double when scanner is unmerged
│   ├── tests/
│   │   ├── test_risk_engine.py  # Member 2 test suite (16 tests)
│   │   └── test_api.py          # Member 3 API & integration test suite (54 tests)
│   └── requirements.txt
├── frontend/                 # [Member 3] React 18 + Vite 5 Interactive Security Dashboard
│   ├── src/
│   │   ├── components/       # Header, Dashboard, ScanWorkspace, ResultsView, FindingsTable, RiskCharts, MigrationPlanner
│   │   ├── services/api.js   # Robust backend communication & blob download helpers
│   │   ├── index.css         # Minimalist charcoal/teal security UI design system
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
└── sample/                   # Multi-language test corpus (Python, Java, C) with RSA, ECDSA, ECDH, AES
```

- **Member 1 (Scanner):** AST and regex-based code scanning for cryptographic usage patterns in `.py`, `.java`, `.c`, `.cpp`, `.go`, `.rs`.
- **Member 2 (Risk Engine):** Risk classification (HIGH / MODERATE / LOWER), algorithmic explanation, and post-quantum migration recommendations (ML-KEM, ML-DSA, SLH-DSA).
- **Member 3 (Frontend, Backend Integration & Reporting):** Secure FastAPI backend, ZIP parsing sandbox, React + Vite interactive dashboard, CSV & JSON report exports, comprehensive automated test suites.

---

## 2. Key Features

- **Secure Archive Ingestion:** Sandboxed ZIP extraction with protection against path traversal (`../`), zip bombs (size & entry limits), symlinks, and absolute path injections.
- **Strict Execution Policy:** Zero execution of uploaded source code; files undergo pure static analysis in isolated ephemeral directories with guaranteed cleanup.
- **NIST Post-Quantum Cryptographic Standards Alignment:**
  - Asymmetric Encryption / Key Exchange (RSA, ECDH) $\to$ **NIST FIPS 203 (ML-KEM / Crystals-Kyber)**
  - Digital Signatures (RSA Sign, ECDSA, Ed25519) $\to$ **NIST FIPS 204 (ML-DSA / Crystals-Dilithium)** or **NIST FIPS 205 (SLH-DSA / SPHINCS+)**
  - Symmetric Ciphers (AES-128 $\to$ AES-256 for Grover's algorithm mitigation)
- **Interactive Security Dashboard:**
  - Real-time drag-and-drop archive scanner.
  - Multi-dimensional risk charts (Risk severity distribution, algorithm counts, cryptographic purposes).
  - Searchable, filterable findings table with code snippet evidence and contextual explanations.
  - Actionable Migration Planner prioritizing high-urgency transitions.
- **Auditing & Reporting:** One-click downloads of comprehensive JSON and formula-injection-safe CSV compliance audit reports.

---

## 3. Quickstart & Setup Guide (Windows / Linux / macOS)

### Prerequisites
- **Python:** 3.10+ (tested on Python 3.14)
- **Node.js:** v18+ (tested on Node.js v24.20.0 and npm 11.19.0)
- **Git**

### A. Backend Setup
1. Clone the repository and checkout the integration branch:
   ```bash
   git clone https://github.com/codewithswastik13/techxperts.git
   cd techxperts
   git checkout feature/frontend-api
   ```
2. Set up Python virtual environment and install backend dependencies:
   ```bash
   python -m venv venv
   # Windows:
   .\venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate

   pip install -r backend/requirements.txt
   ```
3. Start the FastAPI backend server:
   ```bash
   python -m uvicorn backend.app.main:app --reload --port 8000
   ```
   *The backend will be available at [http://localhost:8000](http://localhost:8000) (Interactive Swagger Docs at `/docs`).*

### B. Frontend Setup
1. Open a new terminal and navigate to `frontend`:
   ```bash
   cd frontend
   npm install
   ```
2. Start the Vite development server:
   ```bash
   npm run dev
   ```
   *The frontend dashboard will be available at [http://localhost:5173](http://localhost:5173).*
3. To build for production:
   ```bash
   npm run build
   ```

---

## 4. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Returns server health, version, limits, and module availability status |
| `POST` | `/api/scan` | Accepts a multipart ZIP file, performs safe extraction and triggers analysis |
| `GET` | `/api/scans` | Lists scans executed during the current session |
| `GET` | `/api/scan/{scan_id}/report?format=json` | Downloads a comprehensive JSON migration report |
| `GET` | `/api/scan/{scan_id}/report?format=csv` | Downloads a sanitised, formula-injection-safe CSV audit report |

---

## 5. Running Automated Tests

QuantumShield includes 70 comprehensive automated tests across the backend and risk engine:

```bash
# Run complete test suite (Member 2 + Member 3)
python -m pytest backend/tests/ -v

# Run API integration and security tests specifically
python -m pytest backend/tests/test_api.py -v

# Run Risk Engine test suite specifically
python -m pytest backend/tests/test_risk_engine.py -v
```

### Covered Security Test Scenarios:
- Path traversal rejection (`../../etc/passwd`, Windows drive prefixes)
- Archive bomb mitigation (oversized entries, excessive file counts)
- Corrupted and truncated archives
- CSV formula injection sanitization (protecting spreadsheet viewers from `=cmd|...`)
- Ephemeral workspace directory isolation and guaranteed cleanup
- Non-source file exclusion (`.exe`, `.bin` ignored during extraction)

---

## 6. Known Limitations & Future Work

- **Static Heuristic Scanner:** Static pattern recognition flags potential cryptographic primitives and API usages. Manual code review is always advised before production migration.
- **Session-Scoped Storage:** Scan results and generated reports are held in memory during the server runtime and are bounded to avoid memory exhaustion. In a production cluster, this can be backed by Redis or an encrypted database.
- **Scanner Integration:** While Member 1's scanner branch is awaiting final merge, the application gracefully utilizes the verified risk engine and sample test corpus with end-to-end integration fallback.
