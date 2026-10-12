import { Search, FileCode, Cpu, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import { riskClass, formatTimestamp } from '../services/api.js'

/**
 * Dashboard.jsx — Landing page shown before and after a scan
 *
 * When no scan has been run: shows product overview, capabilities, and empty state
 * When a scan exists: shows a high-level summary derived from actual results
 */
export default function Dashboard({ apiHealth, scanResult, onStartScan }) {
  return (
    <div>
      <section className="landing-hero" aria-labelledby="hero-heading">
        <p className="landing-eyebrow">PS-P2 · Post-Quantum Cryptography</p>
        <h1 className="landing-title" id="hero-heading">
          Find <em>quantum-vulnerable</em> cryptography before it finds you
        </h1>
        <p className="landing-desc">
          QuantumShield scans your source code for cryptographic usage patterns, classifies
          quantum risk using documented NIST standards, and guides your migration to
          post-quantum algorithms.
        </p>
        <div className="landing-actions">
          <button id="hero-start-scan" className="btn btn-primary btn-lg" onClick={onStartScan}>
            <FileCode size={16} />
            Scan a repository
          </button>
          <button id="hero-sample-scan" className="btn btn-secondary btn-lg" onClick={onStartScan}>
            Try sample project
          </button>
        </div>
      </section>

      {/* API status notice */}
      {apiHealth !== null && !apiHealth && (
        <div className="notice notice-error mb-4" role="alert">
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>
            <strong>Cannot reach the backend API.</strong> Make sure the FastAPI server is running:{' '}
            <code className="mono" style={{ fontSize: 12 }}>python -m uvicorn backend.app.main:app --reload</code>
          </span>
        </div>
      )}

      {apiHealth?.status === 'ok' && !apiHealth?.scanner_available && (
        <div className="notice notice-warn mb-4" role="status">
          <Info size={16} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>
            <strong>Scanner pending integration.</strong> The scanner (Member 1) has not been committed yet.
            The API is running; uploads are accepted and risk analysis is available once findings arrive.
          </span>
        </div>
      )}

      {/* Scan summary — only rendered when a scan has been completed */}
      {scanResult && <ScanSummary scanResult={scanResult} />}

      {/* Capabilities grid — always visible */}
      <div className="divider-label">What QuantumShield analyses</div>
      <div className="capability-grid">
        {CAPABILITIES.map(cap => (
          <div key={cap.label} className="capability-item">
            <cap.Icon className="capability-icon" size={18} />
            <div className="capability-label">{cap.label}</div>
            <div className="capability-desc">{cap.desc}</div>
          </div>
        ))}
      </div>

      {/* Limitations */}
      <div style={{ marginTop: 'var(--sp-8)' }}>
        <div className="section-header">
          <div className="section-title">Known limitations</div>
          <div className="section-sub">Understand what the scanner can and cannot detect</div>
        </div>
        <ul className="limitations-list" aria-label="Scanner limitations">
          <li>Results reflect heuristic pattern matching — not formal cryptographic verification.</li>
          <li>A finding indicates potential usage, not a confirmed vulnerability.</li>
          <li>Code paths that are dead, unreachable, or conditionally excluded are not distinguished.</li>
          <li>Binary files, compiled bytecode, and obfuscated sources are not analysed.</li>
          <li>Cryptographic usage in comments and string literals may trigger false positives.</li>
          <li>Risk classification depends on the scanner correctly identifying the algorithm family.</li>
          <li>ML-KEM and ML-DSA recommendations require compatibility testing; no replacement is automatically drop-in safe.</li>
        </ul>
      </div>
    </div>
  )
}

function ScanSummary({ scanResult }) {
  const summary = scanResult.risk_summary || {}
  const counts = summary.risk_level_counts || {}

  return (
    <div style={{ marginBottom: 'var(--sp-8)' }}>
      <div className="section-header">
        <div className="section-title">Last scan — {scanResult.filename}</div>
        <div className="section-sub">{formatTimestamp(scanResult.timestamp)} · {scanResult.total_source_files} source file{scanResult.total_source_files !== 1 ? 's' : ''} scanned</div>
      </div>
      <div className="stat-grid">
        <div className="stat-item">
          <div className="stat-value accent">{summary.total_findings ?? 0}</div>
          <div className="stat-label">Total findings</div>
        </div>
        <div className="stat-item">
          <div className="stat-value high">{counts.HIGH ?? 0}</div>
          <div className="stat-label">High risk</div>
        </div>
        <div className="stat-item">
          <div className="stat-value moderate">{counts.MODERATE ?? 0}</div>
          <div className="stat-label">Moderate risk</div>
        </div>
        <div className="stat-item">
          <div className="stat-value lower">{counts.LOWER ?? 0}</div>
          <div className="stat-label">Lower risk</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: 'var(--risk-unknown)' }}>{summary.manual_review_required_count ?? 0}</div>
          <div className="stat-label">Require manual review</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: 'var(--text-secondary)', fontSize: 18 }}>{(scanResult.scan_duration_seconds ?? 0).toFixed(2)}s</div>
          <div className="stat-label">Scan duration</div>
        </div>
      </div>

      {scanResult.status === 'completed_with_errors' && scanResult.errors && (
        <div className="notice notice-warn mt-4" role="alert">
          <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <strong>Scan completed with errors:</strong>
            <ul style={{ marginTop: 4, paddingLeft: 16, fontSize: 12 }}>
              {scanResult.errors.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

const CAPABILITIES = [
  {
    Icon: Search,
    label: 'RSA detection',
    desc: 'Identifies RSA key generation, encryption, and signature patterns. High quantum risk — vulnerable to Shor\'s algorithm.',
  },
  {
    Icon: Cpu,
    label: 'ECC detection',
    desc: 'Detects ECDSA, ECDH, and generic elliptic curve operations. High quantum risk — ECDLP broken on a CRQC.',
  },
  {
    Icon: CheckCircle,
    label: 'Symmetric analysis',
    desc: 'Classifies AES-128 (moderate risk) vs AES-256 (lower risk). Recommends key-length upgrades, not PQC replacements.',
  },
  {
    Icon: Info,
    label: 'Hash function context',
    desc: 'Identifies SHA-256 usage and explains why it is classified lower risk, with nuanced Grover analysis.',
  },
]
