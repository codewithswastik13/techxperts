import { useState } from 'react'
import { ChevronDown, ChevronRight, AlertTriangle, CheckCircle } from 'lucide-react'
import { riskClass, purposeLabel, priorityLabel } from '../services/api.js'

/**
 * MigrationPlanner.jsx — Deduplicated, prioritised migration recommendations
 *
 * Sourced entirely from the risk engine output.
 * Never makes unsupported claims about automatic compatibility.
 */
export default function MigrationPlanner({ migrationSummary, findings }) {
  const [expandedIdx, setExpandedIdx] = useState(null)

  if (!migrationSummary || migrationSummary.length === 0) {
    return (
      <div className="empty-state">
        <CheckCircle size={48} className="empty-icon" style={{ color: 'var(--risk-lower)', opacity: 0.5 }} />
        <div className="empty-title">No migration actions identified</div>
        <p className="empty-sub">
          Either no findings were produced, or all detected algorithms are already at an adequate quantum security level.
        </p>
      </div>
    )
  }

  // Count findings per (algorithm, purpose) pair
  const findingCounts = {}
  for (const f of findings) {
    const key = `${f.algorithm}::${f.cryptographic_purpose}`
    findingCounts[key] = (findingCounts[key] || 0) + 1
  }

  const highPriority = migrationSummary.filter(m => m.migration_priority === 'HIGH')
  const others = migrationSummary.filter(m => m.migration_priority !== 'HIGH')

  return (
    <div>
      <div className="notice notice-warn" style={{ marginBottom: 'var(--sp-5)' }}>
        <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 2 }} />
        <span style={{ fontSize: 12 }}>
          <strong>These recommendations require manual validation.</strong> No post-quantum algorithm
          is automatically drop-in compatible. Test for correctness, performance, and interoperability
          before deploying any migration.
        </span>
      </div>

      {highPriority.length > 0 && (
        <div style={{ marginBottom: 'var(--sp-6)' }}>
          <div className="section-sub" style={{ marginBottom: 'var(--sp-3)' }}>
            High priority — {highPriority.length} algorithm{highPriority.length !== 1 ? 's' : ''} requiring immediate attention
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
            {highPriority.map((m, i) => (
              <MigrationItem
                key={i}
                item={m}
                count={findingCounts[`${m.algorithm}::${m.cryptographic_purpose}`] || 0}
                expanded={expandedIdx === `h${i}`}
                onToggle={() => setExpandedIdx(expandedIdx === `h${i}` ? null : `h${i}`)}
              />
            ))}
          </div>
        </div>
      )}

      {others.length > 0 && (
        <div>
          {highPriority.length > 0 && (
            <div className="section-sub" style={{ marginBottom: 'var(--sp-3)' }}>Other findings</div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
            {others.map((m, i) => (
              <MigrationItem
                key={i}
                item={m}
                count={findingCounts[`${m.algorithm}::${m.cryptographic_purpose}`] || 0}
                expanded={expandedIdx === `o${i}`}
                onToggle={() => setExpandedIdx(expandedIdx === `o${i}` ? null : `o${i}`)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function MigrationItem({ item, count, expanded, onToggle }) {
  const rc = riskClass(item.risk_level)
  const prioLabel = priorityLabel(item.migration_priority)

  return (
    <div className="migration-item">
      <div className="migration-header" onClick={onToggle} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && onToggle()} aria-expanded={expanded}>
        <span className={`badge badge-${rc}`}>{item.risk_level || 'UNKNOWN'}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="migration-algo">{item.algorithm || '—'}</div>
          <div className="migration-purpose">{purposeLabel(item.cryptographic_purpose)}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', flexShrink: 0 }}>
          {count > 0 && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{count} finding{count !== 1 ? 's' : ''}</span>
          )}
          <span className="badge badge-neutral" style={{ fontSize: 10 }}>{prioLabel}</span>
          {expanded
            ? <ChevronDown size={14} style={{ color: 'var(--accent)' }} />
            : <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />}
        </div>
      </div>

      {expanded && (
        <div className="migration-body">
          {item.recommendation && (
            <div>
              <div className="migration-section-label">Migration recommendation</div>
              <div className="migration-text">{item.recommendation}</div>
            </div>
          )}
          {item.manual_review_required && (
            <div className="notice notice-warn" style={{ padding: 'var(--sp-3)' }}>
              <AlertTriangle size={13} style={{ flexShrink: 0 }} />
              <span style={{ fontSize: 12 }}>Manual review is required to determine the correct post-quantum replacement for this usage.</span>
            </div>
          )}
          <div>
            <div className="migration-section-label">Standards reference</div>
            <div className="migration-text" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {getStandardsRef(item.algorithm, item.cryptographic_purpose)}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function getStandardsRef(algo, purpose) {
  const a = (algo || '').toUpperCase()
  const p = (purpose || '').toUpperCase()
  if (a === 'RSA' || a === 'ECDH' || a === 'ECC_GENERIC') {
    if (p === 'DIGITAL_SIGNATURE') return 'NIST FIPS 204 (ML-DSA) · NIST FIPS 205 (SLH-DSA) · RFC 8554 (LMS) · RFC 8391 (XMSS)'
    if (p === 'KEY_ESTABLISHMENT') return 'NIST FIPS 203 (ML-KEM) · Hybrid classical+PQC key exchange (X25519+ML-KEM)'
    return 'NIST FIPS 203 (ML-KEM) for key exchange · NIST FIPS 204 (ML-DSA) for signatures'
  }
  if (a === 'ECDSA') return 'NIST FIPS 204 (ML-DSA) · NIST FIPS 205 (SLH-DSA)'
  if (a === 'AES-128') return 'AES-256 (FIPS 197) — increase key length; no PQC replacement needed'
  if (a === 'AES-256') return 'AES-256 (FIPS 197) — retain; adequate quantum security margin'
  if (a === 'SHA-256') return 'SHA-256 (FIPS 180-4) — retain for general use; SHA-384/SHA-512 for higher margin'
  return 'Consult NIST PQC standards: FIPS 203, 204, 205'
}
