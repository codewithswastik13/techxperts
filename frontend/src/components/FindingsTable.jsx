import { useState, useMemo } from 'react'
import { Search, ChevronDown, ChevronUp, ChevronRight, FileCode } from 'lucide-react'
import { riskClass, purposeLabel } from '../services/api.js'

/**
 * FindingsTable.jsx — Sortable, searchable, filterable findings explorer
 *
 * Each row is expandable to show the full explanation and recommendation.
 * Clearly distinguishes detection confidence from confirmed vulnerability.
 */
export default function FindingsTable({ findings, filesExcluded }) {
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('ALL')
  const [sortKey, setSortKey] = useState('risk_level')
  const [sortDir, setSortDir] = useState('desc')
  const [expanded, setExpanded] = useState(null)

  const RISK_ORDER = { HIGH: 0, MODERATE: 1, LOWER: 2, UNKNOWN: 3 }

  const handleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  const filtered = useMemo(() => {
    let result = findings

    if (riskFilter !== 'ALL') {
      result = result.filter(f => (f.risk_level || 'UNKNOWN').toUpperCase() === riskFilter)
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      result = result.filter(f =>
        (f.file_path || '').toLowerCase().includes(q) ||
        (f.algorithm || '').toLowerCase().includes(q) ||
        (f.matched_pattern || '').toLowerCase().includes(q) ||
        (f.evidence || '').toLowerCase().includes(q)
      )
    }

    return [...result].sort((a, b) => {
      let va, vb
      if (sortKey === 'risk_level') {
        va = RISK_ORDER[a.risk_level || 'UNKNOWN'] ?? 9
        vb = RISK_ORDER[b.risk_level || 'UNKNOWN'] ?? 9
      } else if (sortKey === 'line_number') {
        va = Number(a.line_number) || 0
        vb = Number(b.line_number) || 0
      } else {
        va = String(a[sortKey] || '').toLowerCase()
        vb = String(b[sortKey] || '').toLowerCase()
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1
      if (va > vb) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [findings, search, riskFilter, sortKey, sortDir])

  if (findings.length === 0) {
    return (
      <div className="empty-state">
        <FileCode size={48} className="empty-icon" />
        <div className="empty-title">No findings</div>
        <p className="empty-sub">
          The scanner did not identify any recognised cryptographic patterns in the scanned files.
          This may mean the code uses cryptography not yet recognised by the scanner, or no cryptographic operations were detected.
        </p>
        {filesExcluded.length > 0 && (
          <p className="empty-sub" style={{ marginTop: 8 }}>
            {filesExcluded.length} file{filesExcluded.length !== 1 ? 's' : ''} were excluded (unsupported extensions or size limits).
          </p>
        )}
      </div>
    )
  }

  const SortIcon = ({ col }) => {
    if (sortKey !== col) return <ChevronRight size={12} style={{ opacity: 0.3 }} />
    return sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
  }

  return (
    <div>
      {/* Controls */}
      <div className="controls-bar">
        <div className="search-wrapper">
          <Search size={14} className="search-icon" aria-hidden="true" />
          <input
            id="findings-search"
            className="search-input"
            placeholder="Search by file, algorithm, pattern…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            aria-label="Search findings"
          />
        </div>
        <select
          id="risk-filter"
          className="filter-select"
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
          aria-label="Filter by risk level"
        >
          <option value="ALL">All risk levels</option>
          <option value="HIGH">High risk</option>
          <option value="MODERATE">Moderate risk</option>
          <option value="LOWER">Lower risk</option>
          <option value="UNKNOWN">Unknown</option>
        </select>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {filtered.length} of {findings.length}
        </span>
      </div>

      <div className="table-wrapper" role="region" aria-label="Findings table">
        <table className="findings-table" aria-label="Cryptographic findings">
          <thead>
            <tr>
              {[
                { key: 'file_path', label: 'File / Line' },
                { key: 'algorithm', label: 'Algorithm' },
                { key: 'risk_level', label: 'Risk' },
                { key: 'cryptographic_purpose', label: 'Purpose' },
                { key: 'evidence', label: 'Evidence' },
                { key: '_expand', label: '' },
              ].map(col => (
                <th
                  key={col.key}
                  className={sortKey === col.key ? 'sorted' : ''}
                  onClick={col.key !== '_expand' ? () => handleSort(col.key) : undefined}
                  style={col.key === '_expand' ? { width: 40 } : {}}
                  aria-sort={sortKey === col.key ? (sortDir === 'asc' ? 'ascending' : 'descending') : undefined}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    {col.label}
                    {col.key !== '_expand' && <SortIcon col={col.key} />}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((finding, idx) => {
              const id = finding.id || `${finding.file_path}-${finding.line_number}-${idx}`
              const isExpanded = expanded === id
              const rc = riskClass(finding.risk_level)

              return (
                <>
                  <tr
                    key={`row-${id}`}
                    className={isExpanded ? 'expanded' : ''}
                    onClick={() => setExpanded(isExpanded ? null : id)}
                    style={{ cursor: 'pointer' }}
                    aria-expanded={isExpanded}
                  >
                    <td>
                      <div className="file-path">{finding.file_path || '—'}</div>
                      {finding.line_number && (
                        <div className="line-number">line {finding.line_number}</div>
                      )}
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>
                        {finding.algorithm || '—'}
                      </div>
                      {finding.language && (
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{finding.language}</div>
                      )}
                    </td>
                    <td>
                      <span className={`badge badge-${rc}`}>
                        {finding.risk_level || 'UNKNOWN'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {purposeLabel(finding.cryptographic_purpose)}
                      </span>
                    </td>
                    <td>
                      {finding.evidence ? (
                        <code className="evidence-snippet" title={finding.evidence}>
                          {finding.evidence}
                        </code>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                      )}
                    </td>
                    <td>
                      {isExpanded
                        ? <ChevronDown size={14} style={{ color: 'var(--accent)' }} />
                        : <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />}
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr key={`detail-${id}`}>
                      <td colSpan={6} style={{ padding: 0 }}>
                        <FindingDetail finding={finding} />
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
      </div>

      {filesExcluded.length > 0 && (
        <div style={{ marginTop: 'var(--sp-4)', fontSize: 12, color: 'var(--text-muted)' }}>
          {filesExcluded.length} file{filesExcluded.length !== 1 ? 's were' : ' was'} excluded from scanning
          (unsupported extensions or size limits).
        </div>
      )}
    </div>
  )
}

function FindingDetail({ finding }) {
  const rc = riskClass(finding.risk_level)
  return (
    <div className="finding-detail">
      <div className="finding-detail-grid">
        <div className="detail-block">
          <div className="detail-label">Explanation</div>
          <div className="detail-value">{finding.explanation || 'No explanation available.'}</div>
        </div>
        <div className="detail-block">
          <div className="detail-label">Migration recommendation</div>
          <div className="detail-value">{finding.recommendation || 'Review the detected usage and determine migration requirements.'}</div>
        </div>
        {finding.evidence && (
          <div className="detail-block">
            <div className="detail-label">Evidence snippet</div>
            <code className="detail-code">{finding.evidence}</code>
          </div>
        )}
        <div className="detail-block">
          <div className="detail-label">Classification metadata</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <MetaRow label="Risk level" value={<span className={`badge badge-${rc}`}>{finding.risk_level || '—'}</span>} />
            <MetaRow label="Migration priority" value={finding.migration_priority || '—'} />
            <MetaRow label="Purpose" value={purposeLabel(finding.cryptographic_purpose)} />
            <MetaRow label="Manual review" value={finding.manual_review_required ? 'Required' : 'Not required'} />
            {finding.detection_method && <MetaRow label="Detection method" value={finding.detection_method} />}
            {finding.confidence && <MetaRow label="Confidence" value={finding.confidence} />}
          </div>
        </div>
      </div>

      {finding.manual_review_required && (
        <div className="notice notice-warn" style={{ marginTop: 'var(--sp-4)' }}>
          <span style={{ fontSize: 12 }}>
            <strong>Manual review required.</strong> The cryptographic purpose could not be determined with high confidence.
            Inspect the call site to select the correct post-quantum alternative.
          </span>
        </div>
      )}
    </div>
  )
}

function MetaRow({ label, value }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 12, alignItems: 'center' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 120 }}>{label}</span>
      <span style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  )
}
