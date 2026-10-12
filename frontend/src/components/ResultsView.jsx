import { useState } from 'react'
import { Download, BarChart2, List, Compass, AlertTriangle, CheckCircle } from 'lucide-react'
import FindingsTable from './FindingsTable.jsx'
import RiskCharts from './RiskCharts.jsx'
import MigrationPlanner from './MigrationPlanner.jsx'
import { downloadReport, triggerDownload, formatTimestamp } from '../services/api.js'

/**
 * ResultsView.jsx — Tabbed results layout
 *
 * Tabs: Findings | Risk Overview | Migration Planner
 * Plus: JSON and CSV download buttons
 */
export default function ResultsView({ scanResult, onNewScan }) {
  const [activeTab, setActiveTab] = useState('findings')
  const [downloadError, setDownloadError] = useState(null)
  const [downloading, setDownloading] = useState(null)

  const summary = scanResult.risk_summary || {}
  const counts = summary.risk_level_counts || {}
  const findingCount = (scanResult.findings || []).length

  const handleDownload = async (format) => {
    setDownloadError(null)
    setDownloading(format)
    const { blob, filename, error } = await downloadReport(scanResult.scan_id, format)
    setDownloading(null)
    if (error) {
      setDownloadError(error)
      return
    }
    triggerDownload(blob, filename)
  }

  return (
    <div>
      {/* Results header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--sp-4)', flexWrap: 'wrap', marginBottom: 'var(--sp-6)' }}>
        <div>
          <h2 className="section-title" style={{ fontSize: 18 }}>
            {scanResult._is_sample && <span className="badge badge-accent" style={{ fontSize: 10, marginRight: 8, verticalAlign: 'middle' }}>SAMPLE</span>}
            {scanResult.filename}
          </h2>
          <p className="section-sub">{formatTimestamp(scanResult.timestamp)} · {scanResult.total_source_files} file{scanResult.total_source_files !== 1 ? 's' : ''} scanned · {(scanResult.scan_duration_seconds || 0).toFixed(2)}s</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            id="download-json-btn"
            className="btn btn-secondary btn-sm"
            onClick={() => handleDownload('json')}
            disabled={!!downloading}
            aria-label="Download JSON report"
          >
            <Download size={13} />
            {downloading === 'json' ? 'Downloading…' : 'JSON report'}
          </button>
          <button
            id="download-csv-btn"
            className="btn btn-secondary btn-sm"
            onClick={() => handleDownload('csv')}
            disabled={!!downloading}
            aria-label="Download CSV report"
          >
            <Download size={13} />
            {downloading === 'csv' ? 'Downloading…' : 'CSV report'}
          </button>
          <button
            id="new-scan-btn"
            className="btn btn-primary btn-sm"
            onClick={onNewScan}
          >
            New scan
          </button>
        </div>
      </div>

      {/* Sample label notice */}
      {scanResult._is_sample && (
        <div className="notice notice-info mb-4" role="status">
          <CheckCircle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>
            <strong>Sample repository.</strong> These results were produced by scanning the bundled sample corpus, not your code.
            The sample contains deliberate cryptographic patterns for demonstration. No results are hardcoded.
          </span>
        </div>
      )}

      {downloadError && (
        <div className="notice notice-error mb-4" role="alert">
          <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>Download failed: {downloadError}</span>
        </div>
      )}

      {/* Stats row */}
      <div className="stat-grid" style={{ marginBottom: 'var(--sp-6)' }}>
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
          <div className="stat-value" style={{ color: 'var(--risk-unknown)', fontSize: 22 }}>{summary.manual_review_required_count ?? 0}</div>
          <div className="stat-label">Manual review needed</div>
        </div>
      </div>

      {/* Errors */}
      {scanResult.status === 'completed_with_errors' && scanResult.errors?.length > 0 && (
        <div className="notice notice-warn mb-4" role="alert">
          <AlertTriangle size={14} style={{ flexShrink: 0 }} />
          <div>
            <strong>Scan completed with errors:</strong>
            <ul style={{ marginTop: 4, paddingLeft: 16, fontSize: 12 }}>
              {scanResult.errors.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="tabs" role="tablist" aria-label="Results sections">
        {[
          { id: 'findings', label: 'Findings', Icon: List, count: findingCount },
          { id: 'risk', label: 'Risk overview', Icon: BarChart2, count: null },
          { id: 'migration', label: 'Migration planner', Icon: Compass, count: (scanResult.migration_summary || []).length },
        ].map(tab => (
          <button
            key={tab.id}
            id={`tab-${tab.id}`}
            role="tab"
            aria-selected={activeTab === tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {tab.count !== null && (
              <span className="tab-count">{tab.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab panels */}
      {activeTab === 'findings' && (
        <FindingsTable findings={scanResult.findings || []} filesExcluded={scanResult.files_excluded || []} />
      )}
      {activeTab === 'risk' && (
        <RiskCharts scanResult={scanResult} />
      )}
      {activeTab === 'migration' && (
        <MigrationPlanner migrationSummary={scanResult.migration_summary || []} findings={scanResult.findings || []} />
      )}

      {/* Limitations */}
      <div style={{ marginTop: 'var(--sp-8)' }}>
        <div className="section-sub" style={{ marginBottom: 8 }}>Scan limitations</div>
        <ul className="limitations-list">
          {(scanResult.limitations || []).map((l, i) => <li key={i}>{l}</li>)}
        </ul>
      </div>
    </div>
  )
}
