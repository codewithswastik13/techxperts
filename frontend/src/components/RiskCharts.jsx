import { useMemo } from 'react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts'

/**
 * RiskCharts.jsx — Visual risk summaries using Recharts
 *
 * Renders only from actual backend data.
 * Handles empty datasets cleanly.
 */

const RISK_COLOURS = {
  HIGH: '#C0392B',
  MODERATE: '#C05621',
  LOWER: '#276749',
  UNKNOWN: '#718096',
}

const CHART_BG = 'transparent'
const AXIS_COLOUR = '#718096'
const TOOLTIP_STYLE = {
  background: '#FFFFFF',
  border: '1px solid rgba(0,0,0,0.10)',
  borderRadius: 6,
  fontSize: 12,
  color: '#1A1A1A',
  boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
}

export default function RiskCharts({ scanResult }) {
  const summary = scanResult.risk_summary || {}
  const riskCounts = summary.risk_level_counts || {}
  const algoCounts = summary.algorithm_counts || {}
  const purposeCounts = summary.cryptographic_purpose_counts || {}

  // Pie: risk distribution
  const riskPieData = useMemo(() =>
    Object.entries(riskCounts)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value, fill: RISK_COLOURS[name] || '#94a3b8' })),
    [riskCounts]
  )

  // Bar: findings by algorithm
  const algoBarData = useMemo(() =>
    Object.entries(algoCounts)
      .map(([algo, count]) => ({ algo, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    [algoCounts]
  )

  // Bar: findings by purpose
  const purposeBarData = useMemo(() =>
    Object.entries(purposeCounts)
      .map(([purpose, count]) => ({ purpose: formatPurpose(purpose), count }))
      .sort((a, b) => b.count - a.count),
    [purposeCounts]
  )

  const totalFindings = summary.total_findings || 0

  if (totalFindings === 0) {
    return (
      <div className="empty-state">
        <div className="empty-title">No data to chart</div>
        <p className="empty-sub">Run a scan that produces findings to see risk visualisations.</p>
      </div>
    )
  }

  return (
    <div>
      {/* Summary cards */}
      <div className="stat-grid" style={{ marginBottom: 'var(--sp-6)' }}>
        {Object.entries(riskCounts).map(([level, count]) => (
          <div key={level} className="stat-item">
            <div
              className="stat-value"
              style={{ color: RISK_COLOURS[level] || 'var(--text-secondary)' }}
            >
              {count}
            </div>
            <div className="stat-label">{level} risk</div>
          </div>
        ))}
        <div className="stat-item">
          <div className="stat-value" style={{ color: 'var(--text-secondary)' }}>
            {((riskCounts.HIGH || 0) / totalFindings * 100).toFixed(0)}%
          </div>
          <div className="stat-label">High risk share</div>
        </div>
      </div>

      <div className="charts-grid">
        {/* Pie chart */}
        {riskPieData.length > 0 && (
          <div className="chart-panel">
            <div className="chart-panel-title">Risk distribution</div>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={riskPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {riskPieData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(value, name) => [`${value} finding${value !== 1 ? 's' : ''}`, name]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Algorithm bar chart */}
        {algoBarData.length > 0 && (
          <div className="chart-panel">
            <div className="chart-panel-title">Findings by algorithm</div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={algoBarData} margin={{ top: 4, right: 12, left: -8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="algo" tick={{ fontSize: 11, fill: AXIS_COLOUR }} />
                <YAxis tick={{ fontSize: 11, fill: AXIS_COLOUR }} allowDecimals={false} />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(value) => [`${value} finding${value !== 1 ? 's' : ''}`, 'Count']}
                />
                <Bar dataKey="count" fill="#176B65" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Purpose bar chart */}
        {purposeBarData.length > 0 && (
          <div className="chart-panel">
            <div className="chart-panel-title">Findings by cryptographic purpose</div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={purposeBarData} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 11, fill: AXIS_COLOUR }} allowDecimals={false} />
                <YAxis type="category" dataKey="purpose" tick={{ fontSize: 11, fill: AXIS_COLOUR }} width={110} />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(value) => [`${value} finding${value !== 1 ? 's' : ''}`, 'Count']}
                />
                <Bar dataKey="count" fill="#176B65" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Scan metadata */}
      <div className="chart-panel" style={{ marginTop: 'var(--sp-4)' }}>
        <div className="chart-panel-title">Scan metadata</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--sp-4)', fontSize: 13 }}>
          <MetaItem label="Files scanned" value={scanResult.total_source_files || 0} />
          <MetaItem label="Files excluded" value={(scanResult.files_excluded || []).length} />
          <MetaItem label="Archive entries" value={scanResult.total_entries_in_archive || '—'} />
          <MetaItem label="Scan duration" value={`${(scanResult.scan_duration_seconds || 0).toFixed(3)}s`} />
          <MetaItem label="Scanner available" value={scanResult.scanner_available ? 'Yes' : 'No (stub used)'} />
          <MetaItem label="Risk engine available" value={scanResult.risk_engine_available ? 'Yes' : 'No'} />
        </div>
      </div>
    </div>
  )
}

function MetaItem({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 2 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{String(value)}</div>
    </div>
  )
}

function formatPurpose(purpose) {
  const map = {
    DIGITAL_SIGNATURE: 'Signature',
    KEY_ESTABLISHMENT: 'Key exchange',
    SYMMETRIC_ENCRYPTION: 'Sym. encryption',
    HASH_FUNCTION: 'Hash',
    UNKNOWN: 'Unknown',
    AMBIGUOUS: 'Ambiguous',
  }
  return map[purpose] || purpose
}
