import { Shield } from 'lucide-react'

/**
 * Header.jsx — Sticky navigation bar with API status indicator
 */
export default function Header({ activeTab, onTabChange, apiHealth, hasScanResult }) {
  const isOnline = apiHealth?.status === 'ok'
  const isChecking = apiHealth === null

  const tabs = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'scan', label: 'Scan repository' },
    ...(hasScanResult ? [{ id: 'results', label: 'Results' }] : []),
  ]

  return (
    <header className="header" role="banner">
      <div className="header-inner">
        <a href="#" className="wordmark" onClick={(e) => { e.preventDefault(); onTabChange('dashboard') }} aria-label="QuantumShield home">
          <div className="wordmark-shield" aria-hidden="true" />
          <span className="wordmark-text">QuantumShield</span>
          <span className="wordmark-sub">QFF 2026</span>
        </a>

        <nav className="nav" role="navigation" aria-label="Main navigation">
          {tabs.map(tab => (
            <button
              key={tab.id}
              id={`nav-${tab.id}`}
              className={`nav-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => onTabChange(tab.id)}
              aria-current={activeTab === tab.id ? 'page' : undefined}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        <div className="header-status" aria-label="API connection status">
          <div
            className={`status-dot ${isChecking ? '' : isOnline ? 'online' : 'offline'}`}
            title={isChecking ? 'Checking connection…' : isOnline ? 'API connected' : 'API offline'}
          />
          <span className="status-label">
            {isChecking ? 'Connecting…' : isOnline ? 'API online' : 'API offline'}
          </span>
        </div>
      </div>
    </header>
  )
}
