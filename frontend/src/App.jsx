import { useState, useEffect, useCallback } from 'react'
import Header from './components/Header.jsx'
import Dashboard from './components/Dashboard.jsx'
import ScanWorkspace from './components/ScanWorkspace.jsx'
import { getHealth } from './services/api.js'

/**
 * App.jsx — Root application component
 *
 * Manages:
 * - Tab navigation (Dashboard / Scan / Results)
 * - API health polling
 * - Scan result state (passed down to components)
 */
export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [apiHealth, setApiHealth] = useState(null)  // null = checking, {} = result
  const [scanResult, setScanResult] = useState(null)

  // Poll health on mount and every 30s
  const checkHealth = useCallback(async () => {
    const { data } = await getHealth()
    setApiHealth(data)
  }, [])

  useEffect(() => {
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [checkHealth])

  const handleScanComplete = useCallback((result) => {
    setScanResult(result)
    setActiveTab('results')
  }, [])

  const handleNewScan = useCallback(() => {
    setActiveTab('scan')
  }, [])

  return (
    <div className="app-layout">
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        apiHealth={apiHealth}
        hasScanResult={!!scanResult}
      />
      <main>
        <div className="page-wrapper">
          {activeTab === 'dashboard' && (
            <Dashboard
              apiHealth={apiHealth}
              scanResult={scanResult}
              onStartScan={handleNewScan}
            />
          )}
          {activeTab === 'scan' && (
            <ScanWorkspace
              onScanComplete={handleScanComplete}
              apiHealth={apiHealth}
            />
          )}
          {activeTab === 'results' && scanResult && (
            <ResultsView
              scanResult={scanResult}
              onNewScan={handleNewScan}
            />
          )}
          {activeTab === 'results' && !scanResult && (
            <div className="empty-state" style={{ padding: 'var(--sp-12)' }}>
              <div className="empty-title">No scan results yet</div>
              <p className="empty-sub">Upload a repository ZIP to begin scanning for quantum-vulnerable cryptography.</p>
              <button className="btn btn-primary mt-4" onClick={handleNewScan}>
                Start a scan
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

// Lazy import to keep App.jsx manageable
import ResultsView from './components/ResultsView.jsx'
