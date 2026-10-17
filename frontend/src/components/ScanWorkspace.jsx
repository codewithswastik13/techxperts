import { useState, useRef, useCallback } from 'react'
import { Upload, File, X, AlertTriangle, Info, Loader } from 'lucide-react'
import { submitScan, formatBytes } from '../services/api.js'

const MAX_SIZE = 50 * 1024 * 1024  // 50 MB — matches backend limit

/**
 * ScanWorkspace.jsx — ZIP upload and scan control
 *
 * Responsibilities:
 * - File selection (drag-and-drop or browse)
 * - Client-side size and extension validation (backend is authoritative)
 * - Upload and scan trigger
 * - Loading/progress/error states
 * - Sample project shortcut
 */
export default function ScanWorkspace({ onScanComplete, apiHealth }) {
  const [selectedFile, setSelectedFile] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState('')
  const fileInputRef = useRef(null)

  const isApiOnline = apiHealth?.status === 'ok'

  const handleFile = useCallback((file) => {
    setError(null)
    if (!file) return

    // Extension check (usability only — backend validates authoritatively)
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setError('Please select a ZIP archive (.zip)')
      return
    }
    if (file.size > MAX_SIZE) {
      setError(`File is too large (${formatBytes(file.size)}). Maximum is 50 MB.`)
      return
    }
    setSelectedFile(file)
  }, [])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }, [handleFile])

  const handleDragOver = useCallback((e) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback(() => setDragOver(false), [])

  const handleInputChange = useCallback((e) => {
    handleFile(e.target.files?.[0])
  }, [handleFile])

  const handleScan = useCallback(async () => {
    if (!selectedFile) return
    setScanning(true)
    setError(null)
    setProgress('Uploading archive…')

    const { data, error: apiError } = await submitScan(selectedFile)

    if (apiError) {
      setError(apiError.message || 'Scan failed. Please try again.')
      setScanning(false)
      setProgress('')
      return
    }

    setProgress('Processing results…')
    // Small delay so "Processing" state is visible
    await new Promise(r => setTimeout(r, 300))
    setScanning(false)
    setProgress('')
    onScanComplete(data)
  }, [selectedFile, onScanComplete])

  const handleSampleScan = useCallback(async () => {
    setScanning(true)
    setError(null)
    setProgress('Loading sample repository…')

    try {
      // Fetch the bundled sample ZIP
      const resp = await fetch('/sample_repo.zip')
      if (!resp.ok) throw new Error('Sample file not found. Ensure sample_repo.zip is in frontend/public/.')
      const blob = await resp.blob()
      const sampleFile = new File([blob], 'sample_repo.zip', { type: 'application/zip' })

      setSelectedFile(sampleFile)
      setProgress('Scanning sample repository…')

      const { data, error: apiError } = await submitScan(sampleFile)
      if (apiError) {
        setError(apiError.message)
        setScanning(false)
        setProgress('')
        return
      }
      setScanning(false)
      setProgress('')
      onScanComplete({ ...data, _is_sample: true })
    } catch (err) {
      setError(err.message)
      setScanning(false)
      setProgress('')
    }
  }, [onScanComplete])

  const clearFile = useCallback(() => {
    setSelectedFile(null)
    setError(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }, [])

  return (
    <div>
      <div className="section-header">
        <h2 className="section-title">Scan a repository</h2>
        <p className="section-sub">Upload a ZIP archive of your source code for cryptographic analysis</p>
      </div>

      {!isApiOnline && apiHealth !== null && (
        <div className="notice notice-error mb-4" role="alert">
          <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>
            The backend API is not reachable. Start it with:{' '}
            <code className="mono" style={{ fontSize: 12 }}>python -m uvicorn backend.app.main:app --reload</code>
          </span>
        </div>
      )}

      {/* Upload zone */}
      <div
        id="upload-dropzone"
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !scanning && fileInputRef.current?.click()}
        role="button"
        tabIndex={0}
        aria-label="Upload ZIP file — click or drag and drop"
        onKeyDown={(e) => e.key === 'Enter' && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip,application/zip"
          onChange={handleInputChange}
          id="file-input"
          aria-label="Select ZIP file"
          disabled={scanning}
          style={{ pointerEvents: 'none' }}
        />
        <div className="upload-icon">
          <Upload size={40} />
        </div>
        <div className="upload-title">
          {dragOver ? 'Drop to upload' : 'Drop a ZIP archive here'}
        </div>
        <div className="upload-sub">or click to browse your files</div>
        <div className="upload-limits">Supported: Python (.py), Java (.java), C/C++ (.c, .h, .cpp) · Max 50 MB</div>
      </div>

      {/* Selected file display */}
      {selectedFile && !scanning && (
        <div className="upload-selected">
          <File size={18} style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <div className="upload-selected-info">
            <div className="upload-filename" title={selectedFile.name}>{selectedFile.name}</div>
            <div className="upload-filesize">{formatBytes(selectedFile.size)}</div>
          </div>
          <button
            id="clear-file-btn"
            className="btn btn-ghost btn-sm"
            onClick={(e) => { e.stopPropagation(); clearFile() }}
            aria-label="Remove selected file"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Error display */}
      {error && (
        <div className="notice notice-error mt-4" role="alert" id="upload-error">
          <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Scanning progress */}
      {scanning && (
        <div className="scan-progress">
          <div className="spinner" aria-label="Scanning in progress" />
          <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>{progress}</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            Validating archive, invoking scanner, applying risk classification…
          </div>
          <div className="progress-bar-track" style={{ width: 280 }}>
            <div className="progress-bar-fill" />
          </div>
        </div>
      )}

      {/* Actions */}
      {!scanning && (
        <div className="flex gap-3 mt-4" style={{ flexWrap: 'wrap' }}>
          <button
            id="start-scan-btn"
            className="btn btn-primary btn-lg"
            onClick={handleScan}
            disabled={!selectedFile || !isApiOnline}
            aria-label="Start scanning the selected file"
          >
            <Upload size={16} />
            {selectedFile ? 'Start scan' : 'Select a file to scan'}
          </button>
          <button
            id="sample-scan-btn"
            className="btn btn-secondary"
            onClick={handleSampleScan}
            disabled={!isApiOnline}
            aria-label="Scan the bundled sample repository"
          >
            Try bundled sample
          </button>
          {selectedFile && (
            <button id="reset-btn" className="btn btn-ghost" onClick={clearFile}>
              Reset
            </button>
          )}
        </div>
      )}

      {/* Info about what gets scanned */}
      <div style={{ marginTop: 'var(--sp-8)' }}>
        <div className="divider-label">How it works</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          {HOW_IT_WORKS.map((step, i) => (
            <div key={i} style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'flex-start' }}>
              <div className="step-number">{i + 1}</div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>{step.title}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{step.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

const HOW_IT_WORKS = [
  { title: 'Archive validation', desc: 'ZIP is checked for path traversal, size limits, and entry count. Only source files are extracted to an isolated temp directory.' },
  { title: 'Cryptographic pattern scan', desc: 'Member 1\'s scanner analyses source files for cryptographic API calls, imports, and identifiers across Python, Java, and C.' },
  { title: 'Quantum risk classification', desc: 'Member 2\'s risk engine applies documented NIST-based rules to classify each finding and assign migration priority.' },
  { title: 'Results and export', desc: 'Enriched findings are returned with explanations and migration recommendations. Download as JSON or CSV.' },
]
