/**
 * api.js — QuantumShield API client
 *
 * Wraps all calls to the FastAPI backend.
 * Never substitutes fake results when the backend is unavailable.
 * All errors propagate as structured objects so the UI can display them accurately.
 */

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api'

/**
 * Generic fetch wrapper that always returns { data, error }.
 * Never throws — the UI decides how to handle errors.
 */
async function apiFetch(path, options = {}) {
  try {
    const resp = await fetch(`${API_BASE}${path}`, options)
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`
      try {
        const body = await resp.json()
        if (body?.detail?.message) detail = body.detail.message
        else if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
        else if (body?.message) detail = body.message
      } catch (_) { /* body was not JSON */ }
      return { data: null, error: { status: resp.status, message: detail } }
    }
    const data = await resp.json()
    return { data, error: null }
  } catch (err) {
    // Network error or JSON parse failure
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      return {
        data: null,
        error: {
          status: 0,
          message: 'Cannot reach the QuantumShield API. Is the backend running on port 8000?',
        },
      }
    }
    return { data: null, error: { status: 0, message: err.message } }
  }
}

/** GET /api/health */
export async function getHealth() {
  return apiFetch('/health')
}

/**
 * POST /api/scan
 * @param {File} file - ZIP file to upload
 * @param {function} onProgress - optional progress callback (not all browsers support upload progress)
 */
export async function submitScan(file, onProgress) {
  const formData = new FormData()
  formData.append('file', file)
  return apiFetch('/scan', { method: 'POST', body: formData })
}

/** GET /api/scans */
export async function listScans() {
  return apiFetch('/scans')
}

/**
 * GET /api/scan/{scan_id}/report?format=json|csv
 * Returns a Blob for download.
 */
export async function downloadReport(scanId, format = 'json') {
  try {
    const resp = await fetch(`${API_BASE}/scan/${scanId}/report?format=${format}`)
    if (!resp.ok) {
      let msg = `HTTP ${resp.status}`
      try { const body = await resp.json(); msg = body?.detail?.message || msg } catch (_) {}
      return { blob: null, filename: null, error: msg }
    }
    const contentDisposition = resp.headers.get('Content-Disposition') || ''
    const match = contentDisposition.match(/filename="(.+)"/)
    const filename = match ? match[1] : `quantumshield_report.${format}`
    const blob = await resp.blob()
    return { blob, filename, error: null }
  } catch (err) {
    return { blob: null, filename: null, error: err.message }
  }
}

/** Trigger a browser download from a Blob */
export function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

/** Format bytes to human-readable string */
export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** Format ISO timestamp to local string */
export function formatTimestamp(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium', timeStyle: 'short',
    })
  } catch (_) {
    return iso
  }
}

/** Map risk level to CSS class suffix */
export function riskClass(level) {
  const map = { HIGH: 'high', MODERATE: 'moderate', LOWER: 'lower', UNKNOWN: 'unknown' }
  return map[String(level).toUpperCase()] || 'unknown'
}

/** Map migration priority to display label */
export function priorityLabel(priority) {
  const map = {
    HIGH: 'High priority',
    MEDIUM: 'Medium priority',
    LOW: 'Low priority',
    REVIEW_REQUIRED: 'Review required',
  }
  return map[priority] || priority || '—'
}

/** Map cryptographic purpose to display label */
export function purposeLabel(purpose) {
  const map = {
    DIGITAL_SIGNATURE: 'Digital signature',
    KEY_ESTABLISHMENT: 'Key establishment',
    SYMMETRIC_ENCRYPTION: 'Symmetric encryption',
    HASH_FUNCTION: 'Hash function',
    UNKNOWN: 'Unknown',
    AMBIGUOUS: 'Ambiguous',
  }
  return map[purpose] || purpose || '—'
}
