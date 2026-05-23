/**
 * VulnerAI API client
 *
 * Tries the local backend first (default: 127.0.0.1:8787).
 * Falls back to dummy data automatically if the backend isn't running.
 * Set VITE_API_URL to your deployed backend URL for production.
 */

import { CVE_FINDINGS, AGENT_LOG } from './data/dummy'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8787'

async function safeFetch(path) {
  try {
    const res = await fetch(`${BASE_URL}${path}`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return await res.json()
  } catch {
    return null // caller decides the fallback
  }
}

export async function fetchStatus() {
  const data = await safeFetch('/api/status')
  return data ?? { status: 'IDLE', last_run: null }
}

export async function fetchTriage() {
  const rows = await safeFetch('/api/triage')

  if (rows && rows.length > 0) {
    // Normalize backend field names -> what CVETable expects
    return rows.map(r => ({
      ...r,
      id: r.cve_id ?? r.id,
      cvss: r.cvss_score ?? r.cvss ?? 0,
      service_name: r.host_name ?? r.service_name ?? r.cve_id ?? r.id,
    }))
  }

  return CVE_FINDINGS
}

export async function fetchRemediation() {
  const rows = await safeFetch('/api/remediation')
  return rows ?? []
}

export async function fetchReport() {
  const data = await safeFetch('/api/report')
  if (data?.ready && data.markdown) return data.markdown
  return null
}

export async function triggerRun() {
  try {
    const res = await fetch(`${BASE_URL}/api/run`, { method: 'POST' })
    return await res.json()
  } catch {
    return { error: 'Backend not reachable' }
  }
}

/**
 * Triggers the real pipeline via POST /api/run, then:
 * - Streams dummy log entries to the terminal while the pipeline runs
 * - Polls /api/status every 2s until it leaves RUNNING
 * - Calls onDone() when the pipeline finishes (HARDENED / ERROR)
 * - Falls back to pure dummy animation if the backend is unreachable
 * Returns a cleanup function.
 */
export function openAgentStream({ onLine, onDone }) {
  let alive = true
  let pollId = null
  let logId = null
  let seenRunning = false

  // Animate the terminal with dummy log while backend runs
  let i = 0
  logId = setInterval(() => {
    if (!alive) return
    if (i < AGENT_LOG.length) onLine(AGENT_LOG[i++])
  }, 260)

  // Kick off the real pipeline then poll for completion
  fetch(`${BASE_URL}/api/run?reset=1`, { method: 'POST' })
    .then(() => {
      pollId = setInterval(async () => {
        if (!alive) return
        try {
          const res = await fetch(`${BASE_URL}/api/status`)
          if (!res.ok) return
          const { status } = await res.json()
          const s = (status || '').toLowerCase()
          if (s === 'running') {
            seenRunning = true
          } else if (seenRunning && (s === 'done' || s === 'error' || s === 'idle')) {
            // Pipeline finished — stop everything and notify
            clearInterval(pollId)
            clearInterval(logId)
            alive = false
            onDone()
          }
        } catch { /* keep polling */ }
      }, 1000)
    })
    .catch(() => {
      // Backend unreachable — finish after dummy log completes
      clearInterval(logId)
      logId = setInterval(() => {
        if (i < AGENT_LOG.length) {
          onLine(AGENT_LOG[i++])
        } else {
          clearInterval(logId)
          onDone()
        }
      }, 260)
    })

  return () => {
    alive = false
    clearInterval(pollId)
    clearInterval(logId)
  }
}

