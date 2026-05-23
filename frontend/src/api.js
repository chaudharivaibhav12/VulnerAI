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
 * Opens an EventSource to /api/stream.
 * Calls onLine({ ts, level, module, msg }) for each agent log line.
 * Calls onDone() when the agent cycle completes.
 * Returns a cleanup function - call it to close the stream.
 *
 * Falls back to the dummy AGENT_LOG timer if backend is unreachable.
 */
export function openAgentStream({ onLine, onDone }) {
  let es
  let alive = true

  try {
    es = new EventSource(`${BASE_URL}/api/stream`)

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.done) {
          onDone()
          es.close()
        } else {
          onLine(data)
        }
      } catch {
        // ignore malformed events
      }
    }

    es.onerror = () => {
      es.close()
      if (alive) _fallbackStream({ onLine, onDone })
    }
  } catch {
    _fallbackStream({ onLine, onDone })
  }

  return () => {
    alive = false
    es?.close()
  }
}

function _fallbackStream({ onLine, onDone }) {
  let i = 0
  const id = setInterval(() => {
    if (i < AGENT_LOG.length) {
      onLine(AGENT_LOG[i])
      i++
    } else {
      clearInterval(id)
      onDone()
    }
  }, 260)
}

