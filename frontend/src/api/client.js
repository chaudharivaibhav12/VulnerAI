async function request(path, options) {
  const res = await fetch(path, options)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`API ${res.status}: ${text || res.statusText}`)
  }
  return res
}

export async function getStatus() {
  const res = await request('/api/status')
  return res.json()
}

export async function runPipeline({ reset = true } = {}) {
  const res = await request(`/api/run?reset=${reset ? 1 : 0}`, { method: 'POST' })
  return res.json()
}

export async function getServices() {
  const res = await request('/api/services')
  return res.json()
}

export async function getFindings() {
  const res = await request('/api/triage')
  return res.json()
}

export async function getRemediationLog() {
  const res = await request('/api/remediation')
  return res.json()
}

export async function getReport() {
  const res = await request('/api/report')
  return res.text()
}

