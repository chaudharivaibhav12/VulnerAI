import { useState, useCallback, useEffect, useRef } from 'react'
import Header from './components/Header'
import ServiceCards from './components/ServiceCards'
import AgentLog from './components/AgentLog'
import CVETable from './components/CVETable'
import ReportViewer from './components/ReportViewer'
import { SERVICES } from './data/dummy'
import {
  fetchStatus, fetchTriage, fetchReport, openAgentStream
} from './api'

const TABS = ['TERMINAL', 'SERVICES', 'INTEL', 'REPORT']

export default function App() {
  // Agent state
  const [agentStatus, setAgentStatus]   = useState('IDLE')
  const [isRunning, setIsRunning]       = useState(false)
  const [reportReady, setReportReady]   = useState(false)
  const [showReport, setShowReport]     = useState(false)

  // Data state
  const [logLines, setLogLines]         = useState([])
  const [triage, setTriage]             = useState([])
  const [reportMd, setReportMd]         = useState(null)

  // UI state
  const [selectedService, setSelectedService] = useState(null)
  const [selectedCVE, setSelectedCVE]         = useState(null)
  const [activeTab, setActiveTab]             = useState('TERMINAL')

  const streamCleanup = useRef(null)

  // ── Boot: load existing data ────────────────────────────
  useEffect(() => {
    async function boot() {
      const [status, rows, report] = await Promise.all([
        fetchStatus(),
        fetchTriage(),
        fetchReport(),
      ])

      setAgentStatus(status.status || 'IDLE')
      if (rows?.length) setTriage(rows)
      if (report) { setReportMd(report); setReportReady(true) }
    }
    boot()
  }, [])

  // ── Poll triage every 5s while running ─────────────────
  useEffect(() => {
    if (!isRunning) return
    const id = setInterval(async () => {
      const rows = await fetchTriage()
      if (rows?.length) setTriage(rows)
    }, 5000)
    return () => clearInterval(id)
  }, [isRunning])

  // ── Execute agent ───────────────────────────────────────
  const runAgent = useCallback(() => {
    if (isRunning) return

    setIsRunning(true)
    setAgentStatus('RUNNING')
    setReportReady(false)
    setShowReport(false)
    setLogLines([])
    setSelectedCVE(null)

    const cleanup = openAgentStream({
      onLine: (entry) => setLogLines(prev => [...prev, entry]),
      onDone: async () => {
        setIsRunning(false)
        setAgentStatus('HARDENED')

        // Fetch updated data after cycle
        const [rows, report] = await Promise.all([fetchTriage(), fetchReport()])
        if (rows?.length)  setTriage(rows)
        if (report)        setReportMd(report)
        setReportReady(true)
      },
    })

    streamCleanup.current = cleanup
  }, [isRunning])

  // Cleanup stream on unmount
  useEffect(() => () => streamCleanup.current?.(), [])

  // ── Derived data ────────────────────────────────────────
  const filteredFindings = selectedService
    ? triage.filter(f => f.host_name === selectedService.name || f.host_ip === selectedService.host)
    : triage

  // Map backend triage rows → ServiceCards expects the SERVICES shape
  const enrichedServices = SERVICES.map(svc => {
    const svcTriage = triage.filter(f =>
      f.host_name === svc.name || f.host_ip === svc.host
    )
    const hasCritical = svcTriage.some(f => f.priority === 'CRITICAL')
    const hasPatched  = svcTriage.some(f => f.status  === 'PATCHED')
    return {
      ...svc,
      cve_count: svcTriage.length,
      status: hasCritical && hasPatched ? 'PATCHED'
            : hasCritical               ? 'CRITICAL'
            : 'DEFERRED',
    }
  })

  const stats = {
    total:    triage.length,
    critical: triage.filter(f => f.priority === 'CRITICAL').length,
    patched:  triage.filter(f => f.status   === 'PATCHED').length,
    deferred: triage.filter(f => f.status   === 'DEFERRED').length,
  }

  const headerProps = {
    agentStatus, stats, isRunning,
    onRun:        runAgent,
    onShowReport: () => { setShowReport(v => !v); setActiveTab('REPORT') },
    reportReady,
    showReport,
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-v-bg font-mono">
      <div className="scan-line" />
      <Header {...headerProps} />

      {/* ── DESKTOP (lg+) ──────────────────────────────── */}
      <div className="hidden lg:flex flex-1 overflow-hidden">
        {showReport ? (
          <ReportViewer markdown={reportMd} />
        ) : (
          <>
            <div className="w-[36%] xl:w-[34%] border-r border-v-border flex flex-col overflow-hidden">
              <AgentLog logs={logLines} isRunning={isRunning} />
            </div>
            <div className="flex-1 flex flex-col overflow-hidden min-w-0">
              <ServiceCards
                services={enrichedServices}
                selected={selectedService}
                onSelect={setSelectedService}
              />
              <CVETable
                findings={filteredFindings}
                selected={selectedCVE}
                onSelect={setSelectedCVE}
              />
            </div>
          </>
        )}
      </div>

      {/* ── MOBILE / TABLET (< lg) ────────────────────── */}
      <div className="flex lg:hidden flex-col flex-1 overflow-hidden">
        <div className="flex-1 overflow-hidden">
          {activeTab === 'TERMINAL' && (
            <AgentLog logs={logLines} isRunning={isRunning} />
          )}
          {activeTab === 'SERVICES' && (
            <div className="overflow-y-auto h-full">
              <ServiceCards
                services={enrichedServices}
                selected={selectedService}
                onSelect={setSelectedService}
              />
            </div>
          )}
          {activeTab === 'INTEL' && (
            <CVETable
              findings={filteredFindings}
              selected={selectedCVE}
              onSelect={setSelectedCVE}
            />
          )}
          {activeTab === 'REPORT' && (
            <ReportViewer markdown={reportMd} />
          )}
        </div>

        <nav className="shrink-0 flex border-t border-v-border bg-v-surface safe-bottom">
          {TABS.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`
                flex-1 py-3 text-[9px] font-mono tracking-widest transition-colors relative
                ${activeTab === tab ? 'text-v-amber' : 'text-v-dim-text hover:text-v-text'}
              `}
            >
              {tab}
              {tab === 'REPORT' && reportReady && activeTab !== 'REPORT' && (
                <span className="absolute top-2 right-[calc(50%-14px)] w-1.5 h-1.5 rounded-full bg-v-green" />
              )}
              {activeTab === tab && (
                <span className="absolute top-0 left-1/4 right-1/4 h-px bg-v-amber" />
              )}
            </button>
          ))}
        </nav>
      </div>
    </div>
  )
}
