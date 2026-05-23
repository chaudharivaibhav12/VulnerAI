import { useState, useCallback } from 'react'
import Header from './components/Header'
import ServiceCards from './components/ServiceCards'
import AgentLog from './components/AgentLog'
import CVETable from './components/CVETable'
import ReportViewer from './components/ReportViewer'
import { SERVICES, CVE_FINDINGS, AGENT_LOG, REPORT_MD } from './data/dummy'

// Mobile tab IDs
const TABS = ['TERMINAL', 'SERVICES', 'INTEL', 'REPORT']

export default function App() {
  const [agentStatus, setAgentStatus]       = useState('IDLE')
  const [isRunning, setIsRunning]           = useState(false)
  const [reportReady, setReportReady]       = useState(false)
  const [showReport, setShowReport]         = useState(false)
  const [selectedService, setSelectedService] = useState(null)
  const [selectedCVE, setSelectedCVE]       = useState(null)
  const [activeTab, setActiveTab]           = useState('TERMINAL')

  const runAgent = useCallback(() => {
    if (isRunning) return
    setIsRunning(true)
    setAgentStatus('RUNNING')
    setReportReady(false)
    setShowReport(false)
    setSelectedCVE(null)

    const duration = AGENT_LOG.length * 260 + 600
    setTimeout(() => {
      setIsRunning(false)
      setAgentStatus('HARDENED')
      setReportReady(true)
    }, duration)
  }, [isRunning])

  const filteredFindings = selectedService
    ? CVE_FINDINGS.filter(f => f.service_id === selectedService.id)
    : CVE_FINDINGS

  const stats = {
    total:    CVE_FINDINGS.length,
    critical: CVE_FINDINGS.filter(f => f.priority === 'CRITICAL').length,
    patched:  CVE_FINDINGS.filter(f => f.status === 'PATCHED').length,
    deferred: CVE_FINDINGS.filter(f => f.status === 'DEFERRED').length,
  }

  const headerProps = {
    agentStatus, stats, onRun: runAgent, isRunning,
    onShowReport: () => setShowReport(v => !v),
    reportReady, showReport,
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-v-bg font-mono">
      <div className="scan-line" />
      <Header {...headerProps} />

      {/* ── DESKTOP LAYOUT (md+) ──────────────────────────────── */}
      <div className="hidden md:flex flex-1 overflow-hidden">
        {showReport ? (
          <ReportViewer markdown={reportReady ? REPORT_MD : null} />
        ) : (
          <>
            {/* Left: Agent terminal */}
            <div className="w-[38%] xl:w-[36%] border-r border-v-border flex flex-col overflow-hidden">
              <AgentLog logs={AGENT_LOG} isRunning={isRunning} />
            </div>

            {/* Right: Services + CVE table */}
            <div className="flex-1 flex flex-col overflow-hidden">
              <ServiceCards
                services={SERVICES}
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

      {/* ── MOBILE LAYOUT (< md) ─────────────────────────────── */}
      <div className="flex md:hidden flex-col flex-1 overflow-hidden">
        {/* Panel */}
        <div className="flex-1 overflow-hidden">
          {activeTab === 'TERMINAL' && (
            <AgentLog logs={AGENT_LOG} isRunning={isRunning} />
          )}
          {activeTab === 'SERVICES' && (
            <div className="overflow-y-auto h-full">
              <ServiceCards
                services={SERVICES}
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
            <ReportViewer markdown={reportReady ? REPORT_MD : null} />
          )}
        </div>

        {/* Bottom tab bar */}
        <nav className="shrink-0 flex border-t border-v-border bg-v-surface">
          {TABS.map(tab => {
            const isReport = tab === 'REPORT'
            const active = activeTab === tab
            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`
                  flex-1 py-2.5 text-[9px] font-mono tracking-widest transition-colors relative
                  ${active ? 'text-v-amber' : 'text-v-dim-text hover:text-v-text'}
                `}
              >
                {tab}
                {isReport && reportReady && !active && (
                  <span className="absolute top-2 right-[calc(50%-14px)] w-1.5 h-1.5 rounded-full bg-v-green" />
                )}
                {active && (
                  <span className="absolute top-0 left-1/4 right-1/4 h-px bg-v-amber" />
                )}
              </button>
            )
          })}
        </nav>
      </div>
    </div>
  )
}
