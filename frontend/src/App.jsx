import { useCallback, useEffect, useRef, useState } from 'react'
import Header from './components/Header'
import AgentLog from './components/AgentLog'
import ReportViewer from './components/ReportViewer'
import { fetchReport, fetchStatus, openAgentStream } from './api'

// Mobile tab IDs
const TABS = ['TERMINAL', 'INTEL', 'REPORT']

export default function App() {
  // Agent state
  const [agentStatus, setAgentStatus] = useState('IDLE')
  const [isRunning, setIsRunning] = useState(false)
  const [reportReady, setReportReady] = useState(false)
  const [showReport, setShowReport] = useState(false)

  // Data state
  const [logLines, setLogLines] = useState([])
  const [reportMd, setReportMd] = useState(null)
  const [pipelineOutput, setPipelineOutput] = useState(null)

  // UI state
  const [activeTab, setActiveTab] = useState('TERMINAL')

  const streamCleanup = useRef(null)

  // Boot: only sync running-state with the backend.
  // We intentionally DO NOT hydrate pipelineOutput / report on first load —
  // insights (rank-flip banner, scores, PRs) must only appear AFTER the
  // user clicks Run in this session. A page refresh always returns to the
  // pre-run DETECTED state, which keeps the demo flow coherent.
  useEffect(() => {
    async function boot() {
      const status = await fetchStatus()
      setAgentStatus(mapStatus(status.status))
    }
    boot()
  }, [])

  // Execute agent (trigger backend + animate terminal)
  const runAgent = useCallback(() => {
    if (isRunning) return

    setIsRunning(true)
    setAgentStatus('RUNNING')
    setReportReady(false)
    setShowReport(false)
    setLogLines([])

    const cleanup = openAgentStream({
      onLine: (entry) => setLogLines((prev) => [...prev, entry]),
      onDone: async () => {
        setIsRunning(false)
        const status = await fetchStatus()
        setAgentStatus(mapStatus(status.status))
        setPipelineOutput(status.output || null)

        const report = await fetchReport()
        if (report) setReportMd(report)
        setReportReady(true)
      },
    })

    streamCleanup.current = cleanup
  }, [isRunning])

  useEffect(() => () => streamCleanup.current?.(), [])

  const ranking = pipelineOutput?.ranking || null
  const rankings = ranking?.rankings || []
  const remediated = pipelineOutput?.remediated || []
  const deferred = pipelineOutput?.deferred || []
  const prs = pipelineOutput?.pull_requests || []

  const stats = {
    total: rankings.length,
    critical: remediated.length,
    patched: prs.length,
    deferred: deferred.length,
  }

  const headerProps = {
    agentStatus,
    stats,
    isRunning,
    onRun: runAgent,
    onShowReport: () => {
      setShowReport((v) => !v)
      setActiveTab('REPORT')
    },
    reportReady,
    showReport,
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-v-bg font-mono">
      <div className="scan-line" />
      <Header {...headerProps} />

      {/* Desktop layout */}
      <div className="hidden lg:flex flex-1 overflow-hidden">
        {showReport ? (
          <ReportViewer markdown={reportMd} />
        ) : (
          <>
            <div className="w-[36%] xl:w-[34%] border-r border-v-border flex flex-col overflow-hidden">
              <AgentLog logs={logLines} isRunning={isRunning} />
            </div>
            <div className="flex-1 overflow-hidden min-w-0">
              <RankingPanel
                ranking={ranking}
                rankings={rankings}
                remediated={remediated}
                deferred={deferred}
                pullRequests={prs}
              />
            </div>
          </>
        )}
      </div>

      {/* Mobile layout */}
      <div className="flex lg:hidden flex-col flex-1 overflow-hidden">
        <div className="flex-1 overflow-hidden">
          {activeTab === 'TERMINAL' && <AgentLog logs={logLines} isRunning={isRunning} />}
          {activeTab === 'INTEL' && (
            <div className="overflow-y-auto h-full">
              <RankingPanel
                ranking={ranking}
                rankings={rankings}
                remediated={remediated}
                deferred={deferred}
                pullRequests={prs}
              />
            </div>
          )}
          {activeTab === 'REPORT' && <ReportViewer markdown={reportMd} />}
        </div>

        <nav className="shrink-0 flex border-t border-v-border bg-v-surface safe-bottom">
          {TABS.map((tab) => (
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
              {activeTab === tab && <span className="absolute top-0 left-1/4 right-1/4 h-px bg-v-amber" />}
            </button>
          ))}
        </nav>
      </div>
    </div>
  )
}

function mapStatus(s) {
  const v = String(s || '').toLowerCase()
  if (v === 'running') return 'RUNNING'
  if (v === 'done') return 'HARDENED'
  if (v === 'error') return 'ERROR'
  return 'IDLE'
}

function ScoreBar({ label, value }) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0))
  const color = pct >= 70 ? 'bg-v-red' : pct >= 40 ? 'bg-v-amber' : 'bg-v-green'
  return (
    <div className="flex items-center gap-2">
      <div className="w-[78px] text-[9px] text-v-dim-text tracking-widest">{label}</div>
      <div className="flex-1 h-1 rounded-full bg-v-dim overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="w-10 text-right text-[9px] tabular-nums text-v-text">{pct.toFixed(1)}</div>
    </div>
  )
}

function Card({ title, children, right }) {
  return (
    <div className="glass border border-v-border rounded-lg overflow-hidden">
      <div className="px-4 py-2.5 border-b border-v-border flex items-center justify-between">
        <div className="text-[9px] text-v-dim-text tracking-[0.2em] font-mono">{title}</div>
        {right}
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

function RankingPanel({ ranking, rankings, remediated, deferred, pullRequests }) {
  const explanation = ranking?.explanation || ''
  const top = rankings?.[0] || null

  return (
    <div className="p-4 flex flex-col gap-4 overflow-y-auto h-full">
      {explanation && (
        <div className="border border-v-blue/40 bg-v-blue-dim rounded-lg px-4 py-3">
          <div className="text-[9px] text-v-blue tracking-[0.2em] mb-1 font-mono">RANK-FLIP INSIGHT</div>
          <div className="text-[10px] text-v-text leading-relaxed">{explanation}</div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card
          title="TOP PICK (PATCH FIRST)"
          right={top ? <span className="text-[9px] text-v-amber font-mono">#{top.rank} • {top.vuln_id}</span> : null}
        >
          {!top ? (
            <div className="text-[10px] text-v-dim-text">Run the agent to generate rankings.</div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-baseline justify-between gap-3">
                <div className="text-[11px] text-v-bright font-semibold">{top.vuln_id}</div>
                <div className="text-[10px] font-mono text-v-amber tabular-nums">
                  composite {Number(top.composite_score || 0).toFixed(2)}
                </div>
              </div>

              <div className="space-y-2">
                <ScoreBar label="ACTIVE" value={top.sub_scores?.active_exploitation} />
                <ScoreBar label="EXTERNAL" value={top.sub_scores?.external_pressure} />
                <ScoreBar label="STATIC" value={top.sub_scores?.static_severity} />
              </div>

              {top.sample_trace_id && (
                <div className="text-[10px] font-mono">
                  <span className="text-v-dim-text">trace_id </span>
                  <span className="text-v-blue break-all">{top.sample_trace_id}</span>
                </div>
              )}
              {top.sample_payload && (
                <div className="text-[10px] font-mono">
                  <span className="text-v-dim-text">payload  </span>
                  <span className="text-v-text break-all">{top.sample_payload}</span>
                </div>
              )}

              {top.reasoning && (
                <div className="text-[10px] text-v-text leading-relaxed">
                  <span className="text-v-dim-text font-mono">reason </span>
                  {top.reasoning}
                </div>
              )}
            </div>
          )}
        </Card>

        <Card title="PULL REQUESTS">
          {pullRequests?.length ? (
            <div className="space-y-2 text-[10px]">
              {pullRequests.map((pr) => (
                <div key={`${pr.vuln_id}-${pr.rank}`} className="border border-v-dim/60 rounded px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-v-text font-mono">#{pr.rank} {pr.vuln_id}</div>
                    <div className="text-v-dim-text font-mono">{pr.pr_status}</div>
                  </div>
                  <div className="text-v-blue break-all">{pr.pr_url}</div>
                  {pr.branch && <div className="text-v-dim-text font-mono">branch: {pr.branch}</div>}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[10px] text-v-dim-text">No PRs created in the last run.</div>
          )}
        </Card>
      </div>

      <Card title="SUB-SCORE RANKINGS">
        {rankings?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-[10px] font-mono border-collapse">
              <thead className="sticky top-0 bg-v-surface z-10">
                <tr className="text-[9px] text-v-dim-text">
                  {['RANK', 'VULN', 'COMPOSITE', 'ACTIVE', 'EXTERNAL', 'STATIC'].map((h) => (
                    <th key={h} className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rankings.map((r) => (
                  <tr key={`${r.vuln_id}-${r.rank}`} className="border-b border-v-dim/50">
                    <td className="px-3 py-2.5 text-v-amber">#{r.rank}</td>
                    <td className="px-3 py-2.5 text-v-blue font-semibold">{r.vuln_id}</td>
                    <td className="px-3 py-2.5 tabular-nums text-v-text">{Number(r.composite_score || 0).toFixed(2)}</td>
                    <td className="px-3 py-2.5 tabular-nums text-v-text">{Number(r.sub_scores?.active_exploitation || 0).toFixed(1)}</td>
                    <td className="px-3 py-2.5 tabular-nums text-v-text">{Number(r.sub_scores?.external_pressure || 0).toFixed(1)}</td>
                    <td className="px-3 py-2.5 tabular-nums text-v-text">{Number(r.sub_scores?.static_severity || 0).toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-[10px] text-v-dim-text">No rankings available.</div>
        )}
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card title="REMEDIATED">
          {remediated?.length ? (
            <div className="space-y-2 text-[10px]">
              {remediated.map((r) => (
                <div key={`${r.vuln_id}-${r.rank}`} className="border border-v-dim/60 rounded px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-v-text font-mono">#{r.rank} {r.vuln_id}</div>
                    <div className="text-v-green font-mono">{r.outcome}</div>
                  </div>
                  {r.action && <div className="text-v-dim-text">{r.action}</div>}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[10px] text-v-dim-text">Nothing remediated in the last run.</div>
          )}
        </Card>

        <Card title="DEFERRED">
          {deferred?.length ? (
            <div className="space-y-2 text-[10px]">
              {deferred.map((d) => (
                <div key={`${d.vuln_id}-${d.rank}`} className="border border-v-dim/60 rounded px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-v-text font-mono">#{d.rank} {d.vuln_id}</div>
                    <div className="text-v-amber font-mono">deferred</div>
                  </div>
                  {d.reason && <div className="text-v-dim-text">{d.reason}</div>}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[10px] text-v-dim-text">Nothing deferred in the last run.</div>
          )}
        </Card>
      </div>
    </div>
  )
}

