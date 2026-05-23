import { useState, useEffect } from 'react'

const STATUS_CFG = {
  IDLE:     { color: 'text-v-dim-text', dot: 'bg-v-dim',   label: 'STANDBY' },
  RUNNING:  { color: 'text-v-amber',   dot: 'bg-v-amber',  label: 'RUNNING' },
  HARDENED: { color: 'text-v-green',   dot: 'bg-v-green',  label: 'HARDENED' },
  ERROR:    { color: 'text-v-red',     dot: 'bg-v-red',    label: 'ERROR' },
}

export default function Header({ agentStatus, stats, onRun, isRunning, onShowReport, reportReady, showReport }) {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const cfg = STATUS_CFG[agentStatus] || STATUS_CFG.IDLE
  const utc = time.toISOString().slice(11, 19)

  return (
    <header className="relative flex items-center justify-between px-4 h-14 shrink-0 border-b border-v-border glass z-10 gap-2">

      {/* Brand */}
      <div className="flex items-center gap-2 shrink-0">
        <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
          <path d="M10 1L2 4.5V10C2 14.418 5.582 18.418 10 19C14.418 18.418 18 14.418 18 10V4.5L10 1Z"
            stroke="#fbbf24" strokeWidth="1.2" fill="rgba(251,191,36,0.08)" />
          <path d="M7 10l2 2 4-4" stroke="#fbbf24" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="font-display text-v-amber text-sm font-bold tracking-[0.2em]">VULNERAI</span>
        <span className="hidden xl:block text-v-dim-text text-[9px] tracking-widest font-mono border-l border-v-dim pl-3">
          AUTONOMOUS SECURITY AGENT
        </span>
      </div>

      {/* Center stats — desktop only */}
      <div className="hidden lg:flex items-center gap-4 text-[10px] font-mono mx-auto">
        <Stat label="CVEs"      value={stats.total}    color="text-v-text" />
        <Stat label="CRITICAL"  value={stats.critical} color="text-v-red" />
        <Stat label="PATCHED"   value={stats.patched}  color="text-v-green" />
        <Stat label="DEFERRED"  value={stats.deferred} color="text-v-amber" />
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2 shrink-0">

        {/* UTC — large screens only */}
        <span className="hidden xl:block text-[10px] text-v-dim-text font-mono tabular-nums">
          {utc} UTC
        </span>

        {/* Status pill — tablet+ */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded border border-v-border bg-v-surface text-[9px] font-mono">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${cfg.dot} ${agentStatus === 'RUNNING' ? 'dot-pulse' : ''}`} />
          <span className={cfg.color}>{cfg.label}</span>
        </div>

        {/* Mobile status dot only */}
        <span className={`sm:hidden w-2 h-2 rounded-full shrink-0 ${cfg.dot} ${agentStatus === 'RUNNING' ? 'dot-pulse' : ''}`} />

        {/* Report button */}
        {reportReady && (
          <button
            onClick={onShowReport}
            className={`hidden sm:block px-2.5 py-1.5 rounded border text-[9px] font-mono font-medium transition-all duration-150
              ${showReport
                ? 'border-v-blue text-v-blue bg-v-blue-dim'
                : 'border-v-border text-v-dim-text hover:border-v-blue hover:text-v-blue'}`}
          >
            {showReport ? 'WAR ROOM' : 'REPORT'}
          </button>
        )}

        {/* Execute button */}
        <button
          onClick={isRunning ? undefined : onRun}
          disabled={isRunning}
          className={`flex items-center gap-1.5 px-3 sm:px-4 py-1.5 rounded border text-[9px] font-mono font-bold tracking-wider transition-all duration-150
            ${isRunning
              ? 'border-v-amber text-v-amber opacity-60 cursor-not-allowed'
              : 'border-v-amber text-v-amber hover:bg-v-amber hover:text-v-bg'}`}
        >
          {isRunning
            ? <><span className="w-1.5 h-1.5 rounded-full bg-v-amber dot-pulse" /><span className="hidden sm:inline">RUNNING</span></>
            : <><RunIcon /><span className="hidden sm:inline">EXECUTE</span></>
          }
        </button>
      </div>
    </header>
  )
}

function Stat({ label, value, color }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-v-dim-text">{label}</span>
      <span className={`font-semibold tabular-nums ${color}`}>{value}</span>
    </div>
  )
}

function RunIcon() {
  return (
    <svg width="9" height="9" viewBox="0 0 9 9" fill="currentColor" className="shrink-0">
      <polygon points="1,0.5 8.5,4.5 1,8.5" />
    </svg>
  )
}
