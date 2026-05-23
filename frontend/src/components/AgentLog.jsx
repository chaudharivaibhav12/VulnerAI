import { useEffect, useRef, useState } from 'react'

const LEVEL = {
  INFO: { color: 'text-v-blue',      label: 'INFO' },
  WARN: { color: 'text-v-amber',     label: 'WARN' },
  CRIT: { color: 'text-v-red',       label: 'CRIT' },
  OK:   { color: 'text-v-green',     label: ' OK ' },
}

const MODULE = {
  DETECT: 'text-purple-400',
  NIMBLE: 'text-sky-400',
  CH:     'text-cyan-300',
  TRIAGE: 'text-orange-400',
  PATCH:  'text-v-red',
  REPORT: 'text-v-blue',
  AGENT:  'text-v-amber',
}

export default function AgentLog({ logs, isRunning }) {
  const [count, setCount] = useState(0)
  const bottomRef = useRef(null)

  useEffect(() => {
    if (!isRunning) { setCount(logs.length); return }
    setCount(0)
    let i = 0
    const id = setInterval(() => {
      i += 1
      setCount(i)
      if (i >= logs.length) clearInterval(id)
    }, 260)
    return () => clearInterval(id)
  }, [isRunning, logs])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [count])

  const visible = logs.slice(0, count)

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-v-border shrink-0">
        <span className="text-[9px] text-v-dim-text tracking-[0.2em] font-mono">AGENT TERMINAL</span>
        <div className="flex items-center gap-3 text-[9px] font-mono">
          <span className="text-v-dim-text tabular-nums">{count}/{logs.length}</span>
          {isRunning && <span className="text-v-amber dot-pulse">●</span>}
        </div>
      </div>

      {/* Log body */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-1">
        {visible.map((e, i) => {
          const lvl = LEVEL[e.level] || LEVEL.INFO
          const mod = MODULE[e.module] || 'text-v-dim-text'
          return (
            <div key={i} className="flex items-start gap-2 text-[10px] font-mono leading-relaxed animate-slide-up">
              <span className="text-v-amber shrink-0 tabular-nums opacity-60">{e.ts}</span>
              <span className={`shrink-0 w-[28px] text-center text-[8px] font-semibold ${lvl.color}`}>{lvl.label}</span>
              <span className={`shrink-0 w-[54px] text-[9px] ${mod}`}>[{e.module}]</span>
              <span className="text-v-text min-w-0 break-words">{e.msg}</span>
            </div>
          )
        })}

        {/* Cursor */}
        {count < logs.length && (
          <div className="flex items-center gap-2 text-[10px] font-mono text-v-amber pl-[84px]">
            <span className="animate-blink">█</span>
          </div>
        )}

        {/* Done state */}
        {count >= logs.length && count > 0 && (
          <div className="mt-3 pt-3 border-t border-v-dim text-[9px] font-mono text-v-green flex items-center gap-2">
            <span>●</span>
            <span>CYCLE COMPLETE — SYSTEM POSTURE: HARDENED</span>
          </div>
        )}

        <div ref={bottomRef} />
      </div>
    </div>
  )
}
