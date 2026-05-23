import { Globe, Lock, AlertTriangle, CheckCircle, Clock } from 'lucide-react'

const STATUS_CFG = {
  CRITICAL: { border: 'border-v-red',   glow: 'animate-critical-glow', badge: 'bg-v-red-dim text-v-red border-v-red',   icon: AlertTriangle, dot: 'bg-v-red' },
  PATCHED:  { border: 'border-v-green', glow: '',                       badge: 'bg-v-green-dim text-v-green border-v-green', icon: CheckCircle,  dot: 'bg-v-green' },
  DEFERRED: { border: 'border-v-dim',   glow: '',                       badge: 'bg-v-surface text-v-dim-text border-v-dim',  icon: Clock,        dot: 'bg-v-dim' },
}

function ServiceCard({ svc, selected, onClick }) {
  const cfg = STATUS_CFG[svc.status] || STATUS_CFG.DEFERRED
  const Icon = cfg.icon

  return (
    <button
      onClick={() => onClick(svc)}
      className={`
        relative w-full text-left rounded-lg border p-4 transition-all duration-200 cursor-pointer glass
        ${cfg.border} ${cfg.glow}
        ${selected ? 'bg-v-raised' : 'hover:bg-v-raised/60'}
      `}
    >
      {/* Top row */}
      <div className="flex items-start justify-between mb-2.5">
        <div className="min-w-0 flex-1 pr-2">
          <div className="text-v-bright text-[11px] font-semibold truncate">{svc.name}</div>
          <div className="text-v-dim-text text-[9px] mt-0.5 font-mono tabular-nums">{svc.host}</div>
        </div>
        <span className={`shrink-0 flex items-center gap-1 px-1.5 py-0.5 rounded border text-[8px] font-bold ${cfg.badge}`}>
          <Icon size={8} />
          {svc.status}
        </span>
      </div>

      {/* Software */}
      <div className="text-[9px] text-v-dim-text font-mono mb-3 truncate">{svc.software}</div>

      {/* Bottom row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          {svc.internet_exposed ? (
            <>
              <Globe size={9} className="text-v-red shrink-0" />
              <span className="text-v-red text-[9px] font-bold">EXPOSED</span>
            </>
          ) : (
            <>
              <Lock size={9} className="text-v-green shrink-0" />
              <span className="text-v-green text-[9px]">INTERNAL</span>
            </>
          )}
        </div>
        <span className={`text-[9px] font-mono ${svc.cve_count > 0 ? 'text-v-amber' : 'text-v-dim-text'}`}>
          {svc.cve_count} CVE{svc.cve_count !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Selected indicator */}
      {selected && (
        <div className="absolute left-0 top-3 bottom-3 w-0.5 rounded-r bg-v-amber" />
      )}
    </button>
  )
}

export default function ServiceCards({ services, selected, onSelect }) {
  return (
    <div className="p-4 border-b border-v-border shrink-0">
      <div className="text-[9px] text-v-dim-text tracking-[0.2em] mb-3 font-mono">ATTACK SURFACE</div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {services.map(svc => (
          <ServiceCard
            key={svc.id}
            svc={svc}
            selected={selected?.id === svc.id}
            onClick={s => onSelect(prev => prev?.id === s.id ? null : s)}
          />
        ))}
      </div>
    </div>
  )
}
