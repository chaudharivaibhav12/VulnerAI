import { ExternalLink } from 'lucide-react'

const PRIORITY_BADGE = {
  CRITICAL: 'text-v-red   border-v-red   bg-v-red-dim',
  LOW:      'text-v-amber border-v-amber bg-v-amber-dim',
}

const STATUS_COLOR = {
  PATCHED:  'text-v-green',
  DEFERRED: 'text-v-amber',
}

function CvssBar({ score }) {
  const pct = (score / 10) * 100
  const color = score >= 9 ? '#f43f5e' : score >= 7 ? '#fbbf24' : '#34d399'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-12 h-1 rounded-full bg-v-dim overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ color }} className="tabular-nums text-[10px] font-semibold">{score.toFixed(1)}</span>
    </div>
  )
}

function CVEDetail({ cve, onClose }) {
  return (
    <div className="border-t border-v-border bg-v-raised px-4 py-3 animate-slide-up shrink-0">
      <div className="flex items-start justify-between mb-2">
        <span className="text-v-blue text-[11px] font-semibold">{cve.id}</span>
        <button onClick={onClose} className="text-v-dim-text hover:text-v-bright text-xs ml-4 transition-colors">✕</button>
      </div>
      <p className="text-v-text text-[10px] mb-3 leading-relaxed">{cve.description}</p>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3 text-[10px] font-mono">
        <Field label="CVSS" value={cve.cvss.toFixed(1)} valueClass="text-v-red font-bold" />
        <Field label="EXPOSED" value={cve.internet_exposed ? 'YES' : 'NO'}
          valueClass={cve.internet_exposed ? 'text-v-red font-bold' : 'text-v-green'} />
        <Field label="EXPLOIT" value={cve.exploit_in_wild ? 'CONFIRMED' : 'NONE'}
          valueClass={cve.exploit_in_wild ? 'text-v-red font-bold' : 'text-v-dim-text'} />
        <Field label="STATUS" value={cve.status} valueClass={STATUS_COLOR[cve.status] || 'text-v-text'} />
      </div>

      {cve.action_taken && (
        <div className="text-[10px] font-mono mb-2">
          <span className="text-v-dim-text">ACTION  </span>
          <span className="text-v-green">{cve.action_taken}</span>
        </div>
      )}
      {cve.deferred_reason && (
        <div className="text-[10px] font-mono mb-2">
          <span className="text-v-dim-text">DEFERRED </span>
          <span className="text-v-amber">{cve.deferred_reason}</span>
        </div>
      )}

      {cve.exploit_sources.length > 0 && (
        <div className="flex flex-wrap gap-3 mt-2 pt-2 border-t border-v-dim">
          <span className="text-[9px] text-v-dim-text font-mono">SOURCES</span>
          {cve.exploit_sources.map((s, i) => (
            <a key={i} href={s.url} target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1 text-[9px] text-v-blue hover:underline font-mono">
              [{i + 1}] {s.title} <ExternalLink size={7} />
            </a>
          ))}
        </div>
      )}
    </div>
  )
}

function Field({ label, value, valueClass }) {
  return (
    <div>
      <div className="text-v-dim-text text-[8px] mb-0.5">{label}</div>
      <div className={`${valueClass}`}>{value}</div>
    </div>
  )
}

export default function CVETable({ findings, selected, onSelect }) {
  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-v-border shrink-0">
        <span className="text-[9px] text-v-dim-text tracking-[0.2em] font-mono">CVE INTELLIGENCE</span>
        <span className="text-[9px] text-v-dim-text font-mono">{findings.length} findings</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-[10px] font-mono border-collapse">
          <thead className="sticky top-0 bg-v-surface z-10">
            <tr className="text-[9px] text-v-dim-text">
              {['CVE ID','SERVICE','CVSS','EXPLOIT','EXPOSED','PRIORITY','STATUS'].map(h => (
                <th key={h} className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map(f => (
              <tr
                key={f.id}
                onClick={() => onSelect(prev => prev?.id === f.id ? null : f)}
                className={`
                  border-b border-v-dim/50 cursor-pointer transition-colors duration-100
                  ${selected?.id === f.id ? 'bg-v-raised' : 'hover:bg-v-raised/60'}
                `}
              >
                <td className="px-3 py-2.5">
                  <span className="text-v-blue font-semibold">{f.id}</span>
                </td>
                <td className="px-3 py-2.5 text-v-text">{f.service_name}</td>
                <td className="px-3 py-2.5">
                  <CvssBar score={f.cvss} />
                </td>
                <td className="px-3 py-2.5">
                  {f.exploit_in_wild
                    ? <span className="text-v-red font-bold">YES</span>
                    : <span className="text-v-dim-text">—</span>}
                </td>
                <td className="px-3 py-2.5">
                  {f.internet_exposed
                    ? <span className="text-v-red font-bold">YES</span>
                    : <span className="text-v-green">NO</span>}
                </td>
                <td className="px-3 py-2.5">
                  <span className={`px-1.5 py-0.5 rounded border text-[8px] font-bold ${PRIORITY_BADGE[f.priority] || ''}`}>
                    {f.priority}
                  </span>
                </td>
                <td className={`px-3 py-2.5 font-semibold ${STATUS_COLOR[f.status] || 'text-v-text'}`}>
                  {f.status}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && <CVEDetail cve={selected} onClose={() => onSelect(null)} />}
    </div>
  )
}
