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
  const s     = Number(score) || 0
  const pct   = (s / 10) * 100
  const color = s >= 9 ? '#f43f5e' : s >= 7 ? '#fbbf24' : '#34d399'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-10 h-1 rounded-full bg-v-dim overflow-hidden shrink-0">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ color }} className="tabular-nums text-[10px] font-semibold">{s.toFixed(1)}</span>
    </div>
  )
}

function CVEDetail({ cve, onClose }) {
  const cvss = Number(cve.cvss ?? cve.cvss_score) || 0

  // exploit_sources can be [{title,url}] (dummy) or ['url','url'] (API)
  const sources = (cve.exploit_sources || []).map(s =>
    typeof s === 'string' ? { url: s, title: s.replace(/^https?:\/\//, '').split('/').slice(0, 3).join('/') } : s
  )

  return (
    <div className="border-t border-v-border bg-v-raised px-4 py-3 animate-slide-up shrink-0">
      <div className="flex items-start justify-between mb-2">
        <span className="text-v-blue text-[11px] font-semibold break-all">{cve.id || cve.cve_id}</span>
        <button onClick={onClose} className="text-v-dim-text hover:text-v-bright text-xs ml-4 transition-colors shrink-0">✕</button>
      </div>

      {cve.description && (
        <p className="text-v-text text-[10px] mb-3 leading-relaxed">{cve.description}</p>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3 text-[10px] font-mono">
        <Field label="CVSS"    value={cvss.toFixed(1)}                        valueClass="text-v-red font-bold" />
        <Field label="EXPOSED" value={cve.internet_exposed ? 'YES' : 'NO'}    valueClass={cve.internet_exposed ? 'text-v-red font-bold' : 'text-v-green'} />
        <Field label="EXPLOIT" value={cve.exploit_in_wild ? 'CONFIRMED' : 'NONE'} valueClass={cve.exploit_in_wild ? 'text-v-red font-bold' : 'text-v-dim-text'} />
        <Field label="STATUS"  value={cve.status || '—'}                      valueClass={STATUS_COLOR[cve.status] || 'text-v-text'} />
      </div>

      {cve.action_taken && (
        <div className="text-[10px] font-mono mb-2 flex gap-2">
          <span className="text-v-dim-text shrink-0">ACTION</span>
          <span className="text-v-green">{cve.action_taken}</span>
        </div>
      )}
      {cve.deferred_reason && (
        <div className="text-[10px] font-mono mb-2 flex gap-2">
          <span className="text-v-dim-text shrink-0">DEFERRED</span>
          <span className="text-v-amber">{cve.deferred_reason}</span>
        </div>
      )}

      {sources.length > 0 && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 pt-2 border-t border-v-dim">
          <span className="text-[9px] text-v-dim-text font-mono w-full mb-0.5">SOURCES</span>
          {sources.map((s, i) => (
            <a key={i} href={s.url} target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1 text-[9px] text-v-blue hover:underline font-mono truncate max-w-full">
              [{i + 1}] {s.title} <ExternalLink size={7} className="shrink-0" />
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
      <div className={`text-[10px] ${valueClass}`}>{value}</div>
    </div>
  )
}

export default function CVETable({ findings, selected, onSelect }) {
  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-v-border shrink-0">
        <span className="text-[9px] text-v-dim-text tracking-[0.2em] font-mono">CVE INTELLIGENCE</span>
        <span className="text-[9px] text-v-dim-text font-mono">{findings.length} findings</span>
      </div>

      {/* Scrollable table wrapper — horizontal + vertical */}
      <div className="flex-1 overflow-auto">
        <table className="min-w-full text-[10px] font-mono border-collapse">
          <thead className="sticky top-0 bg-v-surface z-10">
            <tr className="text-[9px] text-v-dim-text">
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap">CVE ID</th>
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap hidden sm:table-cell">SERVICE</th>
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap">CVSS</th>
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap hidden md:table-cell">EXPLOIT</th>
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap">EXPOSED</th>
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap hidden sm:table-cell">PRIORITY</th>
              <th className="text-left px-3 py-2 border-b border-v-dim font-normal tracking-wider whitespace-nowrap">STATUS</th>
            </tr>
          </thead>
          <tbody>
            {findings.map(f => {
              const fid = f.id || f.cve_id
              return (
                <tr
                  key={fid}
                  onClick={() => onSelect(prev => prev?.id === fid ? null : { ...f, id: fid })}
                  className={`
                    border-b border-v-dim/50 cursor-pointer transition-colors duration-100
                    ${selected?.id === fid ? 'bg-v-raised' : 'hover:bg-v-raised/60'}
                  `}
                >
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <span className="text-v-blue font-semibold">{fid}</span>
                  </td>
                  <td className="px-3 py-2.5 text-v-text hidden sm:table-cell max-w-[120px]">
                    <span className="truncate block">{f.service_name || f.host_name}</span>
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <CvssBar score={f.cvss ?? f.cvss_score} />
                  </td>
                  <td className="px-3 py-2.5 hidden md:table-cell whitespace-nowrap">
                    {f.exploit_in_wild
                      ? <span className="text-v-red font-bold">YES</span>
                      : <span className="text-v-dim-text">—</span>}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {f.internet_exposed
                      ? <span className="text-v-red font-bold">YES</span>
                      : <span className="text-v-green">NO</span>}
                  </td>
                  <td className="px-3 py-2.5 hidden sm:table-cell whitespace-nowrap">
                    <span className={`px-1.5 py-0.5 rounded border text-[8px] font-bold ${PRIORITY_BADGE[f.priority] || 'text-v-dim-text border-v-dim'}`}>
                      {f.priority || '—'}
                    </span>
                  </td>
                  <td className={`px-3 py-2.5 font-semibold whitespace-nowrap ${STATUS_COLOR[f.status] || 'text-v-text'}`}>
                    {f.status || '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {selected && <CVEDetail cve={selected} onClose={() => onSelect(null)} />}
    </div>
  )
}
