import ReactMarkdown from 'react-markdown'
import { ExternalLink } from 'lucide-react'

export default function ReportViewer({ markdown }) {
  if (!markdown) {
    return (
      <div className="flex flex-col h-full items-center justify-center gap-3 text-v-dim-text">
        <svg width="32" height="32" viewBox="0 0 32 32" fill="none" className="opacity-20">
          <path d="M16 2L4 7v9c0 8.836 5.164 14.836 12 16 6.836-1.164 12-7.164 12-16V7L16 2Z"
            stroke="currentColor" strokeWidth="1.5" fill="none" />
          <path d="M11 16l3.5 3.5L21 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
        <span className="text-[10px] font-mono tracking-wider">REPORT GENERATES AFTER AGENT CYCLE</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full animate-fade-in">
      <div className="flex items-center justify-between px-5 py-2.5 border-b border-v-border shrink-0">
        <span className="text-[9px] text-v-dim-text tracking-[0.2em] font-mono">INCIDENT REPORT</span>
        <span className="text-[9px] text-v-green font-mono flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-v-green" />
          cited.md
        </span>
      </div>
      <div className="flex-1 overflow-y-auto px-6 py-5 report-prose">
        <ReactMarkdown
          components={{
            a: ({ href, children }) => (
              <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
                {children}
                <ExternalLink size={8} className="opacity-50 inline" />
              </a>
            ),
          }}
        >
          {markdown}
        </ReactMarkdown>
      </div>
    </div>
  )
}
