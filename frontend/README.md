# /frontend — React Dashboard (Vercel)

This is the judge-facing interface. It fetches live data from ClickHouse and the Senso.ai-generated report to display a real-time security posture dashboard.

## Tech Stack

- **React** (Vite)
- **Tailwind CSS** — styling
- **Recharts** — CVE severity charts
- **Deployed on Vercel**

## Responsibility

- Display the triage table (CRITICAL in red, LOW in grey)
- Show the CVE detail panel (CVSS score, exploit intel, sources from Nimble)
- Render the Senso.ai-generated `cited.md` report
- Show remediation log (what was patched, when, outcome)
- Auto-refresh every 30 seconds to show live pipeline updates

## Pages / Components to Build

| Component | Description |
|-----------|-------------|
| `Dashboard.jsx` | Main page — triage summary cards + CVE table |
| `CVETable.jsx` | Sortable table of all CVEs with priority badges |
| `CVEDetailPanel.jsx` | Slide-out panel showing full CVE context + Nimble sources |
| `RemediationLog.jsx` | Timeline of actions taken by the agent |
| `ReportViewer.jsx` | Renders the Senso.ai `cited.md` as formatted HTML |
| `StatusBadge.jsx` | CRITICAL / LOW / PATCHED / DEFERRED badge component |

## API Endpoints Expected

```
GET /api/triage      — returns triage_results from ClickHouse
GET /api/remediation — returns remediation_log from ClickHouse
GET /api/report      — returns the Senso.ai cited.md content
```

## Setup

```bash
cd frontend
npm install
npm run dev         # local dev on localhost:5173
```

## Vercel Deployment

```bash
npm install -g vercel
vercel --prod
```

Set these environment variables in Vercel dashboard:
```
VITE_API_BASE_URL=https://your-backend-url.com
```
