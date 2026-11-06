import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import ScanReport, { formatTime } from '../components/ScanReport.jsx'

export default function ScanPage() {
  const { id } = useParams()
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setReport(null)
    setError('')
    api.scan(id).then(setReport).catch((err) => setError(err.status === 404 ? 'This scan doesn’t exist, or isn’t yours.' : err.message))
  }, [id])

  return (
    <div className="page">
      <div className="page-head">
        <p><Link to="/">← Dashboard</Link></p>
        <h1>{report ? `Scan of ${formatTime(report.scan.started_at)}` : 'Scan'}</h1>
      </div>
      {error && <p className="banner error" role="alert">{error}</p>}
      {!report && !error && <div className="card loading" aria-busy="true">Loading the scan…</div>}
      {report && report.scan.status === 'failed' && <p className="banner error">{report.scan.error}</p>}
      {report && report.scan.status === 'done' && <ScanReport report={report} />}
    </div>
  )
}
