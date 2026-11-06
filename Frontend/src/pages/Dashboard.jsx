import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import ScanReport, { formatTime } from '../components/ScanReport.jsx'

export default function Dashboard({ user }) {
  const [report, setReport] = useState(null)
  const [latest, setLatest] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [fixing, setFixing] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(async () => {
    const { scans } = await api.scans()
    setLatest(scans[0] || null)
    const done = scans.find((s) => s.status === 'done')
    setReport(done ? await api.scan(done.id) : null)
  }, [])

  useEffect(() => {
    load()
      .catch((err) => setLoadError(err.message))
      .finally(() => setLoading(false))
  }, [load])

  // Runs `before` (such as applying a demo fix), scans again and returns the new scan, or null if it failed.
  async function runScan(before) {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      if (before) await before()
      const scan = await api.startScan()
      await load()
      return scan
    } catch (err) {
      setError(err.message)
      // A failed scan is saved too, so show it.
      await load().catch(() => {})
      return null
    } finally {
      setBusy(false)
      setFixing('')
    }
  }

  async function fixInDemo(check) {
    setFixing(check.id)
    const before = report?.scan.summary?.score
    const scan = await runScan(() => api.demoFix([check.id]))
    if (scan) setNotice(`Fixed: ${check.title}. Score ${before} → ${scan.summary.score}.`)
  }

  async function resetDemo() {
    const scan = await runScan(() => api.resetDemo())
    if (scan) setNotice(`Your fixes were undone. Score ${scan.summary.score}.`)
  }

  const demo = user.is_demo && report?.scan.source === 'demo' ? { onFix: fixInDemo, onReset: resetDemo, busy, fixing } : null

  return (
    <div className="page">
      <div className="page-head">
        <h1>Dashboard</h1>
        <p className="muted">
          {user.is_demo ? 'This is your private demo account. It is deleted after two days.' : `Signed in as ${user.email}.`}
        </p>
      </div>

      {loading && <div className="card loading" aria-busy="true">Loading your scans…</div>}
      {loadError && <p className="banner error" role="alert">{loadError}</p>}

      {!loading && !loadError && latest?.status === 'failed' && report && (
        <p className="banner error" role="status">
          The scan started {formatTime(latest.started_at)} didn&apos;t finish: {latest.error} These are the results from
          the last scan that did.
        </p>
      )}

      {demo && !notice && (
        <p className="banner info">
          This is a simulated AWS account with the kind of problems real accounts have. Open a failing check and choose
          Fix this in the demo to see the score change.
        </p>
      )}
      {notice && <p className="banner success" role="status">{notice}</p>}

      {!loading && !loadError && report && (
        <ScanReport report={report} onRescan={() => runScan()} busy={busy} error={error} demo={demo} />
      )}

      {!loading && !loadError && !report && (
        <section className="card empty">
          <h2>No scans yet</h2>
          <p>
            {user.is_demo && 'Your demo comes with its own simulated AWS account. '}A scan runs 37 read-only checks from the CIS AWS Foundations Benchmark and lists every misconfiguration it
            finds, with the steps to fix each one.
          </p>
          <button type="button" className="button primary" onClick={() => runScan()} disabled={busy}>
            {busy ? 'Scanning… this can take a minute' : 'Run your first scan'}
          </button>
          {error && <p className="banner error" role="alert">{error}</p>}
          {user.is_demo && (
            <p className="muted">
              Want to keep your work? <Link to="/register">Create an account</Link>.
            </p>
          )}
        </section>
      )}
    </div>
  )
}
