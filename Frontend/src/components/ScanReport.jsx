import { useMemo, useState } from 'react'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const STATUS_TABS = [
  ['fail', 'Failing'],
  ['pass', 'Passing'],
  ['error', "Couldn't check"],
]
const FIX_TABS = [
  ['console', 'Console'],
  ['cli', 'AWS CLI'],
  ['terraform', 'Terraform'],
]

const when = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function formatTime(value) {
  return value ? when.format(new Date(value)) : ''
}

function scoreTone(score) {
  if (score === null || score === undefined) return ''
  if (score >= 80) return 'good'
  if (score >= 50) return 'fair'
  return 'poor'
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }
  return (
    <button type="button" className="copy" onClick={copy}>
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

function FixTabs({ fix, label }) {
  const tabs = FIX_TABS.filter(([key]) => (key === 'console' ? fix.console.length : fix[key]))
  const [active, setActive] = useState(tabs[0][0])
  return (
    <div className="fix">
      <div className="fix-tabs" role="tablist" aria-label={`How to fix ${label}`}>
        {tabs.map(([key, name]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={active === key}
            className={active === key ? 'fix-tab is-active' : 'fix-tab'}
            onClick={() => setActive(key)}
          >
            {name}
          </button>
        ))}
      </div>
      <div className="fix-body" role="tabpanel">
        {active === 'console' ? (
          <ol className="fix-steps">
            {fix.console.map((step) => <li key={step}>{step}</li>)}
          </ol>
        ) : (
          <div className="code">
            <CopyButton text={fix[active]} />
            <pre><code>{fix[active]}</code></pre>
          </div>
        )}
        {active !== 'console' && /\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b/.test(fix[active]) && (
          <p className="hint">Replace the words in capitals, such as LOG_BUCKET, with your own values.</p>
        )}
      </div>
    </div>
  )
}

function Finding({ finding, title }) {
  return (
    <li className={`finding is-${finding.status}`}>
      <div className="finding-head">
        <span className="finding-resource mono">{finding.resource}</span>
        {finding.region && <span className="finding-region">{finding.region}</span>}
      </div>
      {finding.detail && <p className="finding-detail">{finding.detail}</p>}
      {finding.fix && <FixTabs fix={finding.fix} label={`${title} for ${finding.resource}`} />}
    </li>
  )
}

function CheckRow({ check, demo }) {
  const [open, setOpen] = useState(false)
  const failing = check.findings.filter((f) => f.status === 'fail')
  const others = check.findings.filter((f) => f.status !== 'fail')
  const [showOthers, setShowOthers] = useState(false)
  const panelId = `check-${check.id.replace('.', '-')}`
  let tally = ''
  if (check.status === 'fail') tally = `${failing.length} failing`
  else if (check.status === 'error') tally = "Couldn't check"
  else tally = check.counts.pass === 1 ? 'Passed' : `${check.counts.pass} passed`

  return (
    <li className={`check is-${check.status}`}>
      <button type="button" className="check-head" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen(!open)}>
        {check.status === 'fail' ? (
          <span className={`sev sev-${check.severity}`}>{check.severity}</span>
        ) : (
          <span className={`state state-${check.status}`}>{check.status === 'pass' ? 'Pass' : 'Error'}</span>
        )}
        <span className="check-title">{check.title}</span>
        <span className="check-meta">
          <span className="mono">CIS {check.cis}</span> · {check.service}
        </span>
        <span className="check-tally">{tally}</span>
        <svg className="chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
      </button>
      {open && (
        <div className="check-body" id={panelId}>
          <p className="why">{check.why}</p>
          {demo && check.status === 'fail' && (
            <div className="demo-fix">
              <button type="button" className="button small" onClick={() => demo.onFix(check)} disabled={demo.busy}>
                {demo.fixing === check.id ? 'Fixing and scanning again…' : 'Fix this in the demo'}
              </button>
              <span className="hint">Applies the fix to the simulated account, then scans it again.</span>
            </div>
          )}
          {failing.length > 0 && (
            <ul className="findings">
              {failing.map((f) => <Finding key={`${f.region}-${f.resource}`} finding={f} title={check.title} />)}
            </ul>
          )}
          {others.length > 0 && failing.length > 0 && (
            <button type="button" className="link-button small" onClick={() => setShowOthers(!showOthers)}>
              {showOthers ? 'Hide' : 'Show'} {others.length} other resource{others.length === 1 ? '' : 's'}
            </button>
          )}
          {others.length > 0 && (failing.length === 0 || showOthers) && (
            <ul className="findings quiet">
              {others.map((f) => <Finding key={`${f.region}-${f.resource}`} finding={f} title={check.title} />)}
            </ul>
          )}
        </div>
      )}
    </li>
  )
}

export default function ScanReport({ report, onRescan, busy, error, demo }) {
  const { scan, checks, services } = report
  const summary = scan.summary || {}
  const [status, setStatus] = useState('fail')
  const [severities, setSeverities] = useState([])
  const [service, setService] = useState('')

  const counts = useMemo(() => {
    const result = { fail: 0, pass: 0, error: 0 }
    for (const check of checks) result[check.status] += 1
    return result
  }, [checks])

  const shown = checks.filter(
    (c) =>
      c.status === status &&
      (!severities.length || severities.includes(c.severity)) &&
      (!service || c.service === service),
  )

  function toggleSeverity(severity) {
    setStatus('fail')
    setSeverities((current) =>
      current.includes(severity) ? current.filter((s) => s !== severity) : [...current, severity],
    )
  }

  return (
    <div className="report">
      <section className="card summary" aria-label="Scan summary">
        <div className={`score score-${scoreTone(summary.score)}`}>
          <span className="score-number">{summary.score ?? '–'}</span>
          <span className="score-of">/100</span>
          <span className="score-label">Security score</span>
        </div>
        <div className="summary-facts">
          <p className="summary-account">
            AWS account <span className="mono">{scan.account_id}</span>
            {scan.source === 'demo' && <span className="tag">Simulated</span>}
          </p>
          <p className="muted">
            {scan.regions.length} region{scan.regions.length === 1 ? '' : 's'} · finished {formatTime(scan.finished_at)}
          </p>
          <div className="sev-counts" aria-label="Failing checks by severity">
            {SEVERITIES.map((severity) => (
              <button
                key={severity}
                type="button"
                className={`sev-count${severities.includes(severity) ? ' is-on' : ''}`}
                aria-pressed={severities.includes(severity)}
                onClick={() => toggleSeverity(severity)}
              >
                <b className={`sev-dot sev-${severity}`} aria-hidden="true" />
                <span className="sev-count-number">{summary.failed_by_severity?.[severity] ?? 0}</span>
                <span className="sev-count-label">{severity}</span>
              </button>
            ))}
          </div>
        </div>
        {onRescan && (
          <div className="summary-action">
            <button type="button" className="button primary" onClick={onRescan} disabled={busy}>
              {busy ? 'Scanning…' : 'Run a new scan'}
            </button>
            {demo && (
              <button type="button" className="link-button small" onClick={demo.onReset} disabled={busy}>
                Undo my fixes
              </button>
            )}
            {error && <p className="banner error" role="alert">{error}</p>}
          </div>
        )}
      </section>

      <div className="filters">
        <div className="status-tabs" role="tablist" aria-label="Check results">
          {STATUS_TABS.map(([key, name]) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={status === key}
              className={status === key ? 'status-tab is-active' : 'status-tab'}
              onClick={() => setStatus(key)}
            >
              {name} <span className="status-count">{counts[key]}</span>
            </button>
          ))}
        </div>
        <label className="service-filter">
          <span className="visually-hidden">Service</span>
          <select value={service} onChange={(e) => setService(e.target.value)}>
            <option value="">All services</option>
            {services.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </label>
      </div>

      {shown.length ? (
        <ul className="checks">
          {shown.map((check) => <CheckRow key={check.id} check={check} demo={demo} />)}
        </ul>
      ) : (
        <p className="card empty-filter">
          {status === 'fail' && !severities.length && !service
            ? 'Every check passed. Nothing to fix.'
            : 'No checks match these filters.'}
        </p>
      )}
    </div>
  )
}
