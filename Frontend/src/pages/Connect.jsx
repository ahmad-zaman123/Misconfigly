import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { CopyButton, formatTime } from '../components/ScanReport.jsx'

const STACK = 'Misconfigly'
const CLOUDSHELL = 'https://console.aws.amazon.com/cloudshell/home'

function Code({ text }) {
  return (
    <div className="code">
      <CopyButton text={text} />
      <pre><code>{text}</code></pre>
    </div>
  )
}

function Connected({ connection, onDisconnect, busy }) {
  return (
    <section className="card connect-step">
      <h2>Connected</h2>
      <p>
        Misconfigly scans AWS account <span className="mono">{connection.account_id}</span> through the role{' '}
        <span className="mono break">{connection.role_arn}</span>. Connected {formatTime(connection.connected_at)}.
      </p>
      <div className="connect-actions">
        <Link to="/" className="button primary">Go to the dashboard</Link>
        <button type="button" className="button" onClick={onDisconnect} disabled={busy}>
          {busy ? 'Disconnecting…' : 'Disconnect'}
        </button>
      </div>
      <p className="hint">
        Disconnecting stops Misconfigly using the role. To remove the role itself, delete the {STACK} stack in
        CloudFormation. Your past scans are kept.
      </p>
    </section>
  )
}

export default function Connect({ user }) {
  const [connection, setConnection] = useState(null)
  const [loadError, setLoadError] = useState('')
  const [roleArn, setRoleArn] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (user.is_demo) return
    api.connection().then(setConnection).catch((err) => setLoadError(err.message))
  }, [user.is_demo])

  if (user.is_demo) {
    return (
      <div className="page narrow">
        <div className="page-head"><h1>Connect AWS</h1></div>
        <p className="banner info">
          The demo scans a simulated account. <Link to="/register">Create an account</Link> to connect your own AWS
          account.
        </p>
      </div>
    )
  }

  async function connect(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      setConnection(await api.connect(roleArn.trim()))
      setRoleArn('')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function disconnect() {
    setBusy(true)
    setError('')
    try {
      setConnection(await api.disconnect())
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const templateUrl = connection ? `${window.location.origin}${connection.template_path}` : ''
  const deploy = connection
    ? [
        `curl -sO ${templateUrl}`,
        `aws cloudformation deploy --stack-name ${STACK} \\`,
        `  --template-file misconfigly-audit-role.yaml --capabilities CAPABILITY_NAMED_IAM \\`,
        `  --parameter-overrides ExternalId=${connection.external_id} \\`,
        `  MisconfiglyRoleArn=${connection.scanner_role_arn}`,
        `aws cloudformation describe-stacks --stack-name ${STACK} \\`,
        `  --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" --output text`,
      ].join('\n')
    : ''

  return (
    <div className="page narrow">
      <div className="page-head">
        <h1>Connect AWS</h1>
        <p className="muted">
          Misconfigly reads your settings through a role in your account. It never gets access keys and can&apos;t
          change anything.
        </p>
      </div>

      {!connection && !loadError && <div className="card loading" aria-busy="true">Loading…</div>}
      {loadError && <p className="banner error" role="alert">{loadError}</p>}

      {connection && !connection.available && (
        <p className="banner info">Connecting AWS accounts isn&apos;t set up on this server yet. The demo still works.</p>
      )}

      {connection?.available && connection.connected && (
        <Connected connection={connection} onDisconnect={disconnect} busy={busy} />
      )}

      {connection?.available && !connection.connected && (
        <ol className="connect-steps">
          <li className="card connect-step">
            <h2>Create the role</h2>
            <p>
              Open <a href={CLOUDSHELL} target="_blank" rel="noreferrer">AWS CloudShell</a>, signed in to the account
              you want to scan as someone who can create IAM roles, and paste these commands. They create a stack named{' '}
              {STACK} with one role, MisconfiglyAudit, and print its ARN when it is done.
            </p>
            <Code text={deploy} />
            <p className="hint">
              Prefer the console? <a href={connection.template_path} download>Download the template</a> and create a stack
              from it in CloudFormation with the values below.
            </p>
            <dl className="connect-values">
              <dt>ExternalId</dt>
              <dd className="mono">{connection.external_id}</dd>
              <dt>MisconfiglyRoleArn</dt>
              <dd className="mono">{connection.scanner_role_arn}</dd>
            </dl>
          </li>

          <li className="card connect-step">
            <h2>Paste the role ARN</h2>
            <form onSubmit={connect}>
              <label className="field-label" htmlFor="role-arn">Role ARN</label>
              <input
                id="role-arn"
                className="mono"
                required
                spellCheck={false}
                autoComplete="off"
                placeholder="arn:aws:iam::123456789012:role/MisconfiglyAudit"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
              />
              <p className="hint">Misconfigly checks that it can use the role before saving it.</p>
              {error && <p className="banner error" role="alert">{error}</p>}
              <button type="submit" className="button primary" disabled={busy}>
                {busy ? 'Checking the role…' : 'Connect'}
              </button>
            </form>
          </li>
        </ol>
      )}

      {connection?.available && (
        <section className="connect-about">
          <h2>What the role allows</h2>
          <ul>
            <li>
              It has <span className="mono">SecurityAudit</span>, AWS&apos;s own read-only policy for security tools. It
              can read settings, not the data in your buckets or databases.
            </li>
            <li>Only Misconfigly can use it, and only with the ExternalId above, which belongs to your account here.</li>
            <li>Each scan signs in for at most an hour. Nothing that lets Misconfigly into your account is stored.</li>
            <li>Delete the {STACK} stack whenever you want, and access ends at once.</li>
          </ul>
        </section>
      )}
      {error && connection?.connected && <p className="banner error" role="alert">{error}</p>}
    </div>
  )
}
