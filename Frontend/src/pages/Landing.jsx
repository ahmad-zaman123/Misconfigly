import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

const STEPS = [
  ['Connect', 'Deploy a one-click CloudFormation template. It creates a read-only role for Misconfigly, so no access keys are ever shared or stored.'],
  ['Scan', 'About 30 checks from the CIS AWS Foundations Benchmark cover IAM, S3, EC2, RDS, CloudTrail, GuardDuty and more.'],
  ['Fix', 'Each finding says why it matters and how to fix it, with console steps, an AWS CLI command and Terraform.'],
]

// A made-up example, labelled as such on the page.
const EXAMPLE = [
  ['critical', 'S3 bucket is public', 'acme-invoices-prod'],
  ['high', 'SSH open to the internet', 'sg-0a41f2 · web-servers'],
  ['high', 'Root account has no MFA', 'account root'],
  ['medium', 'Access key older than 90 days', 'ci-deploy'],
]

export default function Landing({ onDemo }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function startDemo() {
    setBusy(true)
    setError('')
    try {
      onDemo(await api.demo())
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  return (
    <div className="landing">
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">AWS security audit</p>
          <h1>Find the AWS misconfigurations attackers look for first.</h1>
          <p className="lede">
            Misconfigly checks your AWS account for public buckets, missing MFA, open ports, disabled logging and more.
            It explains each problem and shows exactly how to fix it.
          </p>
          <div className="actions">
            <button type="button" className="button primary" onClick={startDemo} disabled={busy}>
              {busy ? 'Setting up your demo…' : 'Try the live demo'}
            </button>
            <Link to="/register" className="button">Create an account</Link>
          </div>
          {error && <p className="banner error" role="alert">{error}</p>}
          <p className="fineprint">The demo opens a private account. No sign-up or AWS account needed.</p>
        </div>

        <figure className="example" aria-label="Example scan results">
          <div className="example-head">
            <span>Example scan</span>
            <span className="example-score"><b>58</b>/100</span>
          </div>
          <ul className="example-list">
            {EXAMPLE.map(([severity, title, resource]) => (
              <li key={title}>
                <span className={`sev sev-${severity}`}>{severity}</span>
                <span className="example-title">{title}</span>
                <span className="example-resource mono">{resource}</span>
              </li>
            ))}
          </ul>
          <figcaption className="example-foot">Made-up account, for illustration.</figcaption>
        </figure>
      </section>

      <section className="steps" aria-label="How it works">
        {STEPS.map(([title, text], index) => (
          <div key={title} className="step">
            <span className="step-number">{index + 1}</span>
            <h2>{title}</h2>
            <p>{text}</p>
          </div>
        ))}
      </section>

      <footer className="footer">
        Built with FastAPI, boto3 and React by Ahmad Zaman.{' '}
        <a href="https://github.com/ahmad-zaman123/Misconfigly" target="_blank" rel="noreferrer">Source on GitHub</a>
      </footer>
    </div>
  )
}
