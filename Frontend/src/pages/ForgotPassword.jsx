import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      setSent((await api.forgotPassword(email)).detail)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth">
      <form className="card auth-card" onSubmit={submit}>
        <h1>Reset your password</h1>
        {sent ? (
          <p className="banner success" role="status">
            {sent} It expires in 15 minutes, so check your spam folder if you don&apos;t see it.
          </p>
        ) : (
          <>
            <p className="auth-lead">Enter your email and we&apos;ll send you a link to choose a new password.</p>
            <label className="field-label" htmlFor="email">Email</label>
            <input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
            {error && <p className="banner error" role="alert">{error}</p>}
            <button type="submit" className="button primary wide" disabled={busy}>
              {busy ? 'One moment...' : 'Send reset link'}
            </button>
          </>
        )}
        <p className="switch"><Link to="/login">Back to sign in</Link></p>
      </form>
    </div>
  )
}
