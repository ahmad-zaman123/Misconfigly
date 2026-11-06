import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

export default function Account({ user, onSession }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  if (user.is_demo) {
    return (
      <div className="auth">
        <div className="card auth-card">
          <h1>Account</h1>
          <p className="banner info">Demo accounts have no password and are deleted after two days. <Link to="/register">Create an account</Link> to keep your scans.</p>
        </div>
      </div>
    )
  }

  async function submit(event) {
    event.preventDefault()
    setDone(false)
    if (next !== confirm) {
      setError("The new passwords don't match.")
      return
    }
    setBusy(true)
    setError('')
    try {
      onSession(await api.changePassword(user.has_password ? current : null, next))
      setCurrent('')
      setNext('')
      setConfirm('')
      setDone(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const title = user.has_password ? 'Change password' : 'Set a password'
  return (
    <div className="auth">
      <form className="card auth-card" onSubmit={submit}>
        <h1>Account</h1>
        <p className="account-email">Signed in as <strong>{user.email}</strong></p>
        <h2 className="account-heading">{title}</h2>
        {user.has_password && (
          <>
            <label className="field-label" htmlFor="current-password">Current password</label>
            <input
              id="current-password"
              type="password"
              autoComplete="current-password"
              required
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </>
        )}
        <label className="field-label" htmlFor="new-password">New password</label>
        <input
          id="new-password"
          type="password"
          autoComplete="new-password"
          required
          minLength={8}
          maxLength={200}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          aria-describedby="new-password-hint"
        />
        <label className="field-label" htmlFor="confirm-password">Confirm new password</label>
        <input
          id="confirm-password"
          type="password"
          autoComplete="new-password"
          required
          minLength={8}
          maxLength={200}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <p id="new-password-hint" className="hint">At least 8 characters. You'll stay signed in here, and signed out everywhere else.</p>
        {error && <p className="banner error" role="alert">{error}</p>}
        {done && <p className="banner success" role="status">Password updated.</p>}
        <button type="submit" className="button primary wide" disabled={busy}>
          {busy ? 'One moment...' : title}
        </button>
        <p className="switch"><Link to="/">Back to the dashboard</Link></p>
      </form>
    </div>
  )
}
