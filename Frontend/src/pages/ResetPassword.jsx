import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'

const INVALID = 'This reset link is invalid or has expired.'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(token ? '' : INVALID)
  const [done, setDone] = useState(false)

  async function submit(event) {
    event.preventDefault()
    if (password !== confirm) {
      setError("The passwords don't match.")
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.resetPassword(token, password)
      setDone(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth">
      <form className="card auth-card" onSubmit={submit}>
        <h1>{done ? 'Password changed' : 'Choose a new password'}</h1>
        {done ? (
          <p className="banner success" role="status">You can sign in with it now. Any other devices have been signed out.</p>
        ) : (
          <>
            <label className="field-label" htmlFor="new-password">New password</label>
            <input
              id="new-password"
              type="password"
              autoComplete="new-password"
              required
              minLength={8}
              maxLength={200}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
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
            <p id="new-password-hint" className="hint">At least 8 characters.</p>
            {error && <p className="banner error" role="alert">{error}</p>}
            <button type="submit" className="button primary wide" disabled={busy || !token}>
              {busy ? 'One moment...' : 'Change password'}
            </button>
          </>
        )}
        <p className="switch">
          {done ? <Link to="/login">Go to sign in</Link> : <Link to="/forgot-password">Send a new reset link</Link>}
        </p>
      </form>
    </div>
  )
}
