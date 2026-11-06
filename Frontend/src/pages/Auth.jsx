import { useCallback, useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { api } from '../api.js'
import GoogleButton from '../components/GoogleButton.jsx'

export default function Auth({ mode, onSignedIn }) {
  const registering = mode === 'register'
  const { search } = useLocation()
  const [email, setEmail] = useState(() => new URLSearchParams(search).get('email') || '')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [canReset, setCanReset] = useState(false)

  useEffect(() => {
    if (registering) return
    // The link only shows when the server can send email.
    api
      .authOptions()
      .then((options) => setCanReset(options.password_reset))
      .catch(() => {})
  }, [registering])

  // Kept stable so the Google button isn't set up again on every render.
  const onGoogleCredential = useCallback(
    async (credential) => {
      setBusy(true)
      setError('')
      try {
        onSignedIn(await api.google(credential))
      } catch (err) {
        setError(err.message)
        setBusy(false)
      }
    },
    [onSignedIn],
  )

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      onSignedIn(registering ? await api.register(email, password) : await api.login(email, password))
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  return (
    <div className="auth">
      <form className="card auth-card" onSubmit={submit} noValidate={false}>
        <h1>{registering ? 'Create an account' : 'Sign in'}</h1>
        <GoogleButton onCredential={onGoogleCredential} onError={setError} busy={busy} />
        <label className="field-label" htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <label className="field-label" htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete={registering ? 'new-password' : 'current-password'}
          required
          minLength={registering ? 8 : 1}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-describedby={registering ? 'password-hint' : undefined}
        />
        {registering && <p id="password-hint" className="hint">At least 8 characters.</p>}
        {!registering && canReset && (
          <Link to="/forgot-password" className="forgot">Forgot password?</Link>
        )}
        {error && <p className="banner error" role="alert">{error}</p>}
        <button type="submit" className="button primary wide" disabled={busy}>
          {busy ? 'One moment...' : registering ? 'Create account' : 'Sign in'}
        </button>
        <p className="switch">
          {registering ? (
            <>Already have an account? <Link to={`/login${search}`}>Sign in</Link></>
          ) : (
            <>New here? <Link to={`/register${search}`}>Create an account</Link> or try the demo from the <Link to="/">home page</Link>.</>
          )}
        </p>
      </form>
    </div>
  )
}
