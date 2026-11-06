import { useCallback, useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { api, getToken, setToken, whenSessionExpires } from './api.js'
import Header from './components/Header.jsx'
import Account from './pages/Account.jsx'
import Auth from './pages/Auth.jsx'
import Dashboard from './pages/Dashboard.jsx'
import ForgotPassword from './pages/ForgotPassword.jsx'
import Landing from './pages/Landing.jsx'
import ResetPassword from './pages/ResetPassword.jsx'

// Where to go after signing in, from ?next=. Only a path on this site, so the link can't send anyone elsewhere.
function nextPath(search) {
  const next = new URLSearchParams(search).get('next') || ''
  return /^\/(?![/\\])/.test(next) ? next : '/'
}

export default function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const [user, setUser] = useState(null)
  const [checking, setChecking] = useState(Boolean(getToken()))

  const signOut = useCallback(() => {
    setToken(null)
    setUser(null)
    navigate('/')
  }, [navigate])

  useEffect(() => {
    whenSessionExpires(signOut)
    if (!getToken()) return
    api
      .me()
      .then(setUser)
      .catch(() => setToken(null))
      .finally(() => setChecking(false))
  }, [signOut])

  function applySession(session) {
    setToken(session.token)
    setUser(session.user)
  }

  function signedIn(session) {
    applySession(session)
    navigate(nextPath(location.search))
  }

  if (checking) return <div className="boot" aria-busy="true" />

  const signedInOnly = (page) => (user ? page : <Navigate to="/login" replace />)
  const signedOutOnly = (page) => (user ? <Navigate to={nextPath(location.search)} replace /> : page)

  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <Header user={user} onSignOut={signOut} />
      <main id="main">
        <Routes>
          <Route path="/" element={user ? <Dashboard user={user} /> : <Landing onDemo={signedIn} />} />
          <Route path="/login" element={signedOutOnly(<Auth mode="login" onSignedIn={signedIn} />)} />
          <Route path="/register" element={signedOutOnly(<Auth mode="register" onSignedIn={signedIn} />)} />
          <Route path="/forgot-password" element={user ? <Navigate to="/account" replace /> : <ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/account" element={signedInOnly(<Account user={user} onSession={applySession} />)} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  )
}
