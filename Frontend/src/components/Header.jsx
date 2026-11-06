import { Link } from 'react-router-dom'
import ThemeToggle from './ThemeToggle.jsx'

export function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" />
      <path className="mark-shield" d="M16 6.5 24.5 10v6.2c0 5-3.6 8.6-8.5 9.8-4.9-1.2-8.5-4.8-8.5-9.8V10Z" />
      <path className="mark-tick" d="m12.4 16.2 2.6 2.6 4.8-5" />
    </svg>
  )
}

export default function Header({ user, onSignOut }) {
  return (
    <header className="topbar">
      <Link to="/" className="brand" aria-label="Misconfigly home">
        <Mark />
        <span className="brand-name">Misconfigly</span>
      </Link>
      <nav className="topbar-right" aria-label="Account">
        {user ? (
          <>
            <span className="who">{user.is_demo ? 'Demo account' : user.email}</span>
            {!user.is_demo && <Link to="/connect" className="link-button">AWS</Link>}
            {!user.is_demo && <Link to="/account" className="link-button">Account</Link>}
            <button type="button" className="link-button" onClick={onSignOut}>Sign out</button>
          </>
        ) : (
          <Link to="/login" className="link-button">Sign in</Link>
        )}
        <ThemeToggle />
      </nav>
    </header>
  )
}
