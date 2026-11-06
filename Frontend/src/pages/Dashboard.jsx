import { Link } from 'react-router-dom'

// The first version of the signed-in page. Scans and findings fill it in the next parts of the build.
export default function Dashboard({ user }) {
  return (
    <div className="page">
      <div className="page-head">
        <h1>Dashboard</h1>
        <p className="muted">
          {user.is_demo ? 'This is your private demo account. It is deleted after two days.' : `Signed in as ${user.email}.`}
        </p>
      </div>
      <section className="card empty">
        <h2>No scans yet</h2>
        <p>
          Scanning AWS accounts is being added next. When it&apos;s ready, you&apos;ll connect an account here with a
          read-only role and see every misconfiguration it finds.
        </p>
        {user.is_demo && (
          <p className="muted">
            Want to keep your work? <Link to="/register">Create an account</Link>.
          </p>
        )}
      </section>
    </div>
  )
}
