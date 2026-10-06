import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { signOut } from '../../services/session'
import { seesAdmin } from '../../utils/scopes'

function TopLink({ to, end, children }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `rounded-md px-3 py-1.5 transition-colors ${isActive ? 'bg-gray-100 font-medium text-gray-900' : 'text-gray-600 hover:text-gray-900'}`}
    >
      {children}
    </NavLink>
  )
}

export default function AppShell() {
  const me = useAuthStore(s => s.me)
  const navigate = useNavigate()

  async function handleSignOut() {
    await signOut()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-gray-200 bg-white">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-4">
          <div className="flex items-center gap-6">
            <Link to="/" className="text-sm font-semibold tracking-wide text-brand-600">ALORA</Link>
            <nav className="flex gap-1 text-sm" aria-label="Main">
              <TopLink to="/" end>Apps</TopLink>
              {seesAdmin(me) && <TopLink to="/admin">Admin</TopLink>}
              {me.is_owner && <TopLink to="/owner">Owner</TopLink>}
            </nav>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <div className="hidden text-right leading-tight sm:block">
              <div className="text-gray-900" data-testid="me-email">{me.email}</div>
              <div className="text-xs text-gray-400" data-testid="me-company">{me.company.name}</div>
            </div>
            <TopLink to="/profile">Profile</TopLink>
            <button type="button" onClick={handleSignOut} className="rounded-md px-3 py-1.5 text-gray-600 hover:bg-gray-100 hover:text-gray-900">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
        <Outlet />
      </main>
    </div>
  )
}
