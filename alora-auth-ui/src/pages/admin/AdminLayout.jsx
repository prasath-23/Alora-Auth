import { NavLink, Outlet } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES } from '../../utils/features'
import { api } from '../../services/apiClient'

export default function AdminLayout() {
  const { user, accessToken, setUnauthenticated } = useAuthStore()

  async function handleLogout() {
    await api.post('/auth/logout', null, accessToken).catch(() => {})
    setUnauthenticated(true)
    // ProtectedRoute re-renders inline with the "signed out" notification — no redirect needed.
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <aside className="w-56 shrink-0 border-r border-gray-200 bg-white flex flex-col">
        <div className="px-4 py-5 border-b border-gray-200">
          <p className="text-sm font-semibold text-gray-900">Alora Auth</p>
          <p className="text-xs text-gray-400 mt-0.5 truncate">{user?.email}</p>
        </div>

        <nav className="flex-1 px-2 py-4 space-y-0.5 text-sm overflow-y-auto">
          <NavItem to="/admin" label="Dashboard" end />
          <NavItem to="/admin/invitations" label="Invitations" />
          <ConditionalNavItem to="/admin/users"    label="Users"    featureKey={ADMIN_FEATURES.USERS_VIEW} />
          <ConditionalNavItem to="/admin/groups"   label="Groups"   featureKey={ADMIN_FEATURES.GROUPS_VIEW} />
          <ConditionalNavItem to="/admin/sessions" label="Sessions" featureKey={ADMIN_FEATURES.SESSIONS_VIEW} />
          <ConditionalNavItem to="/admin/products" label="Products" featureKey={ADMIN_FEATURES.PRODUCTS_VIEW} />
          <ConditionalNavItem to="/admin/client"   label="Client"   featureKey={ADMIN_FEATURES.CLIENT_VIEW} />
        </nav>

        <div className="px-2 py-3 border-t border-gray-200 space-y-0.5">
          <NavItem to="/admin/profile" label="Profile" />
          <button
            onClick={handleLogout}
            className="w-full text-left rounded-md px-3 py-2 text-sm text-gray-500 hover:bg-gray-50 hover:text-gray-900 transition-colors"
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}

function NavItem({ to, label, end = false }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `block rounded-md px-3 py-2 transition-colors ${
          isActive
            ? 'bg-gray-100 text-gray-900 font-medium'
            : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
        }`
      }
    >
      {label}
    </NavLink>
  )
}

function ConditionalNavItem({ to, label, featureKey }) {
  const has = useFeature(featureKey)
  if (!has) return null
  return <NavItem to={to} label={label} />
}
