import { Navigate, NavLink, Outlet } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { can, manages } from '../../utils/scopes'
import { NotAllowed } from '../../components/auth/Guard'

// The company admin area: each section opens with its feature's read scope,
// and its buttons with the edit scope. A company's Admins hold every scope;
// anyone else sees what their groups and extras give — and a group's manager
// sees the groups they run. The API applies the same rules to every request.
export function adminSections(me) {
  return [
    { to: '/admin/users',       label: 'Users',       show: can(me, 'users:read') },
    { to: '/admin/groups',      label: 'Groups',      show: can(me, 'groups:read') },
    { to: '/admin/my-groups',   label: 'Groups you manage', show: manages(me) },
    { to: '/admin/invitations', label: 'Invitations', show: can(me, 'invitations:read') },
    { to: '/admin/sessions',    label: 'Sessions',    show: can(me, 'sessions:read') },
    { to: '/admin/products',    label: 'Products',    show: can(me, 'products:read') },
    { to: '/admin/company',     label: 'Company',     show: can(me, 'company:read') },
    { to: '/admin/api-clients', label: 'API clients', show: can(me, 'api-clients:read') },
  ].filter(s => s.show)
}

export default function AdminLayout() {
  const me = useAuthStore(s => s.me)
  const sections = adminSections(me)
  if (sections.length === 0) return <NotAllowed />

  return (
    <div className="flex flex-col gap-8 md:flex-row">
      <aside className="md:w-48 md:shrink-0">
        <p className="mb-2 px-3 text-xs font-semibold uppercase tracking-wide text-gray-400">{me.company.name}</p>
        <nav className="flex flex-row flex-wrap gap-0.5 text-sm md:flex-col" aria-label="Admin">
          {sections.map(s => (
            <NavLink
              key={s.to} to={s.to}
              className={({ isActive }) =>
                `rounded-md px-3 py-2 transition-colors ${isActive ? 'bg-gray-100 font-medium text-gray-900' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'}`}
            >
              {s.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="min-w-0 flex-1"><Outlet /></div>
    </div>
  )
}

/** /admin itself: the first section this user may see. */
export function AdminHome() {
  const me = useAuthStore(s => s.me)
  const first = adminSections(me)[0]
  return first ? <Navigate to={first.to} replace /> : <NotAllowed />
}
