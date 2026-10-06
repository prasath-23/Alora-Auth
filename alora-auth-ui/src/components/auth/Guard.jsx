import { Link, Outlet } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { can, manages } from '../../utils/scopes'

// Hides a page the signed-in user may not use: one that needs an App Central
// scope they lack, the pages of a group manager, or the Owner console. This
// decides only what to render: the API enforces the same rule on every request,
// whatever the UI shows.
export default function Guard({ scope, owner = false, manager = false, children }) {
  const me = useAuthStore(s => s.me)
  const allowed =
    (!owner || me?.is_owner) &&
    (!manager || manages(me)) &&
    (!scope || can(me, scope))

  if (!allowed) return <NotAllowed />
  return children ?? <Outlet />
}

export function NotAllowed() {
  return (
    <div className="mx-auto max-w-md py-16 text-center" data-testid="not-allowed">
      <h1 className="text-lg font-semibold text-gray-900">You don&apos;t have access to this page</h1>
      <p className="mt-2 text-sm text-gray-500">Ask your administrator if you think you should.</p>
      <Link to="/" className="mt-4 inline-block text-sm text-brand-600 hover:underline">Back to your apps</Link>
    </div>
  )
}
