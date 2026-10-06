import { Navigate, Outlet, useLocation } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { query } from '../../utils/format'

// Pages behind sign-in. Without a session the browser goes to the login page,
// which comes back here afterwards — unless the user signed out on purpose, in
// which case there is nothing to come back to.
export default function RequireAuth() {
  const status    = useAuthStore(s => s.status)
  const signedOut = useAuthStore(s => s.signedOut)
  const location  = useLocation()

  if (status !== 'authenticated') {
    const here = location.pathname + location.search
    const to = signedOut || here === '/' ? '/login' : `/login${query({ return_to: here })}`
    return <Navigate to={to} replace />
  }
  return <Outlet />
}
