import { Navigate, Outlet } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import Spinner    from '../ui/Spinner'
import AdminLogin from '../../pages/admin/AdminLogin'

export default function ProtectedRoute({ featureKey }) {
  const status    = useAuthStore(s => s.status)
  const features  = useAuthStore(s => s.features)
  const loggedOut = useAuthStore(s => s.loggedOut)

  if (status === 'bootstrapping') {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    )
  }

  if (status === 'unauthenticated') {
    // Feature-gated sub-routes: redirect to dashboard (which will show login if still unauth).
    if (featureKey) return <Navigate to="/admin" replace />
    // Top-level gate: render the login panel inline with optional "signed out" notification.
    return <AdminLogin loggedOut={loggedOut} />
  }

  if (featureKey && !features.has(featureKey)) {
    return <Navigate to="/admin" replace />
  }

  return <Outlet />
}
