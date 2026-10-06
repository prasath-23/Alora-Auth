import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { bootstrap } from '../../services/session'
import { FullPageSpinner } from '../ui/Layout'

// Settles the session before any page renders: one refresh of the HttpOnly
// session cookie per page load (shared, so StrictMode's double effect sends
// one request), then GET /api/me. There is no token to read anywhere else —
// the access token only ever lives in memory.
export default function AuthBootstrap() {
  const status = useAuthStore(s => s.status)

  useEffect(() => { bootstrap() }, [])

  if (status === 'bootstrapping') return <FullPageSpinner />
  return <Outlet />
}
