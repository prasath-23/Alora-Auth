import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { api, setOnTokenRefreshed } from '../../services/apiClient'
import { getMyFeatures } from '../../services/adminService'
import { parseJwtPayload } from '../../utils/jwt'

// Route-level wrapper that attempts a silent refresh on mount.
// Renders <Outlet /> (child routes) once the bootstrap attempt settles.
// ProtectedRoute reads the resulting status to redirect or allow.
export default function AuthBootstrap() {
  const { status, setAuthenticated, setUnauthenticated } = useAuthStore()

  // Register the post-refresh callback so apiClient can update Zustand
  // whenever it silently refreshes a token mid-session (expired access token).
  useEffect(() => {
    setOnTokenRefreshed((newToken) => {
      const user = parseJwtPayload(newToken)
      // Keep existing features — they don't change on a plain token refresh.
      const { features } = useAuthStore.getState()
      useAuthStore.getState().setAuthenticated(newToken, user, [...features])
    })
    return () => setOnTokenRefreshed(null)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (status !== 'bootstrapping') return

    let aborted = false

    async function bootstrap() {
      try {
        // Fast path: alora_at cookie is JS-readable and already valid — no round-trip needed.
        // This avoids the StrictMode double-invoke problem on subsequent visits.
        const cookieToken = document.cookie.split(';')
          .map(c => c.trim())
          .find(c => c.startsWith('alora_at='))
          ?.slice('alora_at='.length) ?? null
        const cookiePayload = cookieToken ? parseJwtPayload(cookieToken) : null
        if (cookiePayload && cookiePayload.exp * 1000 > Date.now() + 30_000) {
          try {
            const [user, { features }] = await Promise.all([
              Promise.resolve(cookiePayload),
              getMyFeatures(cookieToken),
            ])
            if (!aborted) setAuthenticated(cookieToken, user, features)
            return
          } catch {
            // Token is valid but getMyFeatures failed (stale pv, role change, etc.)
            // Fall through to the refresh path to get a fresh token.
          }
        }

        // Slow path: no valid access token cookie — call refresh to rotate.
        let res = await api.post('/auth/refresh', null)
        if (aborted) return
        // 409 = StrictMode double-invoke: a concurrent call already rotated the
        // token. The browser cookie is now the new token — one retry suffices.
        if (res.status === 409) {
          res = await api.post('/auth/refresh', null)
          if (aborted) return
        }
        if (!res.ok) { setUnauthenticated(); return }

        const { access_token } = await res.json()
        const [user, { features }] = await Promise.all([
          Promise.resolve(parseJwtPayload(access_token)),
          getMyFeatures(access_token),
        ])
        if (!aborted) setAuthenticated(access_token, user, features)
      } catch {
        if (!aborted) setUnauthenticated()
      }
    }

    bootstrap()
    return () => { aborted = true }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return <Outlet />
}
