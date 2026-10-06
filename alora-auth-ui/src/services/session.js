import { api, onSessionChange, onTokenStale, refreshSession, setAccessToken } from './apiClient'
import useAuthStore from '../store/authStore'

// A refresh that fails while the user is working means the session ended
// elsewhere: signed out in another tab, revoked by an administrator, or the
// login policy no longer allows how they signed in.
onSessionChange(token => {
  const { status, setUnauthenticated } = useAuthStore.getState()
  if (token === null && status === 'authenticated') {
    setUnauthenticated({ notice: 'Your session has ended. Sign in again to continue.' })
  }
})

// Someone changed this person's access (or they changed it themselves): the
// API already enforces the new access; a new token and `me` make the page show
// it too.
onTokenStale(async () => {
  if (useAuthStore.getState().status !== 'authenticated') return
  const token = await refreshSession()
  if (token) await loadMe()
})

let booting = null

/** Settles the session once per page load: refresh the cookie, then load `me`. */
export function bootstrap() {
  if (!booting) {
    booting = (async () => {
      const token = await refreshSession()
      if (!token) {
        useAuthStore.getState().setUnauthenticated()
        return
      }
      await loadMe()
    })().catch(err => useAuthStore.getState().setUnauthenticated({ notice: err?.message ?? null }))
  }
  return booting
}

/** Adopts the access token a sign-in step returned. */
export async function establish(accessToken) {
  setAccessToken(accessToken)
  await loadMe()
}

export async function loadMe() {
  const me = await api.get('/api/me')
  useAuthStore.getState().setAuthenticated(me)
  return me
}

/**
 * Ends the App Central session and, with it, every product login opened under
 * it. The server answers 204 whatever it found; the local state is dropped
 * regardless, so a network failure still signs this tab out.
 */
export async function signOut(notice = 'You have signed out.') {
  try {
    // keepalive, like the refresh: navigating away must not cancel a sign-out.
    await fetch('/auth/central/logout', { method: 'POST', credentials: 'same-origin', keepalive: true })
  } catch {
    // Dropped locally below either way.
  }
  forget(notice)
}

/** Drops the session locally, for when the server has already ended it. */
export function forget(notice) {
  setAccessToken(null)
  useAuthStore.getState().setUnauthenticated({ notice, signedOut: true })
}
