import { create } from 'zustand'

// status lifecycle:
//   'bootstrapping'  → silentRefresh in flight on mount
//   'authenticated'  → valid accessToken in memory
//   'unauthenticated'→ no session / logout
//
// loggedOut: true when the transition to unauthenticated was an explicit logout
//   (vs. never having been logged in). Used to show "signed out" notification.
const useAuthStore = create((set) => ({
  status:      'bootstrapping',
  accessToken: null,
  user:        null,
  features:    new Set(),
  loggedOut:   false,

  setAuthenticated: (accessToken, user, featureArray = []) =>
    set({ status: 'authenticated', accessToken, user, features: new Set(featureArray), loggedOut: false }),

  // Pass loggedOut=true when the user explicitly signed out or was kicked (password change).
  // Pass loggedOut=false (default) for silent-refresh failures on cold load.
  setUnauthenticated: (loggedOut = false) =>
    set({ status: 'unauthenticated', accessToken: null, user: null, features: new Set(), loggedOut }),
}))

export default useAuthStore
