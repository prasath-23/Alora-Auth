import { create } from 'zustand'

// status:
//   'bootstrapping'   the first session refresh of this page load is in flight
//   'authenticated'   an access token is in memory and `me` is loaded
//   'unauthenticated' there is no usable session
//
// me is GET /api/me: who the user is, in which company, and what App Central
// should show them. It only decides what to RENDER; every API route checks its
// own guard again.
//
// signedOut marks a session the user (or the server) ended on purpose, so the
// login page can say so and does not offer to resume the page they were on.
const useAuthStore = create(set => ({
  status:    'bootstrapping',
  me:        null,
  notice:    null,
  signedOut: false,

  setAuthenticated: me => set({ status: 'authenticated', me, notice: null, signedOut: false }),

  setUnauthenticated: ({ notice = null, signedOut = false } = {}) =>
    set({ status: 'unauthenticated', me: null, notice, signedOut }),

  clearNotice: () => set({ notice: null }),
}))

export default useAuthStore
