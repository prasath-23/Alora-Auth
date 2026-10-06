import { api } from './apiClient'
import { query } from '../utils/format'

// App Central's sign-in steps (/auth/*). Every POST here is refused unless it
// comes from App Central's own origin, which is where this code runs.

/** Which methods to offer for an address. Decided by its domain alone. */
export const discover = email => api.post('/auth/login/discover', { email })

export const passwordLogin = (email, password, returnTo) =>
  api.post('/auth/login/password', { email, password, ...(returnTo ? { return_to: returnTo } : {}) })

/** The companies of a pending account choice (after Google or SSO). */
export const loginChoices = () => api.get('/auth/login/choices')

export const chooseCompany = clientId => api.post('/auth/login/choose', { client_id: clientId })

// Google and SSO are browser navigations: the API answers with a redirect to
// the provider and, at the end, one back to App Central.
export const googleStartURL = returnTo => `/auth/google/start${query({ return_to: returnTo })}`

export const ssoStartURL = ({ connectionId, returnTo }) =>
  `/auth/sso/start${query({ connection_id: connectionId, return_to: returnTo })}`

export const lookupInvitation = token =>
  api.get(`/auth/accept-invitation/lookup${query({ token })}`)

export const acceptInvitation = (token, password) =>
  api.post('/auth/accept-invitation', { token, password })

export const acceptInvitationFederated = token =>
  api.post('/auth/accept-invitation/federated', { token })

export const resetPassword = (token, newPassword) =>
  api.post('/auth/reset-password', { token, new_password: newPassword })
