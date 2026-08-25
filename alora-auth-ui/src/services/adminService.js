import { api } from './apiClient'

async function handleResponse(res) {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? `HTTP ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}

// ── Features ──────────────────────────────────────────────────────────────────
export const getMyFeatures = (token) =>
  api.get('/admin/me/features', token).then(handleResponse)

// ── Groups ────────────────────────────────────────────────────────────────────
export const listGroups = (token) =>
  api.get('/admin/groups', token).then(handleResponse)

export const getGroup = (id, token) =>
  api.get(`/admin/groups/${id}`, token).then(handleResponse)

export const createGroup = (data, token) =>
  api.post('/admin/groups', data, token).then(handleResponse)

export const updateGroup = (id, patch, token) =>
  api.patch(`/admin/groups/${id}`, patch, token).then(handleResponse)

export const deleteGroup = (id, token) =>
  api.delete(`/admin/groups/${id}`, token).then(handleResponse)

export const addGroupMemberByEmail = (groupId, email, token) =>
  api.post(`/admin/groups/${groupId}/members`, { email }, token).then(handleResponse)

export const addGroupMember = (groupId, userId, token) =>
  api.post(`/admin/groups/${groupId}/members`, { userId }, token).then(handleResponse)

export const removeGroupMember = (groupId, userId, token) =>
  api.delete(`/admin/groups/${groupId}/members/${userId}`, token).then(handleResponse)

// ── Users ─────────────────────────────────────────────────────────────────────
export function listUsers({ cursor, take, search } = {}, token) {
  const p = new URLSearchParams()
  if (cursor) p.set('cursor', cursor)
  if (take)   p.set('take',   String(take))
  if (search) p.set('search', search)
  const qs = p.toString()
  return api.get(`/admin/users${qs ? `?${qs}` : ''}`, token).then(handleResponse)
}

export const getUser = (id, token) =>
  api.get(`/admin/users/${id}`, token).then(handleResponse)

export const setUserActive = (id, is_active, token) =>
  api.patch(`/admin/users/${id}`, { is_active }, token).then(handleResponse)

export const requestPasswordReset = (userId, token) =>
  api.post(`/admin/users/${userId}/password-reset`, {}, token).then(handleResponse)

export const changeMyPassword = (data, token) =>
  api.post('/admin/me/change-password', data, token).then(handleResponse)

// ── Permissions ───────────────────────────────────────────────────────────────
export const grantPermission = (userId, productId, roleName, token) =>
  api.put(`/admin/users/${userId}/permissions/${productId}`, { roleName }, token).then(handleResponse)

export const revokePermission = (userId, productId, token) =>
  api.delete(`/admin/users/${userId}/permissions/${productId}`, token).then(handleResponse)

// ── Products ──────────────────────────────────────────────────────────────────
export const listProducts = (token) =>
  api.get('/admin/products', token).then(handleResponse)

// ── Client ────────────────────────────────────────────────────────────────────
export const getClientInfo = (token) =>
  api.get('/admin/client', token).then(handleResponse)

export const updateClientInfo = (patch, token) =>
  api.patch('/admin/client', patch, token).then(handleResponse)

// ── Existing: sessions + invitations ──────────────────────────────────────────
export const listSessions = (token) =>
  api.get('/admin/sessions', token).then(handleResponse)

export const revokeSession = (id, token) =>
  api.delete(`/admin/sessions/${id}`, token).then(handleResponse)

export const createInvitation = (data, token) =>
  api.post('/admin/invitations', data, token).then(handleResponse)

export const listInvitations = (token) =>
  api.get('/admin/invitations', token).then(handleResponse)

export const revokeInvitation = (id, token) =>
  api.delete(`/admin/invitations/${id}`, token).then(handleResponse)
