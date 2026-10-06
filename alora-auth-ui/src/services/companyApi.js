import { api } from './apiClient'
import { query } from '../utils/format'

// One company's users, groups, invitations and API clients are reachable through two doors:
// the company's own people use /api/admin (each call needs its App Central
// scope), the Owner uses /api/owner/companies/:cid. The pages that manage them
// take one of these objects and never build a URL themselves, so the same
// component serves both.

const companyRoutes = (base, opts) => ({
  listUsers:       ({ cursor, take = 25, search } = {}) => api.get(`${base}/users${query({ cursor, take, search })}`, opts),
  getUser:         id => api.get(`${base}/users/${id}`, opts),
  setUserActive:   (id, isActive) => api.patch(`${base}/users/${id}`, { is_active: isActive }, opts),
  setUserScopes:   (id, scopes) => api.put(`${base}/users/${id}/scopes`, { scopes }, opts),
  issueReset:      id => api.post(`${base}/users/${id}/password-reset`, undefined, opts),
  listInvitations: () => api.get(`${base}/invitations`, opts),
  createInvitation: (email, groupIds) => api.post(`${base}/invitations`, { email, group_ids: groupIds }, opts),
  revokeInvitation: id => api.delete(`${base}/invitations/${id}`, opts),
  listGroups:      () => api.get(`${base}/groups`, opts),
  getGroup:        id => api.get(`${base}/groups/${id}`, opts),
  createGroup:     body => api.post(`${base}/groups`, body, opts),
  updateGroup:     (id, body) => api.patch(`${base}/groups/${id}`, body, opts),
  deleteGroup:     id => api.delete(`${base}/groups/${id}`, opts),
  setGroupScopes:  (id, scopes) => api.put(`${base}/groups/${id}/scopes`, { scopes }, opts),
  addMember:       (groupId, email) => api.post(`${base}/groups/${groupId}/members`, { email }, opts),
  removeMember:    (groupId, userId) => api.delete(`${base}/groups/${groupId}/members/${userId}`, opts),
  addManager:      (groupId, email) => api.post(`${base}/groups/${groupId}/managers`, { email }, opts),
  removeManager:   (groupId, userId) => api.delete(`${base}/groups/${groupId}/managers/${userId}`, opts),
  listAPIClients:  () => api.get(`${base}/api-clients`, opts),
  getAPIClient:    id => api.get(`${base}/api-clients/${id}`, opts),
  createAPIClient: body => api.post(`${base}/api-clients`, body, opts),
  updateAPIClient: (id, body) => api.patch(`${base}/api-clients/${id}`, body, opts),
  deleteAPIClient: id => api.delete(`${base}/api-clients/${id}`, opts),
  setAPIClientScopes:    (id, scopes) => api.put(`${base}/api-clients/${id}/scopes`, { scopes }, opts),
  setAPIClientProducts:  (id, productIds) => api.put(`${base}/api-clients/${id}/products`, { product_ids: productIds }, opts),
  createAPIClientSecret: (id, expiresInDays) =>
    api.post(`${base}/api-clients/${id}/secrets`, expiresInDays ? { expires_in_days: expiresInDays } : {}, opts),
  revokeAPIClientSecret: (id, secretId) => api.delete(`${base}/api-clients/${id}/secrets/${secretId}`, opts),
})

/** The signed-in person's own company. */
export function adminApi() {
  const base = '/api/admin'
  return {
    kind: 'admin',
    ...companyRoutes(base),
    listSessions:  () => api.get(`${base}/sessions`),
    revokeSession: id => api.delete(`${base}/sessions/${id}`),
    listProducts:  () => api.get(`${base}/products`),
    getCompany:    () => api.get(`${base}/client`),
    renameCompany: name => api.patch(`${base}/client`, { name }),
  }
}

/**
 * The groups the signed-in person manages: a door of its own, open only on
 * those groups, and only to change who is in them. The API asks, on every call,
 * whether they still manage the group.
 */
export function managerApi() {
  const base = '/api/me/managed-groups'
  return {
    kind: 'manager',
    listGroups:   () => api.get(base),
    getGroup:     id => api.get(`${base}/${id}`),
    addMember:    (groupId, email) => api.post(`${base}/${groupId}/members`, { email }),
    removeMember: (groupId, userId) => api.delete(`${base}/${groupId}/members/${userId}`),
  }
}

/**
 * Any company, as the Owner. Every call repeats the company in the
 * X-Alora-Target-Company header: the API refuses a write whose header and path
 * disagree, so a stale tab can never act on the wrong company.
 */
export function ownerCompanyApi(cid) {
  const base = `/api/owner/companies/${cid}`
  const opts = { headers: { 'X-Alora-Target-Company': cid } }
  return {
    kind: 'owner',
    cid,
    ...companyRoutes(base, opts),
    getCompany:        () => api.get(base, opts),
    updateCompany:     changes => api.patch(base, changes, opts),
    setDomain:         (domain, verified) => api.put(`${base}/domain`, { domain: domain || null, verified }, opts),
    listSubscriptions: () => api.get(`${base}/subscriptions`, opts),
    setSubscription:   (productId, body) => api.put(`${base}/subscriptions/${productId}`, body, opts),
    grant:             (userId, productId, roleName) => api.put(`${base}/users/${userId}/grants/${productId}`, { role_name: roleName }, opts),
    revokeGrant:       (userId, productId) => api.delete(`${base}/users/${userId}/grants/${productId}`, opts),
    assignUserPolicy:  (userId, policyId) => api.put(`${base}/users/${userId}/login-policy`, { policy_id: policyId || null }, opts),
    setGroupGrants:    (id, grants) => api.put(`${base}/groups/${id}/product-grants`, { product_grants: grants }, opts),
    assignGroupPolicy: (id, policyId) => api.put(`${base}/groups/${id}/login-policy`, { policy_id: policyId || null }, opts),
    listPolicies:      () => api.get(`${base}/login-policies`, opts),
    createPolicy:      body => api.post(`${base}/login-policies`, body, opts),
    updatePolicy:      (id, body) => api.patch(`${base}/login-policies/${id}`, body, opts),
    deletePolicy:      id => api.delete(`${base}/login-policies/${id}`, opts),
    setDefaultPolicy:  id => api.put(`${base}/login-policies/${id}/default`, undefined, opts),
    listConnections:   () => api.get(`${base}/sso-connections`, opts),
    createConnection:  body => api.post(`${base}/sso-connections`, body, opts),
    updateConnection:  (id, body) => api.patch(`${base}/sso-connections/${id}`, body, opts),
    setConnectionDomains: (id, domains) => api.put(`${base}/sso-connections/${id}/domains`, { domains }, opts),
    testConnection:    id => api.post(`${base}/sso-connections/${id}/test`, undefined, opts),
  }
}

// The platform-wide Owner resources.
export const listCompanies  = () => api.get('/api/owner/companies')
export const createCompany  = body => api.post('/api/owner/companies', body)
export const listProducts   = () => api.get('/api/owner/products')
export const getProduct     = id => api.get(`/api/owner/products/${id}`)
export const createProduct  = body => api.post('/api/owner/products', body)
export const updateProduct  = (id, body) => api.patch(`/api/owner/products/${id}`, body)
export const setRedirectURIs = (id, uris) => api.put(`/api/owner/products/${id}/redirect-uris`, { redirect_uris: uris })
export const setRoles       = (id, roles) => api.put(`/api/owner/products/${id}/roles`, { roles })
export const rotateSecret   = id => api.post(`/api/owner/products/${id}/client-secret`)
export const listAllAPIClients = () => api.get('/api/owner/api-clients')
