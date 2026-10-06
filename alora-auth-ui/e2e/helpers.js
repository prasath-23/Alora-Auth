import { expect, request } from '@playwright/test'
import { owner, suffix, PASSWORD } from './seed.js'

export const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5173'

// ── In the browser ───────────────────────────────────────────────────────────

/** Identifier-first sign-in through App Central's login page. */
export async function signIn(page, email, password, { path = '/login' } = {}) {
  if (path) await page.goto(path)
  await page.locator('#email').fill(email)
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.locator('#password').fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

/** Signs in and waits for the signed-in shell. */
export async function signedIn(page, email, password) {
  await signIn(page, email, password)
  await expect(page.getByTestId('me-email')).toHaveText(email)
}

export const pathOf = page => {
  const u = new URL(page.url())
  return u.pathname + u.search
}

// ── Against the API directly ─────────────────────────────────────────────────

/**
 * A fresh API client with its own cookie jar, never the browser's. It sends no
 * Origin or Sec-Fetch-Site header, as a non-browser client would.
 */
export const apiClient = () => request.newContext({ baseURL: BASE_URL })

/** Signs in with a password and returns an App Central access token. */
export async function tokenFor(api, email, password) {
  const res = await api.post('/auth/login/password', { data: { email, password } })
  expect(res.status(), `sign-in as ${email}: ${await res.text()}`).toBe(200)
  const body = await res.json()
  expect(body.status).toBe('authenticated')
  return body.access_token
}

export const bearer = token => ({ headers: { Authorization: `Bearer ${token}` } })

/**
 * Has the company's Admin invite a new address (into the given groups) and the
 * invitee accept it with a password: a plain member, made the way real members
 * are made.
 */
export async function newMember(seeded, { groupIds = [] } = {}) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, seeded.email, seeded.password)
    const email = `member-${suffix()}@e2e.test`
    const inv = await api.post('/api/admin/invitations', { data: { email, group_ids: groupIds }, ...bearer(token) })
    expect(inv.status(), await inv.text()).toBe(201)
    const inviteToken = new URL((await inv.json()).invite_url).searchParams.get('token')
    const acc = await api.post('/auth/accept-invitation', { data: { token: inviteToken, password: PASSWORD } })
    expect(acc.status(), await acc.text()).toBe(204)
    return { email, password: PASSWORD }
  } finally {
    await api.dispose()
  }
}

/** Reads a JWT's payload without verifying it: for asserting what a token carries. */
export const claimsOf = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())

/** A user's id, as the company's people see it. */
export async function userId(api, token, email) {
  const res = await api.get(`/api/admin/users?search=${encodeURIComponent(email)}`, bearer(token))
  expect(res.status(), await res.text()).toBe(200)
  const user = (await res.json()).users.find(u => u.email === email)
  expect(user, `no user ${email}`).toBeTruthy()
  return user.id
}

/**
 * As the company's Admin, creates a group giving the named App Central scopes
 * (an edit scope brings its read scope). Returns its id.
 */
export async function companyGroup(seeded, name, scopes) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, seeded.email, seeded.password)
    const res = await api.post('/api/admin/groups', { data: { name: `${name} ${suffix()}`, scopes }, ...bearer(token) })
    expect(res.status(), await res.text()).toBe(201)
    return (await res.json()).id
  } finally {
    await api.dispose()
  }
}

/** As the company's Admin, sets someone's extra App Central scopes. */
export async function giveExtras(seeded, email, scopes) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, seeded.email, seeded.password)
    const id = await userId(api, token, email)
    const res = await api.put(`/api/admin/users/${id}/scopes`, { data: { scopes }, ...bearer(token) })
    expect(res.status(), await res.text()).toBe(200)
  } finally {
    await api.dispose()
  }
}

/** As the Owner, switches whether a product accepts API clients. */
export async function acceptAPIClients(productId, on = true) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, owner().email, owner().password)
    const p = await (await api.get(`/api/owner/products/${productId}`, bearer(token))).json()
    const res = await api.patch(`/api/owner/products/${productId}`, {
      data: {
        name: p.name, description: p.description ?? '', base_url: p.base_url ?? '',
        initiate_login_uri: p.initiate_login_uri ?? '', is_active: p.is_active, accepts_api_clients: on,
      },
      ...bearer(token),
    })
    expect(res.status(), await res.text()).toBe(200)
  } finally {
    await api.dispose()
  }
}

/** As the company's Admin, creates an API client. Returns it. */
export async function companyAPIClient(seeded, name) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, seeded.email, seeded.password)
    const res = await api.post('/api/admin/api-clients', { data: { name }, ...bearer(token) })
    expect(res.status(), await res.text()).toBe(201)
    return await res.json()
  } finally {
    await api.dispose()
  }
}

/** HTTP Basic credentials, form-encoded first as RFC 6749 §2.3.1 says. */
export const basicAuth = (id, secret) =>
  'Basic ' + Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')

/**
 * As the company's Admin, sets up an API client: its products, its scopes and
 * a secret. Returns { id, secret, secretId }.
 */
export async function readyAPIClient(seeded, { name, productIds, scopes }) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, seeded.email, seeded.password)
    const c = await api.post('/api/admin/api-clients', { data: { name }, ...bearer(token) })
    expect(c.status(), await c.text()).toBe(201)
    const { id } = await c.json()
    const p = await api.put(`/api/admin/api-clients/${id}/products`, { data: { product_ids: productIds }, ...bearer(token) })
    expect(p.status(), await p.text()).toBe(200)
    const s = await api.put(`/api/admin/api-clients/${id}/scopes`, { data: { scopes }, ...bearer(token) })
    expect(s.status(), await s.text()).toBe(200)
    const sec = await api.post(`/api/admin/api-clients/${id}/secrets`, { data: {}, ...bearer(token) })
    expect(sec.status(), await sec.text()).toBe(201)
    const { client_secret: secret, id: secretId } = await sec.json()
    return { id, secret, secretId }
  } finally {
    await api.dispose()
  }
}

/** As an application: asks the token endpoint for a product token. */
export async function clientCredentials(api, id, secret, { resource, scope } = {}) {
  const form = { grant_type: 'client_credentials' }
  if (resource) form.resource = resource
  if (scope) form.scope = scope
  return api.post('/oauth/token', { form, headers: { Authorization: basicAuth(id, secret) } })
}
