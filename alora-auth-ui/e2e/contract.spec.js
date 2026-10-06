import { test, expect } from '@playwright/test'
import { createHash, randomBytes } from 'node:crypto'
import { seedCompany, stack, suffix } from './seed.js'
import { apiClient, bearer, claimsOf, tokenFor } from './helpers.js'

// The contract, checked through the same proxy the browser uses: the response
// shapes the SPA and a product backend read, and the transport rules that keep
// them safe. Each is exactly the kind of drift a unit test on one side misses —
// the API answers 200, and the other side silently renders nothing.

const basicAuth = (id, secret) =>
  'Basic ' + Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')

test.describe('response shapes', () => {
  let t
  let api
  let token

  test.beforeAll(async () => {
    t = seedCompany({ productPort: 9 })
    api = await apiClient()
    token = await tokenFor(api, t.email, t.password)
  })
  test.afterAll(() => api?.dispose())

  test('GET /api/me says who, in which company, and what App Central should show', async () => {
    const res = await api.get('/api/me', bearer(token))
    expect(res.status()).toBe(200)
    const me = await res.json()
    expect(me).toMatchObject({ email: t.email, company: { id: t.companyId, name: t.company }, is_admin: true, is_owner: false })
    expect(me.scopes).toEqual(expect.arrayContaining(['apps:read', 'users:read', 'users:edit', 'groups:edit', 'company:edit']))
    expect(me.scope_sources.find(x => x.scope === 'users:edit')).toMatchObject({ source: 'GROUP', group_name: 'Admins' })
    expect(me.products).toEqual([t.productKey])
    expect(me.manages, 'the groups they run as a manager: none').toEqual([])
    expect(me).not.toHaveProperty('features')
    expect(Number.isNaN(Date.parse(me.authenticated_at))).toBe(false)
  })

  test('the sign-in token carries App Central access: the scope, and the apps as a list of keys', async () => {
    const claims = claimsOf(token)
    expect(claims.scope.split(' ')).toEqual((await (await api.get('/api/me', bearer(token))).json()).scopes)
    expect(claims.products).toEqual([t.productKey])
    expect(claims.manages, 'the groups they manage, as ids: none').toEqual([])
    expect(claims, 'roles belong in each app’s own token').not.toHaveProperty('roles')
    expect(Number.isInteger(claims.av) && Number.isInteger(claims.pv)).toBe(true)
  })

  test('a manager’s /api/me names the groups they run, and their token lists the ids', async () => {
    const group = await (await api.post('/api/admin/groups', { data: { name: `Run ${suffix()}`, scopes: [] }, ...bearer(token) })).json()
    const lead = `lead-${suffix()}@e2e.test`
    const inv = await api.post('/api/admin/invitations', { data: { email: lead, group_ids: [] }, ...bearer(token) })
    const inviteToken = new URL((await inv.json()).invite_url).searchParams.get('token')
    expect((await api.post('/auth/accept-invitation', { data: { token: inviteToken, password: t.password } })).status()).toBe(204)
    const res = await api.post(`/api/admin/groups/${group.id}/managers`, { data: { email: lead }, ...bearer(token) })
    expect(res.status(), await res.text()).toBe(201)
    expect(await res.json()).toEqual({ group_id: group.id, user_id: expect.any(String) })

    const leadToken = await tokenFor(api, lead, t.password)
    const me = await (await api.get('/api/me', bearer(leadToken))).json()
    expect(me.manages).toEqual([{ id: group.id, name: group.name }])
    expect(claimsOf(leadToken).manages).toEqual([group.id])
    const page = await (await api.get(`/api/me/managed-groups/${group.id}`, bearer(leadToken))).json()
    expect(page).toMatchObject({ id: group.id, members: [], login_policy_name: null })
    expect(page.managers).toEqual([expect.objectContaining({ email: lead, appointed_by_email: t.email, appointed_by_owner: false })])
  })

  test('GET /api/me/apps gives each app a launch URL naming the issuer and where to land', async () => {
    const apps = await (await api.get('/api/me/apps', bearer(token))).json()
    expect(Array.isArray(apps)).toBe(true)
    const app = apps.find(a => a.product_id === t.productId)
    expect(app).toMatchObject({ key: t.productKey, name: t.productName, roles: ['Admin'] })
    const launch = new URL(app.launch_url)
    expect(`${launch.origin}${launch.pathname}`).toBe(`${t.origin}/login/initiate`)
    expect(launch.searchParams.get('iss')).toBe(stack().issuer)
    expect(launch.searchParams.get('target_link_uri')).toBe(`${t.origin}/`)
  })

  test('the admin list endpoints return bare arrays', async () => {
    for (const path of ['/api/admin/invitations', '/api/admin/groups', '/api/admin/sessions', '/api/admin/products']) {
      const res = await api.get(path, bearer(token))
      expect(res.status(), path).toBe(200)
      expect(Array.isArray(await res.json()), `${path} must be a bare array`).toBe(true)
    }
  })

  test('GET /api/admin/users pages as {users, nextCursor} and never carries a password hash', async () => {
    const res = await api.get('/api/admin/users?take=25', bearer(token))
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body).toHaveProperty('nextCursor')
    const me = body.users.find(u => u.email === t.email)
    expect(me).toMatchObject({ is_active: true, is_admin: true, is_owner: false })
    expect(me.groups.map(g => g.system_key)).toContain('ADMINS')
    expect(JSON.stringify(body)).not.toMatch(/password_hash|argon2/)
  })

  test('the session list names each user by address, never by id, and carries no token material', async () => {
    const sessions = await (await api.get('/api/admin/sessions', bearer(token))).json()
    expect(sessions.length).toBeGreaterThan(0)
    expect(sessions.map(s => s.email)).toContain(t.email)
    for (const s of sessions) {
      expect(['CENTRAL', 'PRODUCT']).toContain(s.kind)
      expect(s).not.toHaveProperty('user_id')
      expect(JSON.stringify(s)).not.toMatch(/hash|token/i)
    }
  })

  test('discovery describes exactly what is implemented', async () => {
    const res = await api.get('/.well-known/openid-configuration')
    expect(res.status()).toBe(200)
    const d = await res.json()
    const iss = stack().issuer
    expect(d).toMatchObject({
      issuer: iss,
      authorization_endpoint: `${iss}/oauth/authorize`,
      token_endpoint: `${iss}/oauth/token`,
      jwks_uri: `${iss}/.well-known/jwks.json`,
      revocation_endpoint: `${iss}/oauth/revoke`,
      introspection_endpoint: `${iss}/oauth/introspect`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic'],
      id_token_signing_alg_values_supported: ['RS256'],
      authorization_response_iss_parameter_supported: true,
    })
  })

  test('the JWKS publishes public RS256 keys only, readable from any origin', async () => {
    const res = await api.get('/.well-known/jwks.json', { headers: { Origin: 'https://some-product.example' } })
    expect(res.status()).toBe(200)
    expect(res.headers()['access-control-allow-origin']).toBe('*')
    const { keys } = await res.json()
    expect(keys.length).toBeGreaterThan(0)
    for (const k of keys) {
      expect(k.kty).toBe('RSA')
      expect(k.kid).toBeTruthy()
      for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(k, `private part ${secret}`).not.toHaveProperty(secret)
    }
  })
})

test.describe('transport rules', () => {
  let t

  test.beforeAll(() => {
    t = seedCompany({ productPort: 9 })
  })

  test('App Central’s own API answers no other origin: there is no CORS outside /.well-known', async () => {
    const api = await apiClient()
    const token = await tokenFor(api, t.email, t.password)
    const res = await api.get('/api/me', { headers: { Authorization: `Bearer ${token}`, Origin: 'https://evil.example' } })
    expect(res.headers()['access-control-allow-origin']).toBeUndefined()
    const preflight = await api.fetch('/auth/login/password', {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' },
    })
    expect(preflight.headers()['access-control-allow-origin']).toBeUndefined()
    expect(preflight.headers()['access-control-allow-credentials']).toBeUndefined()
    await api.dispose()
  })

  test('sign-in refuses a cross-site request, a same-site one, and a body that is not JSON', async () => {
    const api = await apiClient()
    const body = { email: t.email, password: t.password }
    const post = opts => api.post('/auth/login/password', opts)

    expect((await post({ data: body, headers: { 'Sec-Fetch-Site': 'cross-site' } })).status(), 'cross-site').toBe(403)
    // A sibling subdomain is same-SITE, which SameSite cookies do not stop.
    expect((await post({ data: body, headers: { 'Sec-Fetch-Site': 'same-site' } })).status(), 'same-site').toBe(403)
    expect((await post({ data: body, headers: { Origin: 'https://evil.example' } })).status(), 'a foreign Origin').toBe(403)
    expect((await post({ form: body })).status(), 'a form post').toBe(415)
    expect((await post({ data: JSON.stringify(body), headers: { 'Content-Type': 'text/plain' } })).status(), 'text/plain').toBe(415)
    expect((await post({ data: body, headers: { 'Sec-Fetch-Site': 'same-origin' } })).status(), 'App Central itself').toBe(200)
    await api.dispose()
  })

  test('a sign-in returns return_to only when it is a path on App Central', async () => {
    const api = await apiClient()
    const answer = async returnTo => (await (await api.post('/auth/login/password', {
      data: { email: t.email, password: t.password, return_to: returnTo },
    })).json()).return_to
    for (const evil of ['https://evil.example/', '//evil.example', '/\\evil.example', '/\t/evil.example', 'javascript:alert(1)']) {
      expect(await answer(evil), evil).toBeUndefined()
    }
    expect(await answer('/admin/users?x=1')).toBe('/admin/users?x=1')
    await api.dispose()
  })

  test('the session refresh is refused cross-site and rotates the cookie same-origin', async () => {
    const api = await apiClient()
    await tokenFor(api, t.email, t.password)
    expect((await api.post('/auth/central/refresh', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status()).toBe(403)
    const res = await api.post('/auth/central/refresh', { headers: { 'Sec-Fetch-Site': 'same-origin' } })
    expect(res.status()).toBe(200)
    expect(res.headers()['cache-control']).toContain('no-store')
    const body = await res.json()
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 900 })
    expect(body).not.toHaveProperty('refresh_token') // it lives only in the HttpOnly cookie
    await api.dispose()
  })
})

test.describe('the OpenID provider, driven as a product backend would', () => {
  let t

  test.beforeAll(() => {
    t = seedCompany({ productPort: 9 })
  })

  function authorizeQuery(overrides = {}) {
    const verifier = randomBytes(48).toString('base64url')
    const query = new URLSearchParams({
      response_type: 'code', client_id: t.productId, redirect_uri: `${t.origin}/callback`, scope: 'openid email',
      state: `st-${suffix()}`, nonce: `n-${suffix()}`,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
      ...overrides,
    })
    return { verifier, query }
  }

  test('the code flow yields a product token that App Central refuses, and App Central’s token means nothing to the product', async () => {
    const browser = await apiClient() // stands in for the user's browser: it holds the session cookie
    const central = await tokenFor(browser, t.email, t.password)
    const { verifier, query } = authorizeQuery()

    const auth = await browser.get(`/oauth/authorize?${query}`, { maxRedirects: 0 })
    expect(auth.status()).toBe(302)
    const back = new URL(auth.headers().location)
    expect(`${back.origin}${back.pathname}`).toBe(`${t.origin}/callback`)
    expect(back.searchParams.get('state')).toBe(query.get('state'))
    expect(back.searchParams.get('iss')).toBe(stack().issuer)
    const code = back.searchParams.get('code')

    const product = await apiClient() // the product's backend: no cookies at all
    const exchange = () => product.post('/oauth/token', {
      form: { grant_type: 'authorization_code', code, redirect_uri: `${t.origin}/callback`, code_verifier: verifier },
      headers: { Authorization: basicAuth(t.productId, t.clientSecret) },
    })
    const tok = await exchange()
    expect(tok.status(), await tok.text()).toBe(200)
    expect(tok.headers()['cache-control']).toContain('no-store')
    const set = await tok.json()
    expect(set).toMatchObject({ token_type: 'Bearer' })
    expect(set.refresh_token && set.id_token).toBeTruthy()

    expect((await browser.get('/api/me', bearer(set.access_token))).status(), 'a product token at App Central').toBe(401)
    const introspect = token => product.post('/oauth/introspect', {
      form: { token }, headers: { Authorization: basicAuth(t.productId, t.clientSecret) },
    })
    expect((await (await introspect(central)).json()).active, 'App Central’s token, to the product').toBe(false)
    const own = await (await introspect(set.access_token)).json()
    expect(own).toMatchObject({ active: true, client_id: t.productId, sub: expect.any(String) })

    const replay = await exchange()
    expect(replay.status(), 'a code is single-use').toBe(400)
    expect((await replay.json()).error).toBe('invalid_grant')
    await browser.dispose()
    await product.dispose()
  })

  test('an unregistered redirect_uri is never redirected to', async () => {
    const browser = await apiClient()
    await tokenFor(browser, t.email, t.password)
    const { query } = authorizeQuery({ redirect_uri: 'https://evil.example/callback' })
    const res = await browser.get(`/oauth/authorize?${query}`, { maxRedirects: 0 })
    expect(res.status()).toBe(400)
    expect(res.headers().location).toBeUndefined()
    await browser.dispose()
  })

  test('a request without PKCE is sent back to the product as an error, not a code', async () => {
    const browser = await apiClient()
    await tokenFor(browser, t.email, t.password)
    const { query } = authorizeQuery()
    query.delete('code_challenge')
    query.delete('code_challenge_method')
    const res = await browser.get(`/oauth/authorize?${query}`, { maxRedirects: 0 })
    expect(res.status()).toBe(302)
    const back = new URL(res.headers().location)
    expect(back.searchParams.get('error')).toBe('invalid_request')
    expect(back.searchParams.get('code')).toBeNull()
    await browser.dispose()
  })

  test('the token endpoint refuses a wrong secret and a secret in the body', async () => {
    const product = await apiClient()
    const wrong = await product.post('/oauth/token', {
      form: { grant_type: 'authorization_code', code: 'x', redirect_uri: `${t.origin}/callback`, code_verifier: 'y' },
      headers: { Authorization: basicAuth(t.productId, `${t.clientSecret}x`) },
    })
    expect(wrong.status()).toBe(401)
    expect((await wrong.json()).error).toBe('invalid_client')
    const inBody = await product.post('/oauth/token', {
      form: { grant_type: 'authorization_code', code: 'x', client_id: t.productId, client_secret: t.clientSecret },
    })
    expect(inBody.status()).toBe(401)
    await product.dispose()
  })
})
