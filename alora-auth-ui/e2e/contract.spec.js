import { test, expect } from '@playwright/test'
import { createHash, randomBytes } from 'node:crypto'
import { seedTenant, seedExtraUser, suffix } from './seed.js'

// Locks the RESPONSE SHAPES the SPA depends on. These are exactly the mismatches
// a backend swap introduces silently: the API returns 200, the UI renders
// nothing, and no unit test notices. Each assertion below mirrors a field the
// React code actually reads.

const base64url = b => b.toString('base64url')

async function loginToken(page, t) {
  const verifier = base64url(randomBytes(48))
  const challenge = base64url(createHash('sha256').update(verifier).digest())
  const redirectUrl = 'http://127.0.0.1:5173/'
  const p = new URLSearchParams({
    product_id: t.productId,
    redirect_url: redirectUrl,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: `s-${suffix()}`,
  })
  await page.goto(`/?${p}`)
  await page.locator('#email').fill(t.email)
  await page.locator('#password').fill(t.password)
  await page.getByRole('button', { name: /sign in/i }).click()
  await page.waitForURL(/[?&]code=/, { timeout: 15_000 })

  const code = new URL(page.url()).searchParams.get('code')
  const res = await page.request.post('/auth/token', {
    data: { code, code_verifier: verifier, redirect_url: redirectUrl },
  })
  expect(res.status()).toBe(200)
  return (await res.json()).access_token
}

test.describe('response contract', () => {
  test('list endpoints return BARE ARRAYS, not wrapped objects', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)
    const auth = { headers: { Authorization: `Bearer ${token}` } }

    // The SPA does setX(await res.json()) then .map() over it — a wrapped object
    // would throw or silently render an empty list.
    for (const path of ['/admin/invitations', '/admin/groups', '/admin/sessions', '/admin/products']) {
      const res = await page.request.get(path, auth)
      expect(res.status(), `${path} should be reachable`).toBe(200)
      expect(Array.isArray(await res.json()), `${path} must return a bare array`).toBe(true)
    }
  })

  test('GET /admin/users returns {users, nextCursor} with per-user groups', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)

    const res = await page.request.get('/admin/users?take=25', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status()).toBe(200)
    const body = await res.json()

    expect(Array.isArray(body.users)).toBe(true)
    expect(body).toHaveProperty('nextCursor') // UsersPage reads data.nextCursor
    const me = body.users.find(u => u.email === t.email)
    expect(me, 'seeded admin should be listed').toBeTruthy()
    for (const field of ['id', 'email', 'is_active', 'account_type', 'created_at']) {
      expect(me, `user.${field} is rendered by the SPA`).toHaveProperty(field)
    }
    expect(Array.isArray(me.groups), 'user.groups must be an array').toBe(true)
    expect(JSON.stringify(body)).not.toMatch(/password_hash|argon2/)
  })

  test('GET /admin/client exposes domain_verified_at as a timestamp, not a bool', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)

    const res = await page.request.get('/admin/client', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status()).toBe(200)
    const body = await res.json()

    // ClientPage.jsx reads client.domain_verified_at directly.
    expect(body).toHaveProperty('domain_verified_at')
    expect(typeof body.domain_verified_at).not.toBe('boolean')
    for (const field of ['id', 'name', 'require_mfa', 'allowed_idp_providers', 'subscription_status', 'is_active']) {
      expect(body).toHaveProperty(field)
    }
  })

  test('GET /admin/products includes every field the SPA renders', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)

    const res = await page.request.get('/admin/products', {
      headers: { Authorization: `Bearer ${token}` },
    })
    const list = await res.json()
    expect(list.length, 'the seeded tenant has one subscription').toBeGreaterThan(0)
    const fields = ['id', 'product_id', 'key', 'name', 'description', 'base_url',
      'is_active', 'seat_limit', 'starts_at', 'ends_at']
    for (const field of fields) {
      expect(list[0], `product.${field} is rendered by ProductsPage`).toHaveProperty(field)
    }
  })

  test('POST /auth/reset-password uses new_password, not password', async ({ page }) => {
    // The wrong field name is rejected outright: unknown fields are a 400.
    const wrong = await page.request.post('/auth/reset-password', {
      data: { token: 'x'.repeat(43), password: 'a-valid-long-password' },
    })
    expect(wrong.status(), 'the password field must be rejected').toBe(400)

    // The correct field reaches the token lookup and fails there instead.
    const right = await page.request.post('/auth/reset-password', {
      data: { token: 'x'.repeat(43), new_password: 'a-valid-long-password' },
    })
    expect(right.status()).toBe(400)
    expect((await right.json()).error).toMatch(/invalid or expired reset token/i)
  })

  test('permission grant takes productId in the PATH and camelCase roleName', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)
    const auth = { headers: { Authorization: `Bearer ${token}` } }

    // Target a DIFFERENT user: granting to ourselves would bump our own
    // permissions_version and invalidate the token we are testing with.
    const target = seedExtraUser(t.clientId)

    const res = await page.request.put(
      `/admin/users/${target.id}/permissions/${t.productId}`,
      { ...auth, data: { roleName: 'Editor' } })
    expect(res.status(), 'the SPA calls exactly this shape').toBe(200)

    // An unsubscribed product is a 403, matching Fastify.
    const other = seedTenant()
    const denied = await page.request.put(
      `/admin/users/${target.id}/permissions/${other.productId}`,
      { ...auth, data: { roleName: 'Editor' } })
    expect(denied.status()).toBe(403)
  })

  test('group members accept userId OR email', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)
    const auth = { headers: { Authorization: `Bearer ${token}` } }

    const g = await page.request.post('/admin/groups',
      { ...auth, data: { name: `G-${suffix()}`, features: ['users:view'] } })
    expect(g.status()).toBe(201)
    const groupId = (await g.json()).id

    // A different user again: adding ourselves would invalidate our own token.
    const target = seedExtraUser(t.clientId)

    const byId = await page.request.post(`/admin/groups/${groupId}/members`,
      { ...auth, data: { userId: target.id } })
    expect(byId.status()).toBe(201)

    // By email, into a second group (the first membership already exists).
    const g2 = await page.request.post('/admin/groups',
      { ...auth, data: { name: `G-${suffix()}`, features: ['users:view'] } })
    const groupId2 = (await g2.json()).id
    const byEmail = await page.request.post(`/admin/groups/${groupId2}/members`,
      { ...auth, data: { email: target.email } })
    expect(byEmail.status(), 'groups:manage does not imply users:view, so email is accepted').toBe(201)

    const neither = await page.request.post(`/admin/groups/${groupId}/members`, { ...auth, data: {} })
    expect(neither.status()).toBe(400)
  })

  test('POST /admin/me/change-password exists and re-verifies the current password', async ({ page }) => {
    const t = seedTenant()
    const token = await loginToken(page, t)
    const auth = { headers: { Authorization: `Bearer ${token}` } }

    // A wrong current password must be refused even with a valid token: that
    // re-authentication is what stops a stolen token becoming a takeover.
    const wrong = await page.request.post('/admin/me/change-password',
      { ...auth, data: { current_password: 'not-my-password', new_password: 'a-new-password-123' } })
    expect(wrong.status()).toBe(401)

    const ok = await page.request.post('/admin/me/change-password',
      { ...auth, data: { current_password: t.password, new_password: 'a-new-password-123' } })
    expect(ok.status()).toBe(204)

    // Changing the password revokes every existing session.
    expect((await page.request.post('/auth/refresh')).status()).toBe(401)
  })
})
