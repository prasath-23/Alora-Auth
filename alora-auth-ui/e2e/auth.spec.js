import { test, expect } from '@playwright/test'
import { createHash, randomBytes } from 'node:crypto'
import { seedTenant, query, suffix } from './seed.js'

// These specs drive the real browser against the real Go/Gin API and a real
// Postgres. Nothing is mocked, so any contract mismatch between the SPA and the
// backend fails HERE — which is the whole point during a backend replacement.
//
// THE REAL LOGIN SHAPE. `/` is an OAuth2 authorization endpoint, not a
// self-contained login page: a product app sends the user there with PKCE
// parameters, the SPA posts the credentials, and the browser is redirected back
// to the product carrying a one-time code. These tests play the product app's
// part, which is why they build a PKCE pair and exchange the code themselves.

const base64url = buf => buf.toString('base64url')

function pkcePair() {
  const verifier = base64url(randomBytes(48))
  const challenge = base64url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge }
}

/** Builds the authorize URL a product app would send the user to. */
function authorizeURL({ productId, redirectUrl, challenge, state }) {
  const p = new URLSearchParams({
    product_id: productId,
    redirect_url: redirectUrl,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  })
  return `/?${p}`
}

/**
 * Runs the complete login: fills the form, follows the redirect back to the
 * "product", then exchanges the code for tokens. page.request shares the
 * browser's cookie jar, so the session cookies land in the page context exactly
 * as they would for a real product app on the same origin.
 */
async function login(page, tenant, { password = tenant.password } = {}) {
  const { verifier, challenge } = pkcePair()
  const redirectUrl = 'http://127.0.0.1:5173/'
  const state = `st-${suffix()}`

  await page.goto(authorizeURL({ productId: tenant.productId, redirectUrl, challenge, state }))
  await page.locator('#email').fill(tenant.email)
  await page.locator('#password').fill(password)
  await page.getByRole('button', { name: /sign in/i }).click()

  // The SPA redirects to the product with ?code=... on success.
  await page.waitForURL(/[?&]code=/, { timeout: 15_000 })
  const code = new URL(page.url()).searchParams.get('code')
  expect(code, 'authorization code should be present in the redirect').toBeTruthy()
  expect(new URL(page.url()).searchParams.get('state'), 'state must round-trip').toBe(state)

  const res = await page.request.post('/auth/token', {
    data: { code, code_verifier: verifier, redirect_url: redirectUrl },
  })
  expect(res.status(), 'token exchange should succeed').toBe(200)
  return { body: await res.json(), verifier, code, redirectUrl }
}

test.describe('login (OAuth2 + PKCE)', () => {
  test('issues a code, exchanges it for tokens, and establishes a session', async ({ page }) => {
    const t = seedTenant()
    const { body } = await login(page, t)

    expect(body.token_type).toBe('Bearer')
    expect(body.expires_in).toBe(900)
    expect(body.access_token).toBeTruthy()

    // The refresh cookie must exist and be invisible to JavaScript.
    const rt = (await page.context().cookies()).find(c => c.name === 'alora_rt')
    expect(rt, 'refresh cookie should be set').toBeTruthy()
    expect(rt.httpOnly, 'refresh cookie must be HttpOnly').toBe(true)
    expect(await page.evaluate(() => document.cookie)).not.toContain('alora_rt')

    // With the session established, the admin SPA bootstraps via silent refresh.
    await page.goto('/admin')
    await expect(page).toHaveURL(/\/admin/)
    await expect(page.locator('body')).not.toContainText(/sign in through your product/i)
  })

  test('rejects a wrong password without leaking which field was wrong', async ({ page }) => {
    const t = seedTenant()
    const { challenge } = pkcePair()

    await page.goto(authorizeURL({
      productId: t.productId, redirectUrl: 'http://127.0.0.1:5173/',
      challenge, state: 'st-bad',
    }))
    await page.locator('#email').fill(t.email)
    await page.locator('#password').fill('definitely-the-wrong-password')
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page.getByText(/invalid email or password/i)).toBeVisible()
    // No code was issued and no session cookie was set.
    expect(page.url()).not.toMatch(/[?&]code=/)
    expect((await page.context().cookies()).find(c => c.name === 'alora_rt')).toBeFalsy()
  })

  test('rejects an unknown email with the SAME message (no enumeration)', async ({ page }) => {
    const t = seedTenant()
    const { challenge } = pkcePair()

    await page.goto(authorizeURL({
      productId: t.productId, redirectUrl: 'http://127.0.0.1:5173/',
      challenge, state: 'st-unknown',
    }))
    await page.locator('#email').fill(`nobody-${suffix()}@nowhere.test`)
    await page.locator('#password').fill(t.password)
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page.getByText(/invalid email or password/i)).toBeVisible()
  })

  test('refuses to render the form without valid PKCE parameters', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText(/missing required parameter/i)).toBeVisible()

    const t = seedTenant()
    const { challenge } = pkcePair()
    // Only S256 is acceptable; `plain` offers no protection.
    await page.goto(`/?product_id=${t.productId}&redirect_url=http://127.0.0.1:5173/&code_challenge=${challenge}&code_challenge_method=plain&state=s`)
    await expect(page.getByText(/unsupported code_challenge_method/i)).toBeVisible()
  })

  test('a code cannot be exchanged twice', async ({ page }) => {
    const t = seedTenant()
    const { code, verifier, redirectUrl } = await login(page, t)

    const replay = await page.request.post('/auth/token', {
      data: { code, code_verifier: verifier, redirect_url: redirectUrl },
    })
    expect(replay.status(), 'replayed code must be rejected').not.toBe(200)
  })

  test('a code cannot be exchanged with the wrong PKCE verifier', async ({ page }) => {
    const t = seedTenant()
    const { challenge } = pkcePair()
    const redirectUrl = 'http://127.0.0.1:5173/'

    await page.goto(authorizeURL({ productId: t.productId, redirectUrl, challenge, state: 'st-pkce' }))
    await page.locator('#email').fill(t.email)
    await page.locator('#password').fill(t.password)
    await page.getByRole('button', { name: /sign in/i }).click()
    await page.waitForURL(/[?&]code=/, { timeout: 15_000 })

    const code = new URL(page.url()).searchParams.get('code')
    const res = await page.request.post('/auth/token', {
      data: { code, code_verifier: base64url(randomBytes(48)), redirect_url: redirectUrl },
    })
    expect(res.status(), 'a stolen code alone must be useless').not.toBe(200)
  })
})

test.describe('admin portal', () => {
  test('redirects an unauthenticated visitor away from the admin area', async ({ page }) => {
    await page.goto('/admin/users')
    // ProtectedRoute sends unauthenticated users to the informational login page.
    await expect(page.getByText(/sign in through your product/i)).toBeVisible({ timeout: 15_000 })
  })

  test('lists the tenant\'s users', async ({ page }) => {
    const t = seedTenant()
    await login(page, t)

    await page.goto('/admin/users')
    // .first() because the address legitimately appears twice: once in the layout
    // header (we are signed in AS this user) and once in the list row. Playwright
    // strict mode rejects an ambiguous locator, and asserting on the first visible
    // occurrence is what the test actually cares about.
    await expect(page.getByText(t.email).first()).toBeVisible({ timeout: 15_000 })
  })

  test('creates an invitation and stores only its hash', async ({ page }) => {
    const t = seedTenant()
    const { body } = await login(page, t)
    const invitee = `invitee-${suffix()}@e2e.test`

    // Exercised through the API with the browser's own token: the invite UI
    // varies, but the contract the SPA depends on is what must hold.
    const res = await page.request.post('/admin/invitations', {
      headers: { Authorization: `Bearer ${body.access_token}` },
      data: { email: invitee },
    })
    expect(res.status()).toBe(201)
    const created = await res.json()
    expect(created.invite_url, 'invite_url is required when SMTP is unconfigured').toBeTruthy()

    // The raw token must never be persisted — only its SHA-256.
    const rawToken = created.invite_url.split('=').pop()
    const stored = query(
      `SELECT token_hash FROM tbl_invitations WHERE lower(email)='${invitee.toLowerCase()}'`)
    expect(stored).toHaveLength(64)
    expect(stored).not.toBe(rawToken)

    // And it shows up in the list the UI renders.
    await page.goto('/admin/invitations')
    await expect(page.getByText(invitee)).toBeVisible({ timeout: 15_000 })
  })

  test('session list never exposes token material', async ({ page }) => {
    const t = seedTenant()
    const { body } = await login(page, t)

    const res = await page.request.get('/admin/sessions', {
      headers: { Authorization: `Bearer ${body.access_token}` },
    })
    expect(res.status()).toBe(200)
    const text = await res.text()
    for (const leak of ['refresh_token_hash', 'prev_token_hash', 'revoked_reason', 'user_id']) {
      expect(text, `session list must not expose ${leak}`).not.toContain(leak)
    }
  })

  test('logging out kills the session', async ({ page }) => {
    const t = seedTenant()
    await login(page, t)

    expect((await page.request.post('/auth/refresh')).status()).toBe(200)
    expect((await page.request.post('/auth/logout')).status()).toBe(204)
    // The rotated cookie is now revoked, so a further refresh must fail.
    expect((await page.request.post('/auth/refresh')).status()).toBe(401)
  })
})
