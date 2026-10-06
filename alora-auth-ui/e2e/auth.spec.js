import { test, expect } from '@playwright/test'
import { seedCompany, suffix } from './seed.js'
import { freePort, startProduct } from './product.js'
import { apiClient, bearer, newMember, pathOf, signIn, signedIn, tokenFor } from './helpers.js'

// App Central sign-in, and the launch of a product that has its own backend
// (sample-product.cjs): the whole two-step token journey in a real browser.

const INVALID = 'Invalid email or password.'

test.describe('signing in at App Central', () => {
  let t

  test.beforeAll(() => {
    t = seedCompany({ productPort: 9 }) // no product process: nothing here launches it
  })

  test('a password sign-in lands on the launcher with the apps the user may open', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    expect(pathOf(page)).toBe('/')
    await expect(page.getByTestId('me-company')).toHaveText(t.company)
    const app = page.getByTestId(`app-${t.productKey}`)
    await expect(app).toBeVisible()
    await expect(app).toContainText('Admin') // the role this user holds in it
    await expect(page.getByRole('link', { name: 'Admin' })).toBeVisible()
  })

  test('a wrong password gets the generic error and starts no session', async ({ page, context }) => {
    await signIn(page, t.email, 'not-the-password')
    await expect(page.getByRole('alert')).toHaveText(INVALID)
    expect((await context.cookies()).map(c => c.name)).not.toContain('alora_cs')
    await page.goto('/')
    await expect(page).toHaveURL(/\/login$/)
  })

  test('an address with no account gets exactly the same answer', async ({ page }) => {
    await signIn(page, `nobody-${suffix()}@e2e.test`, 'some-password-1')
    await expect(page.getByRole('alert')).toHaveText(INVALID)
  })

  test('the session lives only in an HttpOnly, host-only cookie — never in script-readable storage', async ({ page, context }) => {
    await signedIn(page, t.email, t.password)
    const cs = (await context.cookies()).find(c => c.name === 'alora_cs')
    expect(cs, 'the session cookie is set').toBeTruthy()
    expect(cs.httpOnly).toBe(true)
    expect(cs.sameSite).toBe('Lax')
    expect(cs.domain, 'host-only: no Domain attribute').toBe('localhost')
    expect(await page.evaluate(() => document.cookie)).not.toContain('alora_cs')
    const storage = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]))
    expect(storage, 'no token in web storage').not.toMatch(/eyJ/)

    // A reload has no token to read: it refreshes the cookie and carries on.
    await page.reload()
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
  })

  test('signing out ends the session: a reload goes to the login page', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.getByRole('status')).toHaveText('You have signed out.')
    await page.goto('/profile')
    await expect(page).toHaveURL(/\/login\?return_to=%2Fprofile$/)
  })

  // Every page load rotates the session cookie. Leaving a page while that
  // rotation is in flight must not strand the browser on the superseded
  // cookie — which the server would then, rightly, treat as a replay.
  test('leaving pages while their session refresh is in flight keeps the session', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    for (let i = 0; i < 6; i++) {
      const sent = page.waitForRequest(r => r.url().endsWith('/auth/central/refresh'))
      await page.goto(i % 2 ? '/' : '/profile', { waitUntil: 'commit' })
      await sent
      await page.goto('/', { waitUntil: 'commit' }) // away before it answers
    }
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
    await page.reload()
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
  })

  // Only a 401 ends a session. A server that is overloaded or failing says
  // nothing about the session, so it must never sign anybody out.
  test('a server that cannot answer a refresh signs nobody out', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    // (Persistent, not one-shot: React's development mode fetches twice.)
    await page.route('**/api/me/apps', r => r.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"Unauthorized"}' }))
    await page.route('**/auth/central/refresh', r => r.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Service Unavailable"}' }))

    // Re-open the launcher: its call "expires", and every refresh answers 503.
    await page.getByRole('link', { name: 'Profile' }).click()
    await page.getByRole('link', { name: 'Apps', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('not answering')
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
    expect(new URL(page.url()).pathname).toBe('/')

    // The server recovers: the session was never lost.
    await page.unroute('**/auth/central/refresh')
    await page.unroute('**/api/me/apps')
    await page.reload()
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
  })

  test('a page that needs a session comes back after sign-in', async ({ page }) => {
    await page.goto('/profile')
    await expect(page).toHaveURL(/\/login\?return_to=%2Fprofile$/)
    await signIn(page, t.email, t.password, { path: null })
    await expect(page).toHaveURL(/\/profile$/)
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible()
  })

  // Each of these resolves, in a browser, to somewhere other than App Central
  // (a backslash reads as a slash; a tab is stripped before parsing).
  for (const evil of ['https://evil.example/', '//evil.example/', '/\\evil.example/', '/\t/evil.example/', 'javascript:alert(1)']) {
    test(`a return_to of ${evil} is never followed`, async ({ page }) => {
      await page.goto(`/login?return_to=${encodeURIComponent(evil)}`)
      await signIn(page, t.email, t.password, { path: null })
      await expect(page.getByTestId('me-email')).toHaveText(t.email)
      const u = new URL(page.url())
      expect(u.host).toBe('localhost:5173')
      expect(u.pathname).toBe('/')
    })
  }
})

test.describe('one address with accounts in two companies', () => {
  test('the company is chosen only after the password is proven', async ({ page }) => {
    const email = `both-${suffix()}@e2e.test`
    const a = seedCompany({ email, productPort: 9 })
    const b = seedCompany({ email, productPort: 9 })

    await signIn(page, email, a.password)
    await expect(page.getByRole('heading', { name: 'Choose a company' })).toBeVisible()
    const list = page.getByRole('list', { name: 'Companies' })
    await expect(list.getByRole('button')).toHaveCount(2)
    await list.getByRole('button', { name: b.company }).click()
    await expect(page.getByTestId('me-company')).toHaveText(b.company)
  })

  test('a wrong password reveals no company', async ({ page }) => {
    const email = `both-${suffix()}@e2e.test`
    seedCompany({ email, productPort: 9 })
    seedCompany({ email, productPort: 9 })

    await signIn(page, email, 'not-the-password')
    await expect(page.getByRole('alert')).toHaveText(INVALID)
    await expect(page.getByRole('heading', { name: 'Choose a company' })).toHaveCount(0)
  })
})

test.describe('launching a product', () => {
  let t
  let product

  test.beforeAll(async () => {
    t = seedCompany({ productPort: await freePort() })
    product = await startProduct(t)
  })
  test.afterAll(() => product?.stop())

  test('opens the product signed in, with no login page, and the product verifies its own token', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    const shown = []
    page.on('framenavigated', f => { if (f === page.mainFrame()) shown.push(new URL(f.url())) })

    await page.getByRole('link', { name: `Open ${t.productName}` }).click()
    await page.waitForURL(`${product.origin}/`)

    await expect(page.getByTestId('who')).toHaveText(t.email)
    await expect(page.getByTestId('roles')).toHaveText('Admin')
    await expect(page.getByTestId('aud')).toHaveText(`product:${t.productKey}`)
    await expect(page.getByTestId('tenant')).toHaveText(t.companyId)
    await expect(page.getByTestId('id-aud')).toHaveText(t.productId)
    expect(shown.filter(u => u.pathname === '/login'), 'no login page on the way').toEqual([])
  })

  test('the product renews its token, and App Central sign-out stops that renewal', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.getByRole('link', { name: `Open ${t.productName}` }).click()
    await page.waitForURL(`${product.origin}/`)

    await page.getByRole('button', { name: 'Renew token' }).click()
    await expect(page.getByTestId('renewals')).toHaveText('1')
    await page.getByRole('button', { name: 'Renew token' }).click()
    await expect(page.getByTestId('renewals')).toHaveText('2')

    // Sign out of App Central: every product login opened under it ends too.
    await page.goto('/')
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/login$/)

    await page.goto(`${product.origin}/`)
    await page.getByRole('button', { name: 'Renew token' }).click()
    await expect(page.getByTestId('product-error')).toHaveText('invalid_grant')
    await expect(page.getByTestId('signed-out')).toBeVisible()
  })

  test('signing in at the product without a session goes through App Central and resumes', async ({ page }) => {
    await page.goto(`${product.origin}/`)
    await expect(page.getByTestId('signed-out')).toBeVisible()
    await page.getByRole('link', { name: 'Sign in with Alora' }).click()

    await expect(page).toHaveURL(/localhost:5173\/login\?return_to=%2Foauth%2Fauthorize%3F/)
    await signIn(page, t.email, t.password, { path: null })

    await page.waitForURL(`${product.origin}/`)
    await expect(page.getByTestId('who')).toHaveText(t.email)
  })

  test('signing out of the product revokes only its own login', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.getByRole('link', { name: `Open ${t.productName}` }).click()
    await page.waitForURL(`${product.origin}/`)

    await page.getByRole('button', { name: 'Sign out of this product' }).click()
    await expect(page.getByTestId('signed-out')).toBeVisible()

    // App Central is still signed in, and launching again is silent.
    await page.goto('/')
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
    await page.getByRole('link', { name: `Open ${t.productName}` }).click()
    await page.waitForURL(`${product.origin}/`)
    await expect(page.getByTestId('who')).toHaveText(t.email)
  })

  test('a user with no access to the product is refused it, and is told so by the product', async ({ page }) => {
    const member = await newMember(t) // in the company, in no group: no apps
    await signedIn(page, member.email, member.password)
    await expect(page.getByText("You don't have access to any app yet.")).toBeVisible()

    // The product asks anyway: App Central answers the product with an error,
    // never with a code.
    await page.goto(`${product.origin}/login`)
    await expect(page.getByTestId('product-error')).toHaveText('access_denied')
    expect(new URL(page.url()).pathname).toBe('/callback')
  })

  test('a launch naming another issuer is refused by the product', async ({ page }) => {
    await page.goto(`${product.origin}/login/initiate?iss=${encodeURIComponent('https://evil.example')}&target_link_uri=${encodeURIComponent(product.origin + '/')}`)
    await expect(page.getByTestId('product-error')).toHaveText('invalid_issuer')
  })
})

test.describe('a member without admin rights', () => {
  test('sees no Admin area, and the API refuses the admin endpoints', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const member = await newMember(t)

    await signedIn(page, member.email, member.password)
    await expect(page.getByRole('link', { name: 'Admin', exact: true })).toHaveCount(0)
    await expect(page.getByRole('link', { name: 'Owner', exact: true })).toHaveCount(0)
    await page.goto('/admin/users')
    await expect(page.getByTestId('not-allowed')).toBeVisible()
    await page.goto('/owner')
    await expect(page.getByTestId('not-allowed')).toBeVisible()

    const api = await apiClient()
    const token = await tokenFor(api, member.email, member.password)
    expect((await api.get('/api/admin/users', bearer(token))).status()).toBe(403)
    expect((await api.get('/api/owner/companies', bearer(token))).status()).toBe(403)
    expect((await api.get('/api/me', bearer(token))).status()).toBe(200)
    await api.dispose()
  })
})

test.describe('invitations and password resets', () => {
  let t

  test.beforeAll(() => {
    t = seedCompany({ productPort: 9 })
  })

  test('an Admin invites someone, who sets a password and signs in', async ({ page, browser }) => {
    await signedIn(page, t.email, t.password)
    await page.getByRole('link', { name: 'Admin', exact: true }).click()
    await page.getByRole('link', { name: 'Invitations' }).click()

    const email = `invitee-${suffix()}@e2e.test`
    await page.locator('#invite-email').fill(email)
    await page.getByRole('button', { name: 'Send invitation' }).click()
    const link = page.getByTestId('invite-url')
    await expect(link).toBeVisible()
    const inviteURL = await link.getAttribute('href')
    await expect(page.getByTestId('invitation-row').filter({ hasText: email })).toContainText('PENDING')

    const other = await browser.newContext()
    const invitee = await other.newPage()
    await invitee.goto(inviteURL)
    await expect(invitee.getByText(t.company)).toBeVisible()
    await invitee.locator('#password').fill('a-brand-new-passphrase')
    await invitee.locator('#password2').fill('a-brand-new-passphrase')
    await invitee.getByRole('button', { name: 'Create account' }).click()
    await expect(invitee.getByRole('status')).toContainText('Your account is ready')

    await invitee.getByRole('link', { name: 'Go to sign-in →' }).click()
    await signIn(invitee, email, 'a-brand-new-passphrase', { path: null })
    await expect(invitee.getByTestId('me-email')).toHaveText(email)

    // The link was single-use.
    await invitee.goto(inviteURL)
    await expect(invitee.getByText('This invitation is invalid, expired or already used.', { exact: false })).toBeVisible()
    await other.close()
  })

  test('a revoked invitation no longer opens', async ({ page, browser }) => {
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/invitations')
    const email = `revoked-${suffix()}@e2e.test`
    await page.locator('#invite-email').fill(email)
    await page.getByRole('button', { name: 'Send invitation' }).click()
    const inviteURL = await page.getByTestId('invite-url').getAttribute('href')
    const row = page.getByTestId('invitation-row').filter({ hasText: email })
    await row.getByRole('button', { name: 'Revoke' }).click()
    await expect(row).toContainText('REVOKED')

    const other = await browser.newContext()
    const p = await other.newPage()
    await p.goto(inviteURL)
    await expect(p.getByText('This invitation is invalid, expired or already used.', { exact: false })).toBeVisible()
    await other.close()
  })

  test('an Admin issues a reset link; the new password works and the old one no longer does', async ({ page, browser }) => {
    const member = await newMember(t)
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/users')
    await page.getByRole('searchbox', { name: 'Search users' }).fill(member.email)
    await page.getByRole('button', { name: 'Search' }).click()
    const row = page.getByTestId('user-row').filter({ hasText: member.email })
    await expect(row).toHaveCount(1)
    await row.getByRole('button', { name: 'Reset password' }).click()
    const resetURL = await page.getByTestId('reset-url').getAttribute('href')

    const other = await browser.newContext()
    const p = await other.newPage()
    await p.goto(resetURL)
    await p.locator('#new-password').fill('the-reset-passphrase')
    await p.locator('#confirm-password').fill('the-reset-passphrase')
    await p.getByRole('button', { name: 'Update password' }).click()
    await expect(p.getByRole('heading', { name: 'Password updated' })).toBeVisible()

    await signIn(p, member.email, member.password)
    await expect(p.getByRole('alert')).toHaveText(INVALID)
    await signIn(p, member.email, 'the-reset-passphrase')
    await expect(p.getByTestId('me-email')).toHaveText(member.email)

    // The reset link was single-use.
    await p.goto(resetURL)
    await p.locator('#new-password').fill('yet-another-passphrase')
    await p.locator('#confirm-password').fill('yet-another-passphrase')
    await p.getByRole('button', { name: 'Update password' }).click()
    await expect(p.getByRole('alert')).toBeVisible()
    await other.close()
  })

  test('changing your own password signs you out everywhere', async ({ page }) => {
    const member = await newMember(t)
    await signedIn(page, member.email, member.password)
    await page.goto('/profile')
    await page.locator('#current-password').fill(member.password)
    await page.locator('#new-password').fill('changed-passphrase-1')
    await page.locator('#confirm-password').fill('changed-passphrase-1')
    await page.getByRole('button', { name: 'Change password' }).click()
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.getByRole('status')).toContainText('Your password was changed')

    await signIn(page, member.email, 'changed-passphrase-1', { path: null })
    await expect(page.getByTestId('me-email')).toHaveText(member.email)
  })

  test('a wrong current password changes nothing', async ({ page }) => {
    const member = await newMember(t)
    await signedIn(page, member.email, member.password)
    await page.goto('/profile')
    await page.locator('#current-password').fill('not-my-password')
    await page.locator('#new-password').fill('changed-passphrase-2')
    await page.locator('#confirm-password').fill('changed-passphrase-2')
    await page.getByRole('button', { name: 'Change password' }).click()
    await expect(page.getByRole('alert')).toBeVisible()
    await expect(page).toHaveURL(/\/profile$/)

    await page.getByRole('button', { name: 'Sign out' }).click()
    await signIn(page, member.email, member.password, { path: null })
    await expect(page.getByTestId('me-email')).toHaveText(member.email)
  })
})
