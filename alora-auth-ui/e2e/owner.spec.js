import { test, expect } from '@playwright/test'
import { owner, PASSWORD, seedCompany, suffix } from './seed.js'
import { freePort, startProduct } from './product.js'
import { startIdP } from './idp.js'
import { apiClient, bearer, newMember, signIn, signedIn, tokenFor } from './helpers.js'

// The platform Owner: the one role above every company's Admins. It decides,
// for each company, how people sign in, which groups exist and what they
// grant, and which products the company may use.

const INVALID = 'Invalid email or password.'

async function asOwner(page) {
  const o = owner()
  await signedIn(page, o.email, o.password)
}

const basicAuth = (id, secret) =>
  'Basic ' + Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')

test.describe('the Owner console', () => {
  test('is refused to a company Admin, in the UI and by the API', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    await signedIn(page, t.email, t.password)
    await expect(page.getByRole('link', { name: 'Owner', exact: true })).toHaveCount(0)
    await page.goto('/owner')
    await expect(page.getByTestId('not-allowed')).toBeVisible()

    const api = await apiClient()
    const token = await tokenFor(api, t.email, t.password)
    for (const path of ['/api/owner/companies', '/api/owner/products', `/api/owner/companies/${t.companyId}`]) {
      expect((await api.get(path, bearer(token))).status(), path).toBe(403)
    }
    await api.dispose()
  })

  test('sets a company up end to end — subscription, a group that opens a product, an invitation — and the invitee launches it', async ({ page, browser }) => {
    const t = seedCompany({ productPort: await freePort() })
    const product = await startProduct(t)
    try {
      await asOwner(page)
      await page.getByRole('link', { name: 'Owner', exact: true }).click()

      const name = `Owner Co ${suffix()}`
      await page.locator('#company-name').fill(name)
      await page.getByRole('button', { name: 'Create company' }).click()
      await expect(page.getByRole('heading', { name })).toBeVisible()
      const cid = new URL(page.url()).pathname.split('/').pop()

      // A new company starts with its Admins group and a default login policy.
      await page.getByRole('link', { name: 'Groups', exact: true }).click()
      await expect(page.getByTestId('group-row').filter({ hasText: 'Admins' })).toContainText('System')
      await page.getByRole('link', { name: 'Login policies' }).click()
      await expect(page.getByTestId('policy-row').filter({ hasText: 'Default' })).toHaveCount(1)

      await page.getByRole('link', { name: 'Subscriptions' }).click()
      const sub = page.getByTestId(`subscription-${t.productKey}`)
      await sub.getByRole('button', { name: 'Subscribe' }).click()
      await expect(sub).toContainText('Subscribed')

      await page.getByRole('link', { name: 'Groups', exact: true }).click()
      await page.locator('#group-name').fill('Staff')
      await page.getByRole('button', { name: 'Create group' }).click()
      await expect(page.getByRole('heading', { name: 'Staff' })).toBeVisible()
      const apps = page.getByRole('region', { name: 'Opens these apps' })
      await apps.locator('#group-grant-product').selectOption({ label: t.productName })
      await apps.locator('#group-grant-role').selectOption('Viewer')
      await apps.getByRole('button', { name: 'Add', exact: true }).click()
      await apps.getByRole('button', { name: 'Save apps' }).click()
      await expect(apps.getByTestId('grant-row')).toContainText('Viewer')
      await expect(apps.getByRole('button', { name: 'Save apps' })).toBeDisabled()

      await page.getByRole('link', { name: 'Invitations' }).click()
      const email = `staff-${suffix()}@e2e.test`
      await page.locator('#invite-email').fill(email)
      await page.getByLabel('Staff').check()
      await page.getByRole('button', { name: 'Send invitation' }).click()
      const inviteURL = await page.getByTestId('invite-url').getAttribute('href')

      const ctx = await browser.newContext()
      const p = await ctx.newPage()
      await p.goto(inviteURL)
      await expect(p.getByText(`You have been invited to ${name}`)).toBeVisible()
      await expect(p.getByText('Staff', { exact: true })).toBeVisible()
      await p.locator('#password').fill(PASSWORD)
      await p.locator('#password2').fill(PASSWORD)
      await p.getByRole('button', { name: 'Create account' }).click()
      await p.getByRole('link', { name: 'Go to sign-in →' }).click()
      await signIn(p, email, PASSWORD, { path: null })
      await expect(p.getByTestId('me-company')).toHaveText(name)

      await p.getByRole('link', { name: `Open ${t.productName}` }).click()
      await p.waitForURL(`${product.origin}/`)
      await expect(p.getByTestId('who')).toHaveText(email)
      await expect(p.getByTestId('roles')).toHaveText('Viewer')
      await expect(p.getByTestId('tenant')).toHaveText(cid)
      await ctx.close()
    } finally {
      product.stop()
    }
  })

  test('registers a product whose secret is shown exactly once, and rotation retires the old secret', async ({ page }) => {
    await asOwner(page)
    await page.goto('/owner/products')
    const key = `REG-${suffix()}`
    await page.locator('#product-key').fill(key)
    await page.locator('#product-name').fill(`Registered ${key}`)
    await page.locator('#product-base-url').fill('http://127.0.0.1:9/')
    await page.locator('#product-initiate').fill('http://127.0.0.1:9/login/initiate')
    await page.getByRole('button', { name: 'Register product' }).click()
    await expect(page.getByRole('heading', { name: `Registered ${key}` })).toBeVisible()
    const clientId = (await page.getByTestId('client-id').textContent()).trim()

    await page.locator('#redirect-uris').fill('http://127.0.0.1:9/callback')
    await page.getByRole('button', { name: 'Save redirect URIs' }).click()
    await expect(page.locator('#redirect-uris')).toHaveValue('http://127.0.0.1:9/callback')
    await page.locator('#product-roles').fill('Reader\nWriter')
    await page.getByRole('button', { name: 'Save roles' }).click()
    await expect(page.locator('#product-roles')).toHaveValue('Reader\nWriter')

    await page.getByRole('button', { name: 'Issue secret' }).click()
    const secret = (await page.getByTestId('client-secret').textContent()).trim()
    expect(secret).toMatch(/^acs_/)

    const api = await apiClient()
    const introspect = s => api.post('/oauth/introspect', { form: { token: 'not-a-token' }, headers: { Authorization: basicAuth(clientId, s) } })
    const ok = await introspect(secret)
    expect(ok.status(), 'the secret authenticates the product').toBe(200)
    expect((await ok.json()).active).toBe(false)
    expect((await introspect(`${secret}x`)).status(), 'a wrong secret does not').toBe(401)

    // Never shown again: the API keeps only its hash.
    await page.reload()
    await expect(page.getByTestId('client-secret')).toHaveCount(0)
    expect(await page.content()).not.toContain(secret)
    const product = await (await api.get(`/api/owner/products/${clientId}`, bearer(await tokenFor(api, owner().email, owner().password)))).json()
    expect(product.has_secret).toBe(true)
    expect(JSON.stringify(product)).not.toContain(secret)

    page.once('dialog', d => d.accept())
    await page.getByRole('button', { name: 'Rotate secret' }).click()
    const rotated = (await page.getByTestId('client-secret').textContent()).trim()
    expect(rotated).not.toBe(secret)
    expect((await introspect(secret)).status(), 'the old secret stops working at once').toBe(401)
    expect((await introspect(rotated)).status()).toBe(200)
    await api.dispose()
  })

  test('refuses a write that does not repeat the company it targets', async () => {
    const t = seedCompany({ productPort: 9 })
    const other = seedCompany({ productPort: 9 })
    const api = await apiClient()
    const token = await tokenFor(api, owner().email, owner().password)
    const path = `/api/owner/companies/${t.companyId}`
    const patch = headers => api.patch(path, { data: { name: `Renamed ${suffix()}` }, headers: { Authorization: `Bearer ${token}`, ...headers } })

    expect((await patch({})).status(), 'no target header').toBe(400)
    expect((await patch({ 'X-Alora-Target-Company': other.companyId })).status(), 'another company in the header').toBe(400)
    expect((await patch({ 'X-Alora-Target-Company': t.companyId })).status(), 'the right company').toBe(200)
    await api.dispose()
  })

  test('refuses to suspend or deactivate the platform company', async ({ page }) => {
    const api = await apiClient()
    const token = await tokenFor(api, owner().email, owner().password)
    const companies = await (await api.get('/api/owner/companies', bearer(token))).json()
    const platform = companies.find(c => c.is_platform)
    expect(platform, 'the platform company is listed').toBeTruthy()
    const res = await api.patch(`/api/owner/companies/${platform.id}`, {
      data: { is_active: false },
      headers: { Authorization: `Bearer ${token}`, 'X-Alora-Target-Company': platform.id },
    })
    expect(res.status()).toBeGreaterThanOrEqual(400)
    expect(res.status()).toBeLessThan(500)
    await api.dispose()

    // The console does not offer it either.
    await asOwner(page)
    await page.goto(`/owner/companies/${platform.id}`)
    await expect(page.locator('#co-active')).toBeDisabled()
    await expect(page.locator('#co-status')).toBeDisabled()
  })

  test('grants a user a product directly, and deactivating them ends their session', async ({ page, browser }) => {
    const t = seedCompany({ productPort: 9 })
    const member = await newMember(t)
    const ctx = await browser.newContext()
    const m = await ctx.newPage()
    await signedIn(m, member.email, member.password)
    await expect(m.getByText("You don't have access to any app yet.")).toBeVisible()

    await asOwner(page)
    await page.goto(`/owner/companies/${t.companyId}/users`)
    await page.getByRole('link', { name: member.email }).click()
    const grants = page.getByRole('region', { name: 'Direct grants' })
    await grants.locator('#grant-product').selectOption({ label: t.productName })
    await grants.locator('#grant-role').selectOption('Editor')
    await grants.getByRole('button', { name: 'Grant' }).click()
    await expect(grants.getByRole('cell', { name: 'Editor' })).toBeVisible()
    await expect(page.getByRole('region', { name: 'App access' })).toContainText('Directly')

    // The member's launcher shows it at the next load.
    await m.reload()
    await expect(m.getByTestId(`app-${t.productKey}`)).toContainText('Editor')

    await page.getByRole('button', { name: 'Deactivate' }).click()
    await expect(page.getByText('Inactive', { exact: true })).toBeVisible()
    await m.reload()
    await expect(m).toHaveURL(/\/login/)
    await signIn(m, member.email, member.password)
    await expect(m.getByRole('alert')).toHaveText(INVALID)
    await ctx.close()
  })

  test('will not deactivate a company’s last active Admin', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    await asOwner(page)
    await page.goto(`/owner/companies/${t.companyId}/users`)
    await page.getByRole('link', { name: t.email }).click()
    await page.getByRole('button', { name: 'Deactivate' }).click()
    await expect(page.getByRole('alert')).toContainText("Cannot deactivate the company's last active Admin")
    await expect(page.getByText('Active', { exact: true })).toBeVisible()
  })
})

test.describe('login policies', () => {
  test('a policy that disallows passwords refuses them and ends the sessions it no longer allows', async ({ page, browser }) => {
    const t = seedCompany({ productPort: 9 })
    const adminCtx = await browser.newContext()
    const admin = await adminCtx.newPage()
    await signedIn(admin, t.email, t.password)

    await asOwner(page)
    await page.goto(`/owner/companies/${t.companyId}/policies`)
    const row = page.getByTestId('policy-row').filter({ hasText: 'Default' })
    await row.getByRole('button', { name: 'Edit' }).click()
    await page.locator('#policy-password').uncheck()
    await page.locator('#policy-google').check()
    await page.getByRole('button', { name: 'Save policy' }).click()
    await expect(row).toContainText('Google')
    await expect(row).not.toContainText('Password')

    // The right password no longer opens the account — with the same generic answer.
    const ctx = await browser.newContext()
    const p = await ctx.newPage()
    await signIn(p, t.email, t.password)
    await expect(p.getByRole('alert')).toHaveText(INVALID)

    // The session that signed in with a password ends at its next refresh.
    await admin.reload()
    await expect(admin).toHaveURL(/\/login/)

    await row.getByRole('button', { name: 'Edit' }).click()
    await page.locator('#policy-password').check()
    await page.getByRole('button', { name: 'Save policy' }).click()
    await expect(row).toContainText('Password')
    await signIn(p, t.email, t.password)
    await expect(p.getByTestId('me-email')).toHaveText(t.email)
    await ctx.close()
    await adminCtx.close()
  })
})

test.describe.serial('company single sign-on', () => {
  const clientId = 'e2e-app'
  const clientSecret = `idp-secret-${suffix()}`
  const domain = `sso-${suffix()}.e2e.test`
  let idp
  let t

  test.beforeAll(async () => {
    idp = await startIdP({ clientId, clientSecret })
    t = seedCompany({ email: `pat@${domain}`, productPort: 9 })
  })
  test.afterAll(() => idp?.stop())

  test('an Owner connects the company’s identity provider, and the connection tests good', async ({ page }) => {
    await asOwner(page)
    await page.goto(`/owner/companies/${t.companyId}/sso`)
    await page.getByRole('button', { name: 'New connection' }).click()
    await page.locator('#sso-name').fill('Stub IdP')
    await page.locator('#sso-issuer').fill(idp.issuer)
    await page.locator('#sso-client-id').fill(clientId)
    await page.locator('#sso-client-secret').fill(clientSecret)
    await page.locator('#sso-domains').fill(domain)
    await page.getByRole('button', { name: 'Save connection' }).click()

    const row = page.getByTestId('sso-row').filter({ hasText: 'Stub IdP' })
    await expect(row).toContainText(domain)
    await expect(row).toContainText('Active')
    expect(await page.content(), 'the secret is never shown back').not.toContain(clientSecret)
    await row.getByRole('button', { name: 'Test' }).click()
    await expect(page.getByRole('status')).toContainText(`issuer ${idp.issuer}`)
  })

  test('a connection whose provider does not answer fails its test', async ({ page }) => {
    await asOwner(page)
    await page.goto(`/owner/companies/${t.companyId}/sso`)
    await page.getByRole('button', { name: 'New connection' }).click()
    await page.locator('#sso-name').fill('Nobody home')
    await page.locator('#sso-issuer').fill(`http://127.0.0.1:${await freePort()}`)
    await page.locator('#sso-client-id').fill('x')
    await page.locator('#sso-client-secret').fill('y')
    await page.getByRole('button', { name: 'Save connection' }).click()
    const row = page.getByTestId('sso-row').filter({ hasText: 'Nobody home' })
    await row.getByRole('button', { name: 'Test' }).click()
    await expect(page.getByRole('alert')).toBeVisible()
  })

  test('the Owner makes single sign-on the only way in', async ({ page }) => {
    await asOwner(page)
    await page.goto(`/owner/companies/${t.companyId}/policies`)
    const row = page.getByTestId('policy-row').filter({ hasText: 'Default' })
    await row.getByRole('button', { name: 'Edit' }).click()
    await page.locator('#policy-password').uncheck()
    await page.locator('#policy-sso').selectOption({ label: 'Stub IdP' })
    await page.getByRole('button', { name: 'Save policy' }).click()
    await expect(row).toContainText('Stub IdP')
    await expect(row).not.toContainText('Password')
  })

  test('the login page offers only single sign-on at that domain, and a password is refused', async ({ page }) => {
    await page.goto('/login')
    await page.locator('#email').fill(t.email)
    await page.getByRole('button', { name: 'Continue' }).click()
    await expect(page.getByRole('button', { name: 'Continue with single sign-on' })).toBeVisible()
    await expect(page.locator('#password')).toHaveCount(0)

    const api = await apiClient()
    const res = await api.post('/auth/login/password', { data: { email: t.email, password: t.password } })
    expect(res.status(), 'the right password, on an SSO-only account').toBe(401)
    await api.dispose()
  })

  test('an address the provider has not verified is refused', async ({ page }) => {
    idp.signInAs({ sub: 'pat-unverified', email: t.email, email_verified: false })
    await page.goto('/login')
    await page.locator('#email').fill(t.email)
    await page.getByRole('button', { name: 'Continue' }).click()
    await page.getByRole('button', { name: 'Continue with single sign-on' }).click()
    await expect(page).toHaveURL(/\/login\?sso_error=email_unverified$/)
    await expect(page.getByRole('alert')).toHaveText('Your address is not verified with your identity provider. Verify it, then try again.')
  })

  test('an address with no account here is refused — SSO never creates accounts', async ({ page }) => {
    idp.signInAs({ sub: 'stranger', email: `stranger@${domain}` })
    await page.goto('/login')
    await page.locator('#email').fill(`stranger@${domain}`)
    await page.getByRole('button', { name: 'Continue' }).click()
    await page.getByRole('button', { name: 'Continue with single sign-on' }).click()
    await expect(page).toHaveURL(/\/login\?sso_error=account_unavailable$/)
  })

  test('single sign-on signs the user in, and the identity stays linked', async ({ page, context }) => {
    idp.signInAs({ sub: 'pat-1', email: t.email })
    await page.goto('/login')
    await page.locator('#email').fill(t.email)
    await page.getByRole('button', { name: 'Continue' }).click()
    await page.getByRole('button', { name: 'Continue with single sign-on' }).click()
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
    expect(new URL(page.url()).pathname).toBe('/')

    // Signed out and back in: the provider now says only who (the subject);
    // the link made on the first sign-in is what finds the account.
    await page.getByRole('button', { name: 'Sign out' }).click()
    await context.clearCookies()
    idp.signInAs({ sub: 'pat-1', email: `renamed@${domain}` })
    await page.goto('/login')
    await page.locator('#email').fill(t.email)
    await page.getByRole('button', { name: 'Continue' }).click()
    await page.getByRole('button', { name: 'Continue with single sign-on' }).click()
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
  })
})
