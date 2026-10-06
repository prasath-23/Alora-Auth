import { test, expect } from '@playwright/test'
import { owner, seedCompany, suffix } from './seed.js'
import { apiClient, bearer, newMember, signedIn, tokenFor } from './helpers.js'

// What hostile data does in the browser: nothing. Markup in a name is shown as
// the text it is, on every page that shows the name, and no script of anyone's
// runs. Every form refuses what the API refuses, in words, and saves nothing;
// and a session that is over stays over in every tab.

// markup is a name that would run script if a page rendered it as HTML.
const markup = n => `<img src=x onerror="window.__pwned='${n}'">${n}`

async function neverRuns(page) {
  expect(await page.evaluate(() => window.__pwned), 'SECURITY: a name ran as script').toBeUndefined()
}

test.describe('hostile data in the browser', () => {
  let t
  const names = {}
  const ids = {}

  test.beforeAll(async () => {
    test.setTimeout(180_000)
    t = seedCompany({ productPort: 9 })
    const tag = suffix()
    for (const k of ['group', 'client', 'company', 'product', 'policy', 'sso']) names[k] = markup(`${k}-${tag}`)
    const api = await apiClient()
    try {
      const admin = await tokenFor(api, t.email, t.password)
      const g = await api.post('/api/admin/groups', { data: { name: names.group, description: names.group }, ...bearer(admin) })
      expect(g.status(), await g.text()).toBe(201)
      ids.group = (await g.json()).id
      const c = await api.post('/api/admin/api-clients', { data: { name: names.client, description: names.client }, ...bearer(admin) })
      expect(c.status(), await c.text()).toBe(201)
      ids.client = (await c.json()).id
      const r = await api.patch('/api/admin/client', { data: { name: names.company }, ...bearer(admin) })
      expect(r.status(), await r.text()).toBe(200)
      const groups = await (await api.get('/api/admin/groups', bearer(admin))).json()
      const adminsId = groups.find(x => x.system_key === 'ADMINS').id

      const o = owner()
      const ot = await tokenFor(api, o.email, o.password)
      const echo = { headers: { Authorization: `Bearer ${ot}`, 'X-Alora-Target-Company': t.companyId } }
      const p = await api.post('/api/owner/products', {
        data: { key: `XSS${tag.toUpperCase()}`, name: names.product, description: names.product,
                base_url: 'http://127.0.0.1:9/', initiate_login_uri: 'http://127.0.0.1:9/login/initiate', is_active: true },
        ...bearer(ot),
      })
      expect(p.status(), await p.text()).toBe(201)
      ids.product = (await p.json()).id
      expect((await api.put(`/api/owner/products/${ids.product}/roles`, { data: { roles: ['Viewer'] }, ...bearer(ot) })).status()).toBe(204)
      const sub = await api.put(`/api/owner/companies/${t.companyId}/subscriptions/${ids.product}`, { data: { is_active: true }, ...echo })
      expect(sub.status(), await sub.text()).toBe(204)
      const gr = await api.put(`/api/owner/companies/${t.companyId}/groups/${adminsId}/product-grants`, {
        data: { product_grants: [{ product_id: t.productId, role_name: 'Admin' }, { product_id: ids.product, role_name: 'Viewer' }] }, ...echo,
      })
      expect(gr.status(), await gr.text()).toBe(204)
      const pol = await api.post(`/api/owner/companies/${t.companyId}/login-policies`, {
        data: { name: names.policy, allow_password: true, allow_google: false, priority: 50 }, ...echo,
      })
      expect(pol.status(), await pol.text()).toBe(201)
      const sso = await api.post(`/api/owner/companies/${t.companyId}/sso-connections`, {
        data: { name: names.sso, issuer: 'https://sso.invalid', client_id: `xss-${tag}`, client_secret: 's', is_active: true }, ...echo,
      })
      expect(sso.status(), await sso.text()).toBe(201)
    } finally {
      await api.dispose()
    }
  })

  test('markup in a name is shown as text on every page, and never runs', async ({ page, browser }) => {
    test.setTimeout(180_000)
    const dialogs = []
    page.on('dialog', d => { dialogs.push(d.message()); d.dismiss() })
    await signedIn(page, t.email, t.password)
    for (const [path, name] of [
      ['/admin/groups', names.group],
      [`/admin/groups/${ids.group}`, names.group],
      ['/admin/api-clients', names.client],
      [`/admin/api-clients/${ids.client}`, names.client],
      ['/admin/company', names.company],
      ['/admin/products', names.product],
      ['/', names.product],
      ['/profile', names.company],
    ]) {
      await page.goto(path)
      await expect(page.getByText(name).first(), `${path} shows the name as text`).toBeVisible()
      await neverRuns(page)
    }

    const o = owner()
    const op = await (await browser.newContext()).newPage()
    op.on('dialog', d => { dialogs.push(d.message()); d.dismiss() })
    await signedIn(op, o.email, o.password)
    for (const [path, name] of [
      ['/owner', names.company],
      [`/owner/companies/${t.companyId}`, names.company],
      [`/owner/companies/${t.companyId}/groups`, names.group],
      [`/owner/companies/${t.companyId}/policies`, names.policy],
      [`/owner/companies/${t.companyId}/sso`, names.sso],
      [`/owner/companies/${t.companyId}/api-clients`, names.client],
      ['/owner/products', names.product],
      [`/owner/products/${ids.product}`, names.product],
      ['/owner/credentials', names.client],
    ]) {
      await op.goto(path)
      await expect(op.getByText(name).first(), `${path} shows the name as text`).toBeVisible()
      await neverRuns(op)
    }
    expect(dialogs, 'SECURITY: a page opened a dialog').toEqual([])
  })

  test('a hostile browser identity is shown as a fixed label, never as given', async ({ page, browser }) => {
    const m = await newMember(t)
    const hostile = await browser.newContext({ userAgent: `Mozilla/5.0 ${markup('agent')} Chrome/120.0` })
    const hp = await hostile.newPage()
    await signedIn(hp, m.email, m.password)
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/sessions')
    const row = page.getByTestId('session-row').filter({ hasText: m.email })
    await expect(row).toContainText('Chrome')
    await expect(page.getByText("__pwned='agent'"), 'the agent string reached the page').toHaveCount(0)
    await neverRuns(page)
    await hostile.close()
  })

  test('every form refuses what the API refuses, in words, and saves nothing', async ({ page }) => {
    const tag = suffix()
    await signedIn(page, t.email, t.password)

    // Groups: a name taken in any case, and one past its limit, which the field
    // itself will not hold (limits.spec.js holds every such limit to the API's).
    await page.goto('/admin/groups')
    await page.locator('#group-name').fill(`Dup ${tag}`)
    await page.getByRole('button', { name: 'Create group' }).click()
    await expect(page.getByRole('heading', { name: `Dup ${tag}` })).toBeVisible()
    await page.goto('/admin/groups')
    await page.locator('#group-name').fill(`dup ${tag}`.toUpperCase())
    await page.getByRole('button', { name: 'Create group' }).click()
    await expect(page.getByRole('alert')).toContainText('A group with this name already exists')
    await page.locator('#group-name').fill('x'.repeat(101))
    await expect(page.locator('#group-name')).toHaveValue('x'.repeat(100))
    await page.goto('/admin/groups')
    await expect(page.getByTestId('group-row').filter({ hasText: new RegExp(`dup ${tag}`, 'i') })).toHaveCount(1)

    // Invitations: an existing member, a second live invitation, and an
    // address the browser itself will not send.
    const existing = await newMember(t)
    await page.goto('/admin/invitations')
    const invite = async email => {
      await page.locator('#invite-email').fill(email)
      await page.getByRole('button', { name: 'Send invitation' }).click()
    }
    await invite(existing.email)
    await expect(page.getByRole('alert')).toContainText('A user with this email already exists')
    const fresh = `fresh-${tag}@e2e.test`
    await invite(fresh)
    await expect(page.getByTestId('invite-url')).toBeVisible()
    await invite(fresh.toUpperCase())
    await expect(page.getByRole('alert')).toContainText('An invitation for this email is already pending')
    const rows = await page.getByTestId('invitation-row').count()
    await invite('not-an-email')
    await expect(page.locator('#invite-email')).toHaveJSProperty('validity.valid', false)
    await page.goto('/admin/invitations')
    await expect(page.getByTestId('invitation-row')).toHaveCount(rows)
    await expect(page.getByTestId('invitation-row').filter({ hasText: fresh })).toHaveCount(1)

    // API clients: a name taken.
    await page.goto('/admin/api-clients')
    await page.locator('#api-client-name').fill(`Svc ${tag}`)
    await page.getByRole('button', { name: 'Create API client' }).click()
    await expect(page).toHaveURL(/\/admin\/api-clients\/aci_/)
    await page.goto('/admin/api-clients')
    await page.locator('#api-client-name').fill(`svc ${tag}`)
    await page.getByRole('button', { name: 'Create API client' }).click()
    await expect(page.getByRole('alert')).toContainText('An API client with this name already exists')

    // The company: an empty name cannot be sent, and the field will not hold
    // one past its limit; the name stays.
    await page.goto('/admin/company')
    const save = page.getByRole('button', { name: 'Save' })
    await page.locator('#company-name-input').fill('   ')
    await expect(save).toBeDisabled()
    await page.locator('#company-name-input').fill('c'.repeat(201))
    await expect(page.locator('#company-name-input')).toHaveValue('c'.repeat(200))
    await page.goto('/admin/company')
    await expect(page.getByTestId('company-name')).toContainText(names.company)
  })

  test('a session that is over stays over: the back button and a second tab', async ({ context }) => {
    const m = await newMember(t)
    const one = await context.newPage()
    await signedIn(one, m.email, m.password)
    const two = await context.newPage()
    await two.goto('/profile')
    await expect(two.getByTestId('me-email')).toHaveText(m.email)

    await one.getByRole('button', { name: 'Sign out' }).click()
    await expect(one).toHaveURL(/\/login/)
    // Back: sign-in and sign-out replace their history entries, so there is no
    // signed-in page to go back to — either the login page or out of the app.
    await one.goBack()
    const url = one.url()
    if (url.startsWith('http://localhost:5173')) {
      await expect(one.locator('#email'), `back went to ${url}`).toBeVisible()
    } else {
      expect(url, 'back left App Central for somewhere unexpected').toBe('about:blank')
    }
    await expect(one.getByTestId('me-email')).toHaveCount(0)

    // The other tab still holds a token in memory; its next request is refused
    // and it signs out too.
    await two.getByRole('link', { name: 'Apps', exact: true }).click()
    await expect(two.locator('#email')).toBeVisible({ timeout: 20_000 })
    await expect(two.getByTestId('me-email')).toHaveCount(0)
  })
})
