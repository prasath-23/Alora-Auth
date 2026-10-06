import { test, expect } from '@playwright/test'
import { PASSWORD, owner, seedCompany, suffix } from './seed.js'
import { apiClient, bearer, signedIn, tokenFor } from './helpers.js'

// The SPA under double clicks and late answers. A form sends once however often
// its button is pressed while it is sending; and an answer that arrives after
// the person has moved on — a page of an earlier search — never lands in what
// they see now.

test.describe('double clicks and late answers', () => {
  let t
  let api
  let admin
  const tag = suffix()

  // A member with a chosen address, made the way real members are: invited,
  // then accepting.
  const member = async email => {
    const inv = await api.post('/api/admin/invitations', { data: { email, group_ids: [] }, ...bearer(admin) })
    expect(inv.status(), await inv.text()).toBe(201)
    const token = new URL((await inv.json()).invite_url).searchParams.get('token')
    const acc = await api.post('/auth/accept-invitation', { data: { token, password: PASSWORD } })
    expect(acc.status(), await acc.text()).toBe(204)
  }

  test.beforeAll(async () => {
    test.setTimeout(240_000)
    t = seedCompany({ productPort: 9 })
    api = await apiClient()
    admin = await tokenFor(api, t.email, t.password)
    for (let i = 0; i < 30; i++) await member(`alpha-${tag}-${i}@e2e.test`)
    for (let i = 0; i < 3; i++) await member(`bravo-${tag}-${i}@e2e.test`)
  })
  test.afterAll(() => api?.dispose())

  // Holds every request matching `method url` until release() is called.
  const hold = async (page, method, url) => {
    let release
    const gate = new Promise(r => { release = r })
    const seen = []
    await page.route(url, async route => {
      if (route.request().method() !== method) return route.continue()
      seen.push(route.request().url())
      await gate
      await route.continue()
    })
    return { release, seen }
  }

  test('a form sends once, however often it is pressed while sending', async ({ browser }) => {
    test.setTimeout(180_000)
    const o = owner()
    const ownerToken = await tokenFor(api, o.email, o.password)
    const echo = { headers: { Authorization: `Bearer ${ownerToken}`, 'X-Alora-Target-Company': t.companyId } }
    const g = await api.post('/api/admin/groups', { data: { name: `Twice ${tag}` }, ...bearer(admin) })
    const gid = (await g.json()).id
    const members = async () => (await (await api.get(`/api/admin/groups/${gid}`, bearer(admin))).json())
    const cl = await api.post('/api/admin/api-clients', { data: { name: `Secrets ${tag}` }, ...bearer(admin) })
    const clientId = (await cl.json()).id
    const revokeMe = `revoke-${tag}@e2e.test`
    const inv = await api.post('/api/admin/invitations', { data: { email: revokeMe, group_ids: [] }, ...bearer(admin) })
    const invId = (await inv.json()).id
    const cases = [
      // One secret made, shown once — never a second, live and unseen.
      { who: t, path: `/admin/api-clients/${clientId}`, url: `**/api/admin/api-clients/${clientId}/secrets`, fields: {}, button: 'New secret',
        count: async () => (await (await api.get(`/api/admin/api-clients/${clientId}`, bearer(admin))).json()).live_secrets,
        shown: 'api-client-secret' },
      // One revocation, and no "Not Found" for a second.
      { who: t, path: '/admin/invitations', method: 'DELETE', url: `**/api/admin/invitations/${invId}`, fields: {},
        button: page => page.getByTestId('invitation-row').filter({ hasText: revokeMe }).getByRole('button', { name: 'Revoke' }),
        want: 0,
        count: async () => (await (await api.get('/api/admin/invitations', bearer(admin))).json())
          .filter(i => i.email === revokeMe && i.status === 'PENDING').length },
      { who: t, path: `/admin/groups/${gid}`, url: `**/api/admin/groups/${gid}/members`, fields: { 'member-email': `alpha-${tag}-0@e2e.test` },
        button: 'Add', count: async () => (await members()).members.filter(m => m.email === `alpha-${tag}-0@e2e.test`).length },
      { who: t, path: `/admin/groups/${gid}`, url: `**/api/admin/groups/${gid}/managers`, fields: { 'manager-email': `alpha-${tag}-1@e2e.test` },
        button: 'Add manager', count: async () => (await members()).managers.filter(m => m.email === `alpha-${tag}-1@e2e.test`).length },
      { who: o, path: `/owner/companies/${t.companyId}/policies`, open: 'New policy', url: '**/login-policies',
        fields: { 'policy-name': `Twice ${tag}`, 'policy-priority': '444' }, button: 'Save policy',
        count: async () => (await (await api.get(`/api/owner/companies/${t.companyId}/login-policies`, echo)).json()).filter(p => p.name === `Twice ${tag}`).length },
      { who: o, path: `/owner/companies/${t.companyId}/sso`, open: 'New connection', url: '**/sso-connections',
        fields: { 'sso-name': `Twice ${tag}`, 'sso-issuer': 'https://sso.invalid', 'sso-client-id': `twice-${tag}`, 'sso-client-secret': 's' },
        button: 'Save connection',
        count: async () => (await (await api.get(`/api/owner/companies/${t.companyId}/sso-connections`, echo)).json()).filter(c => c.name === `Twice ${tag}`).length },
      { who: t, path: '/admin/groups', url: '**/api/admin/groups', fields: { 'group-name': `Once ${tag}` }, button: 'Create group',
        count: async () => (await (await api.get('/api/admin/groups', bearer(admin))).json()).filter(g => g.name === `Once ${tag}`).length },
      { who: t, path: '/admin/api-clients', url: '**/api/admin/api-clients', fields: { 'api-client-name': `Once ${tag}` }, button: 'Create API client',
        count: async () => (await (await api.get('/api/admin/api-clients', bearer(admin))).json()).filter(c => c.name === `Once ${tag}`).length },
      { who: t, path: '/admin/invitations', url: '**/api/admin/invitations', fields: { 'invite-email': `once-${tag}@e2e.test` }, button: 'Send invitation',
        count: async () => (await (await api.get('/api/admin/invitations', bearer(admin))).json()).filter(i => i.email === `once-${tag}@e2e.test`).length },
      { who: o, path: '/owner', url: '**/api/owner/companies', fields: { 'company-name': `Once ${tag}` }, button: 'Create company',
        count: async () => {
          const tok = await tokenFor(api, o.email, o.password)
          return (await (await api.get('/api/owner/companies', bearer(tok))).json()).filter(c => c.name === `Once ${tag}`).length
        } },
      { who: o, path: '/owner/products', url: '**/api/owner/products', fields: { 'product-key': `ONCE${tag.toUpperCase()}`, 'product-name': 'Once' },
        button: 'Register product',
        count: async () => {
          const tok = await tokenFor(api, o.email, o.password)
          return (await (await api.get('/api/owner/products', bearer(tok))).json()).filter(p => p.key === `ONCE${tag.toUpperCase()}`).length
        } },
    ]
    for (const c of cases) {
      const ctx = await browser.newContext()
      const page = await ctx.newPage()
      await signedIn(page, c.who.email, c.who.password)
      await page.goto(c.path)
      if (c.open) await page.getByRole('button', { name: c.open }).click()
      for (const [id, v] of Object.entries(c.fields)) await page.locator(`#${id}`).fill(v)
      const { release, seen } = await hold(page, c.method ?? 'POST', c.url)
      const button = typeof c.button === 'function' ? c.button(page) : page.getByRole('button', { name: c.button, exact: true })
      await button.click()
      await expect.poll(() => seen.length, `${c.path}: the first press sent`).toBe(1)
      await expect(button, `${c.path}: the button while its request is out`).toBeDisabled()
      await button.click({ force: true, timeout: 2000 }).catch(() => {})
      await button.press('Enter').catch(() => {})
      release()
      await expect.poll(c.count, `${c.path}: what the presses made`).toBe(c.want ?? 1)
      expect(seen, `${c.path}: requests sent`).toHaveLength(1)
      // And nothing claims it failed: no second answer came back to refuse it.
      await page.waitForLoadState('networkidle')
      await expect(page.getByRole('alert'), `${c.path}: after one press that worked`).toHaveCount(0)
      if (c.shown) await expect(page.getByTestId(c.shown), `${c.path}: what it made, shown once`).toHaveCount(1)
      await ctx.close()
    }
  })

  test('a page of an earlier search never lands in a later one', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/users')
    const search = async q => {
      await page.getByRole('searchbox', { name: 'Search users' }).fill(q)
      await page.getByRole('button', { name: 'Search' }).click()
    }
    await search(`alpha-${tag}`)
    await expect(page.getByTestId('user-row')).toHaveCount(25)
    // The second page of alpha is asked for, and held back; meanwhile the
    // person searches for something else.
    const { release, seen } = await hold(page, 'GET', '**/api/admin/users?*cursor=*')
    await page.getByRole('button', { name: 'Load more' }).click()
    await expect.poll(() => seen.length).toBe(1)
    await search(`bravo-${tag}`)
    await expect(page.getByTestId('user-row')).toHaveCount(3)
    release()
    // The late alpha page arrives: it must not join the bravo list.
    await page.waitForLoadState('networkidle')
    await expect(page.getByTestId('user-row')).toHaveCount(3)
    await expect(page.getByTestId('user-row').filter({ hasText: `alpha-${tag}` })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Load more' })).toHaveCount(0)

    // Without interference, Load more walks the whole alpha list, each once.
    await page.unroute('**/api/admin/users?*cursor=*')
    await search(`alpha-${tag}`)
    await expect(page.getByTestId('user-row')).toHaveCount(25)
    await page.getByRole('button', { name: 'Load more' }).click()
    await expect(page.getByTestId('user-row')).toHaveCount(30)
    await expect(page.getByRole('button', { name: 'Load more' })).toHaveCount(0)
    const emails = await page.getByTestId('user-row').locator('a').allTextContents()
    expect(new Set(emails).size, 'each person once').toBe(30)
  })
})
