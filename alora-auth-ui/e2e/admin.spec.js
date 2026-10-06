import { test, expect } from '@playwright/test'
import { owner, seedCompany, suffix } from './seed.js'
import { apiClient, bearer, companyGroup, giveExtras, newMember, signedIn, tokenFor, userId } from './helpers.js'

// A company's own administration at /admin. Every section opens with its
// feature's Read scope and its buttons with the Edit scope; a company's Admins
// hold every scope, anyone else what their groups and extras give. Two rules
// hold for everyone but the Owner: nobody gives or takes away access they do
// not hold, and nobody acts on someone with more access than they have. Which
// apps a group opens stays the Owner's (see owner.spec.js).

const RULE_ONE = 'You can only give or take away scopes you hold yourself'
const RULE_TWO = 'You can only manage people who have no more access than you'

test.describe('a company Admin', () => {
  let t

  test.beforeAll(() => {
    t = seedCompany({ productPort: 9 })
  })

  test('sees every admin section, the subscribed products and the company', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.getByRole('link', { name: 'Admin', exact: true }).click()
    await expect(page).toHaveURL(/\/admin\/users$/)
    const nav = page.getByRole('navigation', { name: 'Admin' })
    for (const section of ['Users', 'Groups', 'Invitations', 'Sessions', 'Products', 'Company']) {
      await expect(nav.getByRole('link', { name: section })).toBeVisible()
    }
    await nav.getByRole('link', { name: 'Products' }).click()
    await expect(page.getByRole('cell', { name: new RegExp(t.productName) })).toBeVisible()
    await nav.getByRole('link', { name: 'Company' }).click()
    await expect(page.getByTestId('company-name')).toHaveText(t.company)
  })

  test('adds a member to a group and removes them — but not the last Admin', async ({ page }) => {
    const member = await newMember(t)
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/groups')
    await page.getByRole('link', { name: 'Admins' }).click()
    await expect(page.getByTestId('member-row')).toHaveCount(1)

    // The only Admin cannot be removed: the company would have none.
    await page.getByTestId('member-row').filter({ hasText: t.email }).getByRole('button', { name: 'Remove' }).click()
    await expect(page.getByRole('alert')).toBeVisible()
    await expect(page.getByTestId('member-row')).toHaveCount(1)

    await page.locator('#member-email').fill(member.email)
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(page.getByTestId('member-row')).toHaveCount(2)

    // The new Admin's next page load shows the admin area.
    const api = await apiClient()
    const token = await tokenFor(api, member.email, member.password)
    expect((await (await api.get('/api/me', bearer(token))).json()).is_admin).toBe(true)

    await page.getByTestId('member-row').filter({ hasText: member.email }).getByRole('button', { name: 'Remove' }).click()
    await expect(page.getByTestId('member-row')).toHaveCount(1)
    expect((await (await api.get('/api/me', bearer(token))).json()).is_admin, 'loses Admin at once, on the same token').toBe(false)
    expect((await api.get('/api/admin/users', bearer(token))).status()).toBe(403)
    await api.dispose()
  })

  test('creates a group and chooses what it may do — but not which apps it opens', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/groups')
    const name = `Support ${suffix()}`
    await page.locator('#group-name').fill(name)
    await page.getByRole('button', { name: 'Create group' }).click()
    await expect(page.getByRole('heading', { name })).toBeVisible()
    await page.getByRole('radio', { name: 'Sessions: Edit' }).check()
    await page.getByRole('button', { name: 'Save access' }).click()
    await expect(page.getByRole('button', { name: 'Save access' })).toBeDisabled()
    await expect(page.getByTestId('scope-row-sessions')).toHaveAttribute('data-level', 'edit')
    // Which apps it opens is shown, and is the Owner's to change.
    await expect(page.getByRole('region', { name: 'Opens these apps' })).toContainText('No apps.')
    await expect(page.getByRole('button', { name: 'Save apps' })).toHaveCount(0)

    const api = await apiClient()
    const token = await tokenFor(api, t.email, t.password)
    const g = (await (await api.get('/api/admin/groups', bearer(token))).json()).find(x => x.name === name)
    expect(g.scopes).toEqual(['sessions:edit', 'sessions:read'])
    const grants = await api.put(`/api/admin/groups/${g.id}/product-grants`, { data: { product_grants: [] }, ...bearer(token) })
    expect([404, 405]).toContain(grants.status())
    await api.dispose()
  })

  test('revokes a user’s session, and that browser is signed out', async ({ page, browser }) => {
    const member = await newMember(t)
    const ctx = await browser.newContext()
    const m = await ctx.newPage()
    await signedIn(m, member.email, member.password)

    await signedIn(page, t.email, t.password)
    await page.goto('/admin/sessions')
    const theirs = page.getByTestId('session-row').filter({ hasText: member.email })
    await expect(theirs).toHaveCount(1)
    await expect(theirs).toContainText('App Central')
    await theirs.getByRole('button', { name: 'Revoke' }).click()
    await expect(theirs).toHaveCount(0)

    await m.reload()
    await expect(m).toHaveURL(/\/login/)
    // The Admin's own session is untouched.
    await page.reload()
    await expect(page.getByTestId('me-email')).toHaveText(t.email)
    await ctx.close()
  })

  test('renames the company, and the header follows', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/company')
    const name = `Renamed ${suffix()}`
    await page.locator('#company-name-input').fill(name)
    await page.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByTestId('company-name')).toHaveText(name)
    await expect(page.getByTestId('me-company')).toHaveText(name)
    t.company = name
  })
})

test.describe('a delegated user', () => {
  test('with users:read sees people but nothing that changes them, and the API holds the same line', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const member = await newMember(t, { groupIds: [await companyGroup(t, 'Viewers', ['users:read'])] })
    const other = await newMember(t)

    await signedIn(page, member.email, member.password)
    await page.getByRole('link', { name: 'Admin', exact: true }).click()
    const nav = page.getByRole('navigation', { name: 'Admin' })
    await expect(nav.getByRole('link')).toHaveText(['Users'])
    const row = page.getByTestId('user-row').filter({ hasText: other.email })
    await expect(row).toBeVisible()
    await expect(row.getByRole('button')).toHaveCount(0)
    await row.getByRole('link', { name: other.email }).click()
    await expect(page.getByTestId('scope-grid')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Deactivate' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Reset password' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Save extra access' })).toHaveCount(0)
    await page.goto('/admin/sessions')
    await expect(page.getByTestId('not-allowed')).toBeVisible()

    const api = await apiClient()
    const token = await tokenFor(api, member.email, member.password)
    expect((await api.get('/api/admin/users', bearer(token))).status()).toBe(200)
    expect((await api.get('/api/admin/sessions', bearer(token))).status()).toBe(403)
    const id = await userId(api, token, other.email)
    expect((await api.patch(`/api/admin/users/${id}`, { data: { is_active: false }, ...bearer(token) })).status()).toBe(403)
    expect((await api.post(`/api/admin/users/${id}/password-reset`, bearer(token))).status()).toBe(403)
    expect((await api.put(`/api/admin/users/${id}/scopes`, { data: { scopes: [] }, ...bearer(token) })).status()).toBe(403)
    await api.dispose()
  })

  test('with users:edit resets a member’s password — never an Admin’s', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const member = await newMember(t, { groupIds: [await companyGroup(t, 'Helpdesk', ['users:edit'])] })
    const other = await newMember(t)

    await signedIn(page, member.email, member.password)
    await page.goto('/admin/users')
    await page.getByTestId('user-row').filter({ hasText: other.email }).getByRole('button', { name: 'Reset password' }).click()
    await expect(page.getByTestId('reset-url')).toBeVisible()

    // An Admin has more access: their page offers nothing to press.
    await page.getByTestId('user-row').filter({ hasText: t.email }).getByRole('link', { name: t.email }).click()
    await expect(page.getByText('They have access you don’t hold')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Reset password' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Deactivate' })).toHaveCount(0)

    const api = await apiClient()
    const token = await tokenFor(api, member.email, member.password)
    const res = await api.post(`/api/admin/users/${t.adminId}/password-reset`, bearer(token))
    expect(res.status()).toBe(403)
    expect((await res.json()).error).toBe(RULE_TWO)
    await api.dispose()
  })

  test('with groups:edit creates a group, but can only give it access they hold', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const d = await newMember(t, { groupIds: [await companyGroup(t, 'Organisers', ['groups:edit', 'users:read'])] })

    await signedIn(page, d.email, d.password)
    await page.goto('/admin/groups')
    const name = `Readers ${suffix()}`
    await page.locator('#group-name').fill(name)
    await page.getByRole('button', { name: 'Create group' }).click()
    await expect(page.getByRole('heading', { name })).toBeVisible()
    await expect(page.getByRole('radio', { name: 'Users: Read' })).toBeEnabled()
    await expect(page.getByRole('radio', { name: 'Users: Edit' })).toBeDisabled()
    await expect(page.getByRole('radio', { name: 'Sessions: Read' })).toBeDisabled()
    await page.getByRole('radio', { name: 'Users: Read' }).check()
    await page.getByRole('button', { name: 'Save access' }).click()
    await expect(page.getByRole('button', { name: 'Save access' })).toBeDisabled()
    await expect(page.getByTestId('scope-row-users')).toHaveAttribute('data-level', 'read')

    // The API holds the same line — for a scope they lack, and for the Admins
    // group, which holds every scope.
    const api = await apiClient()
    const token = await tokenFor(api, d.email, d.password)
    const gid = new URL(page.url()).pathname.split('/').pop()
    const res = await api.put(`/api/admin/groups/${gid}/scopes`, { data: { scopes: ['users:read', 'sessions:read'] }, ...bearer(token) })
    expect(res.status()).toBe(403)
    expect((await res.json()).error).toBe(RULE_ONE)
    const admins = (await (await api.get('/api/admin/groups', bearer(token))).json()).find(g => g.system_key === 'ADMINS')
    const join = await api.post(`/api/admin/groups/${admins.id}/members`, { data: { email: d.email }, ...bearer(token) })
    expect(join.status()).toBe(403)
    expect((await join.json()).error).toBe(RULE_ONE)
    await api.dispose()
  })

  test('loses the section as soon as they leave the group', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const member = await newMember(t)
    const groupId = await companyGroup(t, 'Viewers', ['users:read'])
    const api = await apiClient()
    const adminToken = await tokenFor(api, t.email, t.password)
    expect((await api.post(`/api/admin/groups/${groupId}/members`, { data: { email: member.email }, ...bearer(adminToken) })).status()).toBe(201)

    await signedIn(page, member.email, member.password)
    await expect(page.getByRole('link', { name: 'Admin', exact: true })).toBeVisible()

    const id = await userId(api, adminToken, member.email)
    expect((await api.delete(`/api/admin/groups/${groupId}/members/${id}`, bearer(adminToken))).status()).toBe(204)
    await api.dispose()

    await page.reload()
    await expect(page.getByTestId('me-email')).toHaveText(member.email) // still signed in…
    await expect(page.getByRole('link', { name: 'Admin', exact: true })).toHaveCount(0) // …without the section
    await page.goto('/admin/users')
    await expect(page.getByTestId('not-allowed')).toBeVisible()
  })
})

test.describe('your access', () => {
  test('Profile shows each person what they may do, where it comes from, and what their token says', async ({ browser }) => {
    const t = seedCompany({ productPort: 9 })
    const helpdesk = await companyGroup(t, 'Helpdesk', ['users:read'])
    const delegate = await newMember(t, { groupIds: [helpdesk] })
    await giveExtras(t, delegate.email, ['sessions:edit'])
    const plain = await newMember(t)

    async function profileOf(who) {
      const ctx = await browser.newContext()
      const page = await ctx.newPage()
      await signedIn(page, who.email, who.password)
      await page.getByRole('link', { name: 'Profile', exact: true }).click()
      await expect(page.getByTestId('scope-grid')).toBeVisible()
      return { page, ctx }
    }
    const level = (page, feature) => page.getByTestId(`scope-row-${feature}`)

    // An Admin: every feature, from the Admins group; the app the Admins group opens.
    let { page, ctx } = await profileOf(t)
    for (const f of ['users', 'groups', 'invitations', 'sessions', 'company', 'api-clients']) {
      await expect(level(page, f)).toHaveAttribute('data-level', 'edit')
      await expect(level(page, f)).toContainText('Admins')
    }
    await expect(level(page, 'products')).toHaveAttribute('data-level', 'read')
    await expect(page.getByTestId('my-products')).toHaveText(t.productKey)
    await expect(page.getByTestId('my-scope')).toHaveText(
      'apps:read api-clients:edit api-clients:read company:edit company:read groups:edit groups:read ' +
      'invitations:edit invitations:read products:read sessions:edit sessions:read users:edit users:read')
    await ctx.close();

    // A delegate: Read on users from their group, Edit on sessions as an extra.
    ({ page, ctx } = await profileOf(delegate))
    await expect(level(page, 'users')).toHaveAttribute('data-level', 'read')
    await expect(level(page, 'users')).toContainText('Helpdesk')
    await expect(level(page, 'sessions')).toHaveAttribute('data-level', 'edit')
    await expect(level(page, 'sessions')).toContainText('Extra access')
    await expect(level(page, 'groups')).toHaveAttribute('data-level', 'none')
    await expect(page.getByTestId('my-scope')).toHaveText('apps:read sessions:edit sessions:read users:read')
    await expect(page.getByTestId('my-products')).toHaveCount(0)
    await ctx.close();

    // A member: signing in, and nothing more.
    ({ page, ctx } = await profileOf(plain))
    for (const f of ['users', 'groups', 'invitations', 'sessions', 'products', 'company', 'api-clients']) {
      await expect(level(page, f)).toHaveAttribute('data-level', 'none')
    }
    await expect(page.getByTestId('my-scope')).toHaveText('apps:read')
    await ctx.close();

    // The Owner: every scope, and `owner`.
    ({ page, ctx } = await profileOf(owner()))
    await expect(page.getByText('You manage every company')).toBeVisible()
    await expect(level(page, 'users')).toHaveAttribute('data-level', 'edit')
    await expect(page.getByTestId('my-scope')).toHaveText(/ owner$/)
    await ctx.close()
  })

  test('access given while someone is working shows up in their open page, without a reload', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const m = await newMember(t)
    await signedIn(page, m.email, m.password)
    await page.getByRole('link', { name: 'Profile', exact: true }).click()
    await expect(page.getByTestId('scope-row-sessions')).toHaveAttribute('data-level', 'none')
    await expect(page.getByRole('link', { name: 'Admin', exact: true })).toHaveCount(0)

    await giveExtras(t, m.email, ['sessions:read'])

    // Their next request is answered with the stale-token flag, and the page
    // renews its token and reloads who they are.
    await page.getByRole('link', { name: 'Apps', exact: true }).click()
    await expect(page.getByRole('link', { name: 'Admin', exact: true })).toBeVisible()
    await page.getByRole('link', { name: 'Profile', exact: true }).click()
    await expect(page.getByTestId('scope-row-sessions')).toHaveAttribute('data-level', 'read')
    await expect(page.getByTestId('scope-row-sessions')).toContainText('Extra access')
    await expect(page.getByTestId('my-scope')).toHaveText('apps:read sessions:read')
  })
})
