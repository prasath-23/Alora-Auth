import { test, expect } from '@playwright/test'
import { owner, seedCompany } from './seed.js'
import { apiClient, bearer, companyAPIClient, companyGroup, giveExtras, newMember, signedIn, tokenFor, userId } from './helpers.js'

// Every page for every role, in the browser. The navigation offers exactly the
// sections a person may open; a page they may not open says so however it is
// reached; a page shows the controls that change things only to those holding
// its edit scope; and the Owner console is the Owner's alone. The API holds the
// same lines (scopes_test.go, credentials_matrix_test.go).

// Each page, the scope that opens it and the one that shows its edit control,
// and what marks its data as loaded — an absent control means nothing until
// then.
const PAGES = [
  { path: '/admin/users', heading: 'Users', read: 'users:read', ready: page => page.getByTestId('user-row').first() },
  { path: '/admin/groups', heading: 'Groups', read: 'groups:read', edit: 'groups:edit', control: '#group-name',
    ready: page => page.getByTestId('group-row').first() },
  { path: '/admin/invitations', heading: 'Invitations', read: 'invitations:read', edit: 'invitations:edit', control: '#invite-email',
    ready: page => page.getByTestId('invitation-row').first() },
  { path: '/admin/sessions', heading: 'Sessions', read: 'sessions:read', edit: 'sessions:edit', control: 'button:has-text("Revoke")',
    ready: page => page.getByTestId('session-row').first() },
  // The Owner's own company is the platform company: its products, or none.
  { path: '/admin/products', heading: 'Products', read: 'products:read',
    ready: (page, t, role) => (role.owner ? page.getByText('No subscriptions.').or(page.getByRole('row').nth(1)) : page.getByText(t.productName).first()) },
  { path: '/admin/company', heading: 'Company', read: 'company:read', edit: 'company:edit', control: '#company-name-input',
    ready: page => page.getByTestId('company-name') },
  { path: '/admin/api-clients', heading: 'API clients', read: 'api-clients:read', edit: 'api-clients:edit', control: '#api-client-name',
    ready: page => page.getByTestId('api-client-row').first() },
]
const SECTION = {
  'users:read': 'Users', 'groups:read': 'Groups', 'invitations:read': 'Invitations', 'sessions:read': 'Sessions',
  'products:read': 'Products', 'company:read': 'Company', 'api-clients:read': 'API clients',
}
const ALL = [
  'users:read', 'users:edit', 'groups:read', 'groups:edit', 'invitations:read', 'invitations:edit', 'sessions:read',
  'sessions:edit', 'products:read', 'company:read', 'company:edit', 'api-clients:read', 'api-clients:edit',
]
// An edit scope comes with its read scope.
const withReads = scopes => [...new Set(scopes.flatMap(s => (s.endsWith(':edit') ? [s, s.replace(':edit', ':read')] : [s])))]

const ROLES = [
  { name: 'a member', scopes: [] },
  ...ALL.map(s => ({ name: `a holder of ${s}`, scopes: [s] })),
  { name: 'a group manager', scopes: [], manager: true },
  { name: 'a company Admin', scopes: ALL, admin: true },
  { name: 'the Owner', scopes: ALL, owner: true },
]

test.describe('every page for every role', () => {
  let t
  const people = {}
  let targetId

  test.beforeAll(async () => {
    // Fifteen people made through real invitations, each a password hashed
    // the slow way: longer than one test's budget.
    test.setTimeout(300_000)
    t = seedCompany({ productPort: 9 })
    const target = await newMember(t)
    const api = await apiClient()
    const adminToken = await tokenFor(api, t.email, t.password)
    targetId = await userId(api, adminToken, target.email)
    // Something on every page: a pending invitation and an API client.
    const inv = await api.post('/api/admin/invitations', { data: { email: `pending-${Date.now()}@e2e.test`, group_ids: [] }, ...bearer(adminToken) })
    expect(inv.status(), await inv.text()).toBe(201)
    await companyAPIClient(t, `Matrix client ${Date.now()}`)
    for (const r of ROLES) {
      if (r.admin) {
        people[r.name] = { email: t.email, password: t.password }
      } else if (r.owner) {
        people[r.name] = owner()
      } else {
        const m = await newMember(t)
        if (r.scopes.length) await giveExtras(t, m.email, r.scopes)
        if (r.manager) {
          const groupId = await companyGroup(t, 'Run by a manager', [])
          const token = await tokenFor(api, t.email, t.password)
          const res = await api.post(`/api/admin/groups/${groupId}/managers`, { data: { email: m.email }, ...bearer(token) })
          expect(res.status(), await res.text()).toBe(201)
        }
        people[r.name] = m
      }
    }
    await api.dispose()
  })

  for (const role of ROLES) {
    test(`${role.name} sees exactly what they may open`, async ({ page }) => {
      const held = new Set(withReads(role.scopes))
      const seesAdmin = held.size > 0 || role.manager
      await signedIn(page, people[role.name].email, people[role.name].password)
      // From here on, a page this person may open must not fail in any way.
      // (Paused only where a refusal is the answer, which the browser logs.)
      const consoleErrors = []
      let judging = true
      page.on('console', m => { if (judging && m.type() === 'error') consoleErrors.push(`${page.url()}: ${m.text()}`) })

      // The top navigation.
      await expect(page.getByRole('link', { name: 'Admin', exact: true })).toHaveCount(seesAdmin ? 1 : 0)
      await expect(page.getByRole('link', { name: 'Owner', exact: true })).toHaveCount(role.owner ? 1 : 0)

      // The Admin sidebar lists exactly the sections their scopes open.
      if (seesAdmin) {
        await page.goto('/admin')
        const nav = page.getByRole('navigation', { name: 'Admin' })
        await expect(nav).toBeVisible()
        const want = Object.entries(SECTION).filter(([s]) => held.has(s)).map(([, label]) => label)
        if (role.manager) want.push('Groups you manage')
        expect((await nav.getByRole('link').allTextContents()).sort()).toEqual(want.sort())
      }

      // Every page, reached directly: open with its read scope, controls with
      // its edit scope, and a plain refusal otherwise.
      for (const p of PAGES) {
        await page.goto(p.path)
        if (held.has(p.read)) {
          await expect(page.getByRole('heading', { name: p.heading, exact: true })).toBeVisible()
          await expect(p.ready(page, t, role).or(page.locator(p.control ?? '#never')).first()).toBeVisible()
          // Every request the page makes has answered before its errors are judged.
          await page.waitForLoadState('networkidle')
          await expect(page.getByRole('alert'), `${p.path} shows an error to ${role.name}`).toHaveCount(0)
          if (p.edit && held.has(p.edit)) {
            await expect(page.locator(p.control).first(), `${p.path}: the edit control`).toBeVisible()
            if (p.path === '/admin/invitations') {
              // Without groups:read, an inviter invites into no group, and is told so.
              await expect(page.getByTestId('invite-no-groups')).toHaveCount(held.has('groups:read') ? 0 : 1)
            }
          } else if (p.edit) {
            // Absent means something only once the page has its data.
            await expect(p.ready(page, t, role), `${p.path}: its data`).toBeVisible()
            await expect(page.locator(p.control), `${p.path}: no edit control`).toHaveCount(0)
          }
        } else {
          await expect(page.getByTestId('not-allowed'), `${p.path} for ${role.name}`).toBeVisible()
        }
      }

      // A person's page: resets and deactivation need users:edit.
      judging = !role.owner
      await page.goto(`/admin/users/${targetId}`)
      if (role.owner) {
        // The Owner's Admin area is their own company's: another company's
        // person is not there even for them. The Owner console reaches them.
        await expect(page.getByRole('alert')).toContainText('Not Found')
        await expect(page.getByRole('region', { name: /App Central access/ })).toHaveCount(0)
        judging = true
        await page.goto(`/owner/companies/${t.companyId}/users/${targetId}`)
        await expect(page.getByRole('button', { name: 'Reset password' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Deactivate' })).toBeVisible()
      } else if (held.has('users:read')) {
        await expect(page.getByRole('region', { name: /App Central access/ })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Reset password' })).toHaveCount(held.has('users:edit') ? 1 : 0)
        await expect(page.getByRole('button', { name: 'Deactivate' })).toHaveCount(held.has('users:edit') ? 1 : 0)
      } else {
        await expect(page.getByTestId('not-allowed')).toBeVisible()
      }

      // The manager's own section, and the Owner console.
      await page.goto('/admin/my-groups')
      if (role.manager) {
        await expect(page.getByRole('heading', { name: 'Groups you manage', exact: true })).toBeVisible()
      } else {
        await expect(page.getByTestId('not-allowed')).toBeVisible()
      }
      await page.goto('/owner')
      if (role.owner) {
        await expect(page.getByText('Owner console')).toBeVisible()
      } else {
        await expect(page.getByTestId('not-allowed')).toBeVisible()
      }
      expect(consoleErrors, `pages ${role.name} may open failed`).toEqual([])
    })
  }
})
