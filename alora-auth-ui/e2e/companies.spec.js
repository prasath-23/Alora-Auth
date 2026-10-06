import { test, expect } from '@playwright/test'
import { owner, seedCompany, suffix } from './seed.js'
import { apiClient, bearer, companyAPIClient, newMember, signedIn, tokenFor, userId } from './helpers.js'

// Several companies side by side, in the browser. Each company's Admin sees
// their own people, groups, invitations, API clients and products and nothing
// of anyone else's — not in a list, not on the launcher, and not by typing
// another company's address into the bar. The Owner sees every company, each
// through its own door. (tenant_matrix_test.go holds the API to the same.)

async function seedWorld() {
  const t = seedCompany({ productPort: 9 })
  const tag = suffix()
  const api = await apiClient()
  try {
    const token = await tokenFor(api, t.email, t.password)
    const groupName = `Team ${tag}`
    const g = await api.post('/api/admin/groups', { data: { name: groupName, scopes: ['sessions:read'] }, ...bearer(token) })
    expect(g.status(), await g.text()).toBe(201)
    const pending = `pending-${tag}@e2e.test`
    const inv = await api.post('/api/admin/invitations', { data: { email: pending, group_ids: [] }, ...bearer(token) })
    expect(inv.status(), await inv.text()).toBe(201)
    const member = await newMember(t)
    const client = await companyAPIClient(t, `Client ${tag}`)
    return {
      ...t, tag, groupName, groupId: (await g.json()).id, pending, member,
      memberId: await userId(api, token, member.email), clientName: client.name, clientId: client.id,
    }
  } finally {
    await api.dispose()
  }
}

test.describe('companies side by side', () => {
  const world = []

  test.beforeAll(async () => {
    test.setTimeout(300_000)
    for (let i = 0; i < 3; i++) world.push(await seedWorld())
  })

  test('each company’s Admin sees only their own company, on every page', async ({ page }) => {
    test.setTimeout(180_000)
    for (const me of world) {
      const others = world.filter(o => o !== me)
      await signedIn(page, me.email, me.password)
      const pages = [
        { path: '/admin/users', own: me.member.email, theirs: o => [o.member.email, o.email] },
        { path: '/admin/groups', own: me.groupName, theirs: o => [o.groupName] },
        { path: '/admin/invitations', own: me.pending, theirs: o => [o.pending] },
        { path: '/admin/api-clients', own: me.clientName, theirs: o => [o.clientName] },
        { path: '/admin/products', own: me.productName, theirs: o => [o.productName] },
        { path: '/', own: me.productName, theirs: o => [o.productName] },
      ]
      for (const p of pages) {
        await page.goto(p.path)
        await expect(page.getByText(me.company, { exact: true }).first()).toBeVisible()
        await expect(page.getByText(p.own).first(), `${me.company} ${p.path}: its own`).toBeVisible()
        for (const o of others) {
          for (const x of p.theirs(o)) {
            await expect(page.getByText(x), `SECURITY: ${me.company}'s ${p.path} shows ${o.company}'s ${x}`).toHaveCount(0)
          }
        }
      }
      await page.getByRole('button', { name: 'Sign out' }).click()
      await expect(page).toHaveURL(/\/login/)
    }
  })

  test('another company’s things are not there, even by address', async ({ page }) => {
    const [me, other] = world
    await signedIn(page, me.email, me.password)
    for (const [path, secret] of [
      [`/admin/groups/${other.groupId}`, other.groupName],
      [`/admin/users/${other.memberId}`, other.member.email],
      [`/admin/api-clients/${other.clientId}`, other.clientName],
    ]) {
      await page.goto(path)
      await expect(page.getByRole('alert'), path).toContainText('Not Found')
      await expect(page.getByText(secret), `SECURITY: ${path} shows ${secret}`).toHaveCount(0)
    }
    // Not a manager of it either: the manager's door stays shut.
    await page.goto(`/admin/my-groups/${other.groupId}`)
    await expect(page.getByTestId('not-allowed')).toBeVisible()
  })

  test('the Owner sees every company, each through its own door', async ({ page }) => {
    const o = owner()
    await signedIn(page, o.email, o.password)
    await page.goto('/owner')
    for (const c of world) await expect(page.getByText(c.company, { exact: true })).toBeVisible()
    for (const c of world) {
      const others = world.filter(x => x !== c)
      for (const [tab, own, theirs] of [
        ['groups', c.groupName, x => x.groupName],
        ['users', c.member.email, x => x.member.email],
        ['api-clients', c.clientName, x => x.clientName],
        ['invitations', c.pending, x => x.pending],
      ]) {
        await page.goto(`/owner/companies/${c.companyId}/${tab}`)
        await expect(page.getByText(own).first(), `${c.company} ${tab}`).toBeVisible()
        for (const x of others) await expect(page.getByText(theirs(x)), `SECURITY: ${c.company}'s ${tab} shows another's`).toHaveCount(0)
      }
    }
    // Client credentials lists every company's API clients together.
    await page.goto('/owner/credentials')
    for (const c of world) await expect(page.getByText(c.clientName).first()).toBeVisible()
  })
})
