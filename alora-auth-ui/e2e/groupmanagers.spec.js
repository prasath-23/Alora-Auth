import { test, expect } from '@playwright/test'
import { owner, seedCompany } from './seed.js'
import { apiClient, bearer, companyGroup, giveExtras, newMember, signedIn, tokenFor, userId } from './helpers.js'

// A group's managers run one group — they add and remove its members, and
// nothing else — without Groups: Edit for the whole company. An Admin or the
// Owner appoints them on the group's page; a manager works in Admin → Groups you
// manage. Rule 2 measures everyone by their reach: what they hold, plus what the
// groups they manage give.

const RULE_TWO = 'You can only manage people who have no more access than you'
const MANAGERS_SELF = "A group's managers can't add or remove themselves or each other; an Admin does that"

/** As the company's Admin, over the API: makes someone a group's manager. */
async function appoint(t, groupId, email) {
  const api = await apiClient()
  try {
    const token = await tokenFor(api, t.email, t.password)
    const res = await api.post(`/api/admin/groups/${groupId}/managers`, { data: { email }, ...bearer(token) })
    expect(res.status(), await res.text()).toBe(201)
  } finally {
    await api.dispose()
  }
}

test.describe('group managers', () => {
  let t

  test.beforeAll(() => {
    t = seedCompany({ productPort: 9 })
  })

  test('an Admin appoints a manager, who runs the group from their open page, without a reload', async ({ page, browser }) => {
    const groupId = await companyGroup(t, 'Field sales', ['sessions:read'])
    const lead = await newMember(t)
    const colleague = await newMember(t)

    // The manager-to-be is signed in, with nothing to administer.
    const leadContext = await browser.newContext()
    const lp = await leadContext.newPage()
    await signedIn(lp, lead.email, lead.password)
    await lp.getByRole('link', { name: 'Profile', exact: true }).click()
    await expect(lp.getByRole('link', { name: 'Admin', exact: true })).toHaveCount(0)

    // The Admin appoints them on the group's page.
    await signedIn(page, t.email, t.password)
    await page.goto(`/admin/groups/${groupId}`)
    const managers = page.getByRole('region', { name: /^Managers/ })
    await managers.locator('#manager-email').fill(lead.email)
    await managers.getByRole('button', { name: 'Add manager' }).click()
    const row = managers.getByTestId('manager-row')
    await expect(row).toContainText(lead.email)
    await expect(row, 'and who appointed them').toContainText(t.email)

    // The manager's next request is answered with the stale-token flag: their
    // page renews its token, and the section appears.
    await lp.getByRole('link', { name: 'Apps', exact: true }).click()
    await expect(lp.getByRole('link', { name: 'Admin', exact: true })).toBeVisible()
    await lp.getByRole('link', { name: 'Profile', exact: true }).click()
    await expect(lp.getByTestId('my-managed-groups')).toContainText('Field sales')
    await lp.getByRole('link', { name: 'Admin', exact: true }).click()
    await expect(lp).toHaveURL(/\/admin\/my-groups$/)
    await expect(lp.getByTestId('group-row')).toHaveCount(1)
    await lp.getByTestId('group-row').getByRole('link').click()
    await expect(lp.getByTestId('manager-note')).toBeVisible()

    // They add a colleague, who then has what the group gives...
    await lp.locator('#member-email').fill(colleague.email)
    await lp.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(lp.getByTestId('member-row').filter({ hasText: colleague.email })).toHaveCount(1)
    const api = await apiClient()
    const ct = await tokenFor(api, colleague.email, colleague.password)
    expect((await (await api.get('/api/me', bearer(ct))).json()).scopes).toContain('sessions:read')
    // ...and take them out again: their access came from this group.
    await lp.getByTestId('member-row').filter({ hasText: colleague.email }).getByRole('button', { name: 'Remove' }).click()
    await expect(lp.getByTestId('member-row')).toHaveCount(0)
    expect((await (await api.get('/api/me', bearer(ct))).json()).scopes).not.toContain('sessions:read')
    await api.dispose()

    // Nothing else on the page is theirs to change.
    await expect(lp.getByRole('button', { name: 'Save access' })).toHaveCount(0)
    await expect(lp.getByRole('button', { name: 'Add manager' })).toHaveCount(0)
    await expect(lp.getByRole('button', { name: 'Delete group' })).toHaveCount(0)
    await expect(lp.locator('#edit-group-name')).toHaveCount(0)
    await expect(lp.getByTestId('group-policy'), 'the sign-in policy it carries is shown').toBeVisible()

    // Dismissed, their door closes at once — the API asks on every call — and
    // the section is gone from their next page load.
    await row.filter({ hasText: lead.email }).getByRole('button', { name: 'Remove' }).click()
    await expect(managers.getByTestId('manager-row')).toHaveCount(0)
    await lp.locator('#member-email').fill(colleague.email)
    await lp.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(lp.getByRole('alert')).toContainText('Not Found')
    await lp.reload()
    await expect(lp.getByTestId('me-email')).toHaveText(lead.email)
    await expect(lp.getByTestId('not-allowed')).toBeVisible()
    await expect(lp.getByRole('link', { name: 'Admin', exact: true })).toHaveCount(0)
    await leadContext.close()
  })

  test('a manager is refused someone above them, themselves, and every other group', async ({ page }) => {
    const groupId = await companyGroup(t, 'Support desk', [])
    const lead = await newMember(t)
    const colead = await newMember(t)
    await appoint(t, groupId, lead.email)
    await appoint(t, groupId, colead.email)
    const api = await apiClient()
    const at = await tokenFor(api, t.email, t.password)
    for (const email of [t.email, colead.email]) {
      const res = await api.post(`/api/admin/groups/${groupId}/members`, { data: { email }, ...bearer(at) })
      expect(res.status(), await res.text()).toBe(201)
    }
    await api.dispose()

    await signedIn(page, lead.email, lead.password)
    await page.goto(`/admin/my-groups/${groupId}`)
    // The Admin reaches further than the manager: refused, in the rule's words.
    await page.getByTestId('member-row').filter({ hasText: t.email }).getByRole('button', { name: 'Remove' }).click()
    await expect(page.getByRole('alert')).toContainText(RULE_TWO)
    await expect(page.getByTestId('member-row').filter({ hasText: t.email })).toHaveCount(1)
    // A fellow manager's membership is the Admins' to change: no button for it.
    await expect(page.getByTestId('member-row').filter({ hasText: colead.email })).toHaveCount(1)
    await expect(page.getByTestId('member-row').filter({ hasText: colead.email }).getByRole('button', { name: 'Remove' })).toHaveCount(0)
    // Nor do they decide their own membership.
    await page.locator('#member-email').fill(lead.email)
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText(MANAGERS_SELF)

    // Another group of the company is not theirs, and neither is the Groups section.
    const elsewhere = await companyGroup(t, 'Elsewhere', [])
    await page.goto(`/admin/my-groups/${elsewhere}`)
    await expect(page.getByRole('alert')).toBeVisible()
    await expect(page.getByTestId('member-row')).toHaveCount(0)
    await page.goto('/admin/groups')
    await expect(page.getByTestId('not-allowed')).toBeVisible()
  })

  test('appointing is refused on the page for yourself, an unknown address and twice; without the group’s access there is no form', async ({ page }) => {
    const groupId = await companyGroup(t, 'Refusals', ['sessions:read'])
    const lead = await newMember(t)
    await signedIn(page, t.email, t.password)
    await page.goto(`/admin/groups/${groupId}`)
    const managers = page.getByRole('region', { name: /^Managers/ })
    const appointBy = async email => {
      await managers.locator('#manager-email').fill(email)
      await managers.getByRole('button', { name: 'Add manager' }).click()
    }
    await appointBy(t.email)
    await expect(page.getByRole('alert')).toContainText("You can't make yourself a group's manager")
    await appointBy(`nobody-${Date.now()}@e2e.test`)
    await expect(page.getByRole('alert')).toContainText('Not Found')
    await appointBy(lead.email)
    await expect(managers.getByTestId('manager-row')).toHaveCount(1)
    await appointBy(lead.email)
    await expect(page.getByRole('alert')).toContainText('This person already manages the group')
    await expect(managers.getByTestId('manager-row')).toHaveCount(1)
    // The note on what the group gives: its managers can hand it out.
    await expect(page.getByTestId('access-managers-note')).toBeVisible()

    // A delegate with Groups: Edit but not what this group gives cannot appoint
    // here — no form — and the API holds the same line.
    const delegate = await newMember(t)
    await giveExtras(t, delegate.email, ['groups:edit'])
    const api = await apiClient()
    const dt = await tokenFor(api, delegate.email, delegate.password)
    const res = await api.post(`/api/admin/groups/${groupId}/managers`, { data: { email: (await newMember(t)).email }, ...bearer(dt) })
    expect(res.status()).toBe(403)
    expect((await res.json()).error).toBe('You can only give or take away scopes you hold yourself')
    await api.dispose()
    const dp = await page.context().browser().newPage()
    await signedIn(dp, delegate.email, delegate.password)
    await dp.goto(`/admin/groups/${groupId}`)
    await expect(dp.getByRole('region', { name: /^Managers/ }).getByTestId('manager-row')).toHaveCount(1)
    await expect(dp.locator('#manager-email')).toHaveCount(0)
    await dp.close()
  })

  test('the user page says which groups someone manages', async ({ page }) => {
    const groupId = await companyGroup(t, 'Night shift', ['sessions:read'])
    const lead = await newMember(t)
    await appoint(t, groupId, lead.email)
    const api = await apiClient()
    const id = await userId(api, await tokenFor(api, t.email, t.password), lead.email)
    await api.dispose()

    await signedIn(page, t.email, t.password)
    await page.goto(`/admin/users/${id}`)
    await expect(page.getByTestId('user-manages')).toContainText('Night shift')
    // The Admin manages no group: the manager's pages are not theirs, whatever
    // else of the admin area is.
    await expect(page.getByRole('link', { name: 'Groups you manage' })).toHaveCount(0)
    await page.goto('/admin/my-groups')
    await expect(page.getByTestId('not-allowed')).toBeVisible()
  })

  test('the Owner appoints a manager from the Owner console; the Admins group has none', async ({ page }) => {
    const groupId = await companyGroup(t, 'Owner picked', [])
    const lead = await newMember(t)
    const o = owner()
    await signedIn(page, o.email, o.password)
    await page.goto(`/owner/companies/${t.companyId}/groups/${groupId}`)
    const managers = page.getByRole('region', { name: /^Managers/ })
    await managers.locator('#manager-email').fill(lead.email)
    await managers.getByRole('button', { name: 'Add manager' }).click()
    await expect(managers.getByTestId('manager-row')).toContainText(`${o.email} (Owner)`)

    await page.goto(`/owner/companies/${t.companyId}/groups`)
    await page.getByRole('link', { name: 'Admins' }).click()
    await expect(page.getByRole('region', { name: 'Managers' })).toContainText("can't have managers")
    await expect(page.locator('#manager-email')).toHaveCount(0)
  })
})
