import { test, expect } from '@playwright/test'
import { owner, seedCompany, suffix } from './seed.js'
import {
  acceptAPIClients, apiClient, bearer, companyAPIClient, companyGroup, newMember, signedIn, tokenFor,
} from './helpers.js'

// API clients: applications' identities. A company's people set them up in the
// admin area (api-clients:read to look, api-clients:edit to change), the Owner
// in the Owner console. A secret is shown once; two may be live, so it rotates
// without downtime; only products the Owner lets accept API clients can go on a
// client's list.

test.describe('API clients', () => {
  test.beforeEach(({ page }) => {
    page.on('dialog', d => d.accept()) // the revoke and delete confirmations
  })

  test('an Admin sets one up: a secret shown once, a product on its list, a scope', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    await acceptAPIClients(t.productId)
    await signedIn(page, t.email, t.password)
    await page.getByRole('link', { name: 'Admin', exact: true }).click()
    await page.getByRole('navigation', { name: 'Admin' }).getByRole('link', { name: 'API clients' }).click()
    await page.locator('#api-client-name').fill('Nightly sync')
    await page.getByRole('button', { name: 'Create API client' }).click()
    await expect(page.getByTestId('api-client-id')).toHaveText(/^aci_[0-9a-f-]{36}$/)
    const id = await page.getByTestId('api-client-id').textContent()
    await expect(page.getByText('No secret yet')).toBeVisible()

    // The secret, once.
    await page.getByRole('button', { name: 'New secret' }).click()
    const secret = (await page.getByTestId('api-client-secret').textContent()).trim()
    expect(secret).toMatch(/^acc_[A-Za-z0-9_-]{40,}$/)
    await page.reload()
    await expect(page.getByTestId('api-client-id')).toHaveText(id)
    await expect(page.getByTestId('api-client-secret')).toHaveCount(0)
    expect(await page.content()).not.toContain(secret)
    await expect(page.getByTestId('secret-row')).toHaveCount(1)
    await expect(page.getByTestId('secret-row')).toContainText(secret.slice(0, 12))
    await expect(page.getByTestId('secret-row')).toContainText('Live')

    // What it may get a token for, and where the token may be used.
    await page.getByLabel(`${t.productName} (${t.productKey})`).check()
    await page.getByRole('button', { name: 'Save products' }).click()
    await expect(page.getByRole('button', { name: 'Save products' })).toBeDisabled()
    await page.getByRole('radio', { name: 'REST API: Read' }).check()
    await page.getByRole('radio', { name: 'MCP tools: On' }).check()
    await expect(page.getByText('MCP tools let an AI agent act')).toBeVisible()
    await page.getByRole('button', { name: 'Save scope' }).click()
    await expect(page.getByRole('button', { name: 'Save scope' })).toBeDisabled()
    await expect(page.getByTestId('client-scope-api')).toHaveAttribute('data-level', 'read')

    // The API says the same.
    const api = await apiClient()
    const token = await tokenFor(api, t.email, t.password)
    const c = await (await api.get(`/api/admin/api-clients/${id}`, bearer(token))).json()
    expect(c).toMatchObject({ name: 'Nightly sync', scopes: ['api:read', 'mcp:tools'], live_secrets: 1, is_active: true })
    expect(c.products.map(p => p.product_key)).toEqual([t.productKey])
    expect(JSON.stringify(c)).not.toContain(secret)
    await api.dispose()
  })

  test('rotates without downtime: two live secrets, then the old one revoked', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const c = await companyAPIClient(t, `Rotating ${suffix()}`)
    await signedIn(page, t.email, t.password)
    await page.goto(`/admin/api-clients/${c.id}`)
    await page.getByRole('button', { name: 'New secret' }).click()
    const first = (await page.getByTestId('api-client-secret').textContent()).trim()
    await expect(page.getByText('To rotate: make a second secret')).toBeVisible()
    await page.locator('#secret-expiry').selectOption({ label: '90 days' })
    await page.getByRole('button', { name: 'New secret' }).click()
    await expect(page.getByTestId('secret-row')).toHaveCount(2)
    await expect(page.getByRole('button', { name: 'New secret' })).toHaveCount(0)
    await expect(page.getByText('Two secrets are live')).toBeVisible()

    // A third is refused by the API too.
    const api = await apiClient()
    const token = await tokenFor(api, t.email, t.password)
    expect((await api.post(`/api/admin/api-clients/${c.id}/secrets`, { data: {}, ...bearer(token) })).status()).toBe(409)

    // Revoke the first: its row says so, and a new secret may be made again.
    const firstRow = page.getByTestId('secret-row').filter({ hasText: first.slice(0, 12) })
    await firstRow.getByRole('button', { name: 'Revoke' }).click()
    await expect(firstRow).toContainText('Revoked')
    await expect(page.getByRole('button', { name: 'New secret' })).toBeVisible()
    const detail = await (await api.get(`/api/admin/api-clients/${c.id}`, bearer(token))).json()
    expect(detail.live_secrets).toBe(1)
    expect(detail.secrets.find(s => first.startsWith(s.prefix)).is_live).toBe(false)
    await api.dispose()
  })

  test('only a product the Owner lets accept API clients can go on the list', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const c = await companyAPIClient(t, `Reporting ${suffix()}`)
    await signedIn(page, t.email, t.password)
    await page.goto(`/admin/api-clients/${c.id}`)
    await expect(page.getByText('No product accepts API clients yet')).toBeVisible()
    const api = await apiClient()
    const token = await tokenFor(api, t.email, t.password)
    const refused = await api.put(`/api/admin/api-clients/${c.id}/products`, { data: { product_ids: [t.productId] }, ...bearer(token) })
    expect(refused.status()).toBe(400)

    await acceptAPIClients(t.productId)
    await page.reload()
    await page.getByLabel(`${t.productName} (${t.productKey})`).check()
    await page.getByRole('button', { name: 'Save products' }).click()
    await expect(page.getByRole('button', { name: 'Save products' })).toBeDisabled()

    // Switched off again: the entry stays, marked as earning no token.
    await acceptAPIClients(t.productId, false)
    await page.reload()
    await expect(page.getByText('No longer accepts API clients')).toBeVisible()
    const after = await (await api.get(`/api/admin/api-clients/${c.id}`, bearer(token))).json()
    expect(after.products).toEqual([expect.objectContaining({ product_id: t.productId, usable: false })])
    await api.dispose()
  })

  test('with api-clients:read, a person sees API clients but nothing that changes them', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const c = await companyAPIClient(t, `Watched ${suffix()}`)
    const reader = await newMember(t, { groupIds: [await companyGroup(t, 'Auditors', ['api-clients:read'])] })
    await signedIn(page, reader.email, reader.password)
    await page.getByRole('link', { name: 'Admin', exact: true }).click()
    await expect(page.getByRole('navigation', { name: 'Admin' }).getByRole('link')).toHaveText(['API clients'])
    await expect(page.getByRole('button', { name: 'Create API client' })).toHaveCount(0)
    await page.getByTestId('api-client-row').filter({ hasText: c.name }).getByRole('link').click()
    await expect(page.getByTestId('api-client-id')).toHaveText(c.id)
    for (const button of ['New secret', 'Save products', 'Save scope', 'Delete API client']) {
      await expect(page.getByRole('button', { name: button })).toHaveCount(0)
    }
    await expect(page.getByRole('radio', { name: 'REST API: Read' })).toBeDisabled()

    const api = await apiClient()
    const token = await tokenFor(api, reader.email, reader.password)
    expect((await api.post(`/api/admin/api-clients/${c.id}/secrets`, { data: {}, ...bearer(token) })).status()).toBe(403)
    expect((await api.put(`/api/admin/api-clients/${c.id}/scopes`, { data: { scopes: ['api:edit'] }, ...bearer(token) })).status()).toBe(403)
    await api.dispose()
  })
})

test.describe('the Owner’s client credentials', () => {
  test('lists every product login and every company’s API clients, and switches a product to accept them', async ({ page }) => {
    const t = seedCompany({ productPort: 9 })
    const c = await companyAPIClient(t, `Warehouse feed ${suffix()}`)
    await signedIn(page, owner().email, owner().password)
    await page.getByRole('link', { name: 'Owner', exact: true }).click()
    await page.getByRole('navigation', { name: 'Owner' }).getByRole('link', { name: 'Client credentials' }).click()

    const login = page.getByTestId('product-login-row').filter({ hasText: t.productName })
    await expect(login).toContainText(t.productId)
    await expect(login).toContainText('Not accepted')

    await page.getByRole('searchbox', { name: 'Filter API clients' }).fill(t.company)
    const row = page.getByTestId('api-client-row').filter({ hasText: c.name })
    await expect(row).toContainText(t.company)
    await row.getByRole('link', { name: c.name }).click()
    await expect(page).toHaveURL(new RegExp(`/owner/companies/${t.companyId}/api-clients/${c.id}$`))
    await expect(page.getByTestId('api-client-id')).toHaveText(c.id)

    // The switch lives on the product's page.
    await page.goto(`/owner/products/${t.productId}`)
    await page.locator('#edit-product-api-clients').check()
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await page.goto('/owner/credentials')
    await expect(page.getByTestId('product-login-row').filter({ hasText: t.productName })).toContainText('Accepted')

    // And now the company's API client may be given the product.
    await page.goto(`/owner/companies/${t.companyId}/api-clients/${c.id}`)
    await page.getByLabel(`${t.productName} (${t.productKey})`).check()
    await page.getByRole('button', { name: 'Save products' }).click()
    await expect(page.getByRole('button', { name: 'Save products' })).toBeDisabled()
  })
})
