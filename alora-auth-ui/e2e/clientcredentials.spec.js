import { test, expect, request } from '@playwright/test'
import { seedCompany, suffix } from './seed.js'
import { freePort, startProduct } from './product.js'
import {
  BASE_URL, acceptAPIClients, clientCredentials, readyAPIClient, signedIn,
} from './helpers.js'

// The client-credentials grant, end to end: an application — here, the test
// runner itself, with no browser and no person — gets a token for a product on
// its API client's list and calls that product's REST API with it. The product
// (sample-product.cjs) checks the token's audience and its scope.

test.describe('an application with client credentials', () => {
  let t
  let product
  let app

  test.beforeAll(async () => {
    t = seedCompany({ productPort: await freePort() })
    product = await startProduct(t)
    await acceptAPIClients(t.productId)
  })
  test.afterAll(async () => {
    product?.stop()
    await app?.dispose()
  })
  test.beforeEach(async ({ page }) => {
    page.on('dialog', d => d.accept())
    app = app ?? await request.newContext({ baseURL: BASE_URL })
  })

  test('is set up in the admin area, gets a token and calls the product’s REST API', async ({ page }) => {
    await signedIn(page, t.email, t.password)
    await page.goto('/admin/api-clients')
    await page.locator('#api-client-name').fill(`Warehouse sync ${suffix()}`)
    await page.getByRole('button', { name: 'Create API client' }).click()
    const id = (await page.getByTestId('api-client-id').textContent()).trim()
    await page.getByRole('button', { name: 'New secret' }).click()
    const secret = (await page.getByTestId('api-client-secret').textContent()).trim()
    await page.getByLabel(`${t.productName} (${t.productKey})`).check()
    await page.getByRole('button', { name: 'Save products' }).click()
    await expect(page.getByRole('button', { name: 'Save products' })).toBeDisabled()
    await page.getByRole('radio', { name: 'REST API: Read' }).check()
    await page.getByRole('button', { name: 'Save scope' }).click()
    await expect(page.getByRole('button', { name: 'Save scope' })).toBeDisabled()
    // The page shows how, never the secret itself.
    const curl = page.getByTestId('try-it-curl')
    await expect(curl).toContainText(`resource=product:${t.productKey}`)
    await expect(curl).toContainText(id)
    await expect(curl).not.toContainText(secret)

    // The application: a token for the product, and a call with it.
    const res = await clientCredentials(app, id, secret, { resource: `product:${t.productKey}` })
    expect(res.status(), await res.text()).toBe(200)
    const body = await res.json()
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 900, scope: 'api:read' })
    expect(body).not.toHaveProperty('refresh_token')
    const items = await app.get(`${product.origin}/api/items`, { headers: { Authorization: `Bearer ${body.access_token}` } })
    expect(items.status(), await items.text()).toBe(200)
    expect(await items.json()).toMatchObject({ client_id: id, tenant_id: t.companyId, scopes: ['api:read'] })

    // What it may not have is refused at App Central.
    const lacking = await clientCredentials(app, id, secret, { resource: `product:${t.productKey}`, scope: 'api:edit' })
    expect(lacking.status()).toBe(400)
    expect((await lacking.json()).error).toBe('invalid_scope')
    const elsewhere = await clientCredentials(app, id, secret, { resource: 'product:NOT-ON-ITS-LIST' })
    expect(elsewhere.status()).toBe(400)
    expect((await elsewhere.json()).error).toBe('invalid_target')

    // The product refuses what it should: no token, and a token without the scope it needs.
    expect((await app.get(`${product.origin}/api/items`)).status()).toBe(401)
    await page.getByRole('radio', { name: 'REST API: None' }).check()
    await page.getByRole('radio', { name: 'MCP tools: On' }).check()
    await page.getByRole('button', { name: 'Save scope' }).click()
    await expect(page.getByRole('button', { name: 'Save scope' })).toBeDisabled()
    const mcpOnly = await (await clientCredentials(app, id, secret, { resource: `product:${t.productKey}` })).json()
    expect(mcpOnly.scope).toBe('mcp:tools')
    const refused = await app.get(`${product.origin}/api/items`, { headers: { Authorization: `Bearer ${mcpOnly.access_token}` } })
    expect(refused.status()).toBe(403)
    expect((await refused.json()).error).toBe('insufficient_scope')
  })

  test('keeps working through a rotation, and stops when its secret is revoked or it is switched off', async ({ page }) => {
    const c = await readyAPIClient(t, { name: `Rotator ${suffix()}`, productIds: [t.productId], scopes: ['api:read'] })
    const resource = `product:${t.productKey}`
    await signedIn(page, t.email, t.password)
    await page.goto(`/admin/api-clients/${c.id}`)
    await page.getByRole('button', { name: 'New secret' }).click()
    const second = (await page.getByTestId('api-client-secret').textContent()).trim()

    // Both work while both are live.
    for (const s of [c.secret, second]) {
      expect((await clientCredentials(app, c.id, s, { resource })).status()).toBe(200)
    }
    // Revoke the first: it stops at once; the second goes on.
    await page.getByTestId('secret-row').filter({ hasText: c.secret.slice(0, 12) }).getByRole('button', { name: 'Revoke' }).click()
    await expect(page.getByTestId('secret-row').filter({ hasText: c.secret.slice(0, 12) })).toContainText('Revoked')
    const old = await clientCredentials(app, c.id, c.secret, { resource })
    expect(old.status()).toBe(401)
    expect((await old.json()).error).toBe('invalid_client')
    expect((await clientCredentials(app, c.id, second, { resource })).status()).toBe(200)

    // Switched off, it gets nothing.
    await page.locator('#edit-api-client-active').uncheck()
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Off')
    expect((await clientCredentials(app, c.id, second, { resource })).status()).toBe(401)
    // The last use shows on its page.
    await page.reload()
    await expect(page.getByTestId('secret-row').filter({ hasText: second.slice(0, 12) }).getByTestId('secret-last-used')).not.toHaveText('Never')
  })
})
