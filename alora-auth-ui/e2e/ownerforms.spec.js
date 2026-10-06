import { test, expect } from '@playwright/test'
import { owner, seedCompany, suffix } from './seed.js'
import { apiClient, bearer, signedIn, tokenFor } from './helpers.js'

// The Owner console's forms refuse what the API refuses, in words, and save
// nothing. A rule the API checks only as it reads the request — a list's
// length, a domain's or a URL's shape, a product key — would come back as a
// bare "Invalid request", so the form checks it first and says which rule.

test.describe('the Owner console refuses in words and saves nothing', () => {
  let t
  let api
  let ownerToken
  const echo = () => ({ headers: { Authorization: `Bearer ${ownerToken}`, 'X-Alora-Target-Company': t.companyId } })
  // The alert that says it: a page may show a card's earlier refusal too.
  const says = (page, words) => expect(page.getByRole('alert').filter({ hasText: words })).toBeVisible()

  test.beforeAll(async () => {
    t = seedCompany({ productPort: 9 })
    api = await apiClient()
    const o = owner()
    ownerToken = await tokenFor(api, o.email, o.password)
  })
  test.afterAll(() => api?.dispose())
  test.beforeEach(async ({ page }) => {
    const o = owner()
    await signedIn(page, o.email, o.password)
  })

  test('companies: a domain that is no domain', async ({ page }) => {
    const tag = suffix()
    await page.goto('/owner')
    await page.locator('#company-name').fill(`Forms ${tag}`)
    for (const [domain, words] of [
      [`acme_${tag}.com`, 'is not a domain name, such as acme.com'],
      [`${tag}`, 'is not a domain name'],
      [`-${tag}.com`, 'is not a domain name'],
    ]) {
      await page.locator('#company-domain').fill(domain)
      await page.getByRole('button', { name: 'Create company' }).click()
      await says(page, words)
    }
    await page.goto('/owner')
    await expect(page.getByTestId('company-row').first()).toBeVisible()
    await expect(page.getByText(`Forms ${tag}`), 'a refused company was created').toHaveCount(0)

    // A company's own domain, likewise; the stored one stays.
    await page.goto(`/owner/companies/${t.companyId}`)
    await page.locator('#co-domain').fill('not a domain')
    await page.getByRole('button', { name: 'Save domain' }).click()
    await says(page, '“not a domain” is not a domain name')
    const co = await (await api.get(`/api/owner/companies/${t.companyId}`, bearer(ownerToken))).json()
    expect(co.domain ?? '').not.toBe('not a domain')
  })

  test('products: the key, the URLs, the redirect URIs and the roles', async ({ page }) => {
    const tag = suffix().toUpperCase()
    const taken = `TAKEN${tag}`
    expect((await api.post('/api/owner/products', { data: { key: taken, name: 'Taken' }, ...bearer(ownerToken) })).status()).toBe(201)

    await page.goto('/owner/products')
    const fill = async fields => {
      for (const [id, v] of Object.entries({ 'product-key': '', 'product-name': 'Forms', 'product-base-url': '', 'product-initiate': '', ...fields })) {
        await page.locator(`#${id}`).fill(v)
      }
      await page.getByRole('button', { name: 'Register product' }).click()
    }
    const register = async (fields, words) => {
      await fill(fields)
      await says(page, words)
      await expect(page).toHaveURL(/\/owner\/products$/)
    }
    await register({ 'product-key': 'K' }, "The key must be 2-40 letters, digits, '-' or '_'")
    await register({ 'product-key': `-${tag}` }, "The key must be 2-40 letters, digits, '-' or '_'")
    await register({ 'product-key': taken }, 'A product with this key already exists')
    await register({ 'product-key': `F${tag}`, 'product-base-url': 'crm.acme.test' }, 'The base URL must be an absolute URL starting with https://')
    await register({ 'product-key': `F${tag}`, 'product-base-url': 'HTTPS://CRM.ACME.TEST' }, 'The base URL must be an absolute URL starting with https://')
    await register({ 'product-key': `F${tag}`, 'product-initiate': 'https://crm.acme.test/login#' }, 'The launch URI cannot have a fragment')
    await register({ 'product-key': `F${tag}`, 'product-initiate': 'https://me@crm.acme.test/login' }, 'The launch URI cannot carry a user name or password')
    const list = await (await api.get('/api/owner/products', bearer(ownerToken))).json()
    expect(list.filter(p => p.key === `F${tag}`), 'a refused registration was saved').toHaveLength(0)

    // A good registration opens its page, where every list is checked too.
    await fill({ 'product-key': `F${tag}` })
    await expect(page).toHaveURL(/\/owner\/products\/[0-9a-f-]{36}$/)
    const pid = page.url().split('/').pop()
    const saveURIs = async (text, words) => {
      await page.locator('#redirect-uris').fill(text)
      await page.getByRole('button', { name: 'Save redirect URIs' }).click()
      await says(page, words)
    }
    await saveURIs(Array.from({ length: 21 }, (_, i) => `https://crm.acme.test/cb${i}`).join('\n'), 'At most 20 redirect URIs; this list has 21.')
    await saveURIs(`https://crm.acme.test/${'p'.repeat(2049 - 'https://crm.acme.test/'.length)}`, 'A redirect URI can be at most 2,048 characters; one has 2,049.')
    await saveURIs('https://crm.acme.test/cb\nHTTPS://CRM.ACME.TEST/CB', 'A redirect URI must be an absolute URL starting with https://')
    await saveURIs('https://crm.acme.test/cb#', 'A redirect URI cannot have a fragment')
    const saveRoles = async (text, words) => {
      await page.locator('#product-roles').fill(text)
      await page.getByRole('button', { name: 'Save roles' }).click()
      await says(page, words)
    }
    await saveRoles(Array.from({ length: 51 }, (_, i) => `Role ${i}`).join('\n'), 'At most 50 roles; this list has 51.')
    await saveRoles(`R${'r'.repeat(64)}`, 'A role can be at most 64 characters; one has 65.')
    await saveRoles('Viewer\n1bad', 'A role is 1-64 letters, digits, spaces')
    const saved = await (await api.get(`/api/owner/products/${pid}`, bearer(ownerToken))).json()
    expect(saved.redirect_uris, 'a refused list was saved').toEqual([])
    expect(saved.roles, 'a refused list was saved').toEqual([])

    // And the good ones are kept exactly.
    await page.locator('#redirect-uris').fill('https://crm.acme.test/cb\nhttp://localhost:4100/cb')
    await page.getByRole('button', { name: 'Save redirect URIs' }).click()
    await page.locator('#product-roles').fill('Viewer\nEditor')
    await page.getByRole('button', { name: 'Save roles' }).click()
    await expect.poll(async () => (await (await api.get(`/api/owner/products/${pid}`, bearer(ownerToken))).json()).roles.length).toBe(2)
    const kept = await (await api.get(`/api/owner/products/${pid}`, bearer(ownerToken))).json()
    expect([...kept.redirect_uris].sort()).toEqual(['http://localhost:4100/cb', 'https://crm.acme.test/cb'])
    expect([...kept.roles].sort()).toEqual(['Editor', 'Viewer'])

    // Its registration's URLs, too.
    await page.locator('#edit-product-base-url').fill('ftp://crm.acme.test')
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await says(page, 'The base URL must be an absolute URL starting with https://')
  })

  test('policies: one that allows nothing, and a priority taken', async ({ page }) => {
    await page.goto(`/owner/companies/${t.companyId}/policies`)
    await expect(page.getByTestId('policy-row').first()).toBeVisible()
    const rows = await page.getByTestId('policy-row').count()
    const taken = (await (await api.get(`/api/owner/companies/${t.companyId}/login-policies`, echo())).json())[0].priority
    const newPolicy = async (name, priority, { password = true } = {}) => {
      await page.getByRole('button', { name: 'New policy' }).click()
      await page.locator('#policy-name').fill(name)
      await page.locator('#policy-priority').fill(String(priority))
      if (!password) await page.locator('#policy-password').uncheck()
      await page.getByRole('button', { name: 'Save policy' }).click()
    }
    await newPolicy(`Nothing ${suffix()}`, 555, { password: false })
    await says(page, 'A policy must allow at least one sign-in method')
    await page.getByRole('button', { name: 'Cancel' }).click()
    await newPolicy(`Clash ${suffix()}`, taken)
    await says(page, 'A policy with this name or priority already exists')
    await page.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByTestId('policy-row')).toHaveCount(rows)
  })

  test('SSO: the issuer, the domains, and a save the API half refuses', async ({ page }) => {
    const tag = suffix()
    // Another connection already holds this domain.
    const other = await api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `Holder ${tag}`, issuer: 'https://holder.invalid', client_id: `h-${tag}`, client_secret: 's', is_active: true }, ...echo() })
    const held = `held-${tag}.test`
    expect((await api.put(`/api/owner/companies/${t.companyId}/sso-connections/${(await other.json()).id}/domains`,
      { data: { domains: [held] }, ...echo() })).status()).toBe(204)

    await page.goto(`/owner/companies/${t.companyId}/sso`)
    await expect(page.getByTestId('sso-row').filter({ hasText: `Holder ${tag}` })).toBeVisible()
    const rows = await page.getByTestId('sso-row').count()
    await page.getByRole('button', { name: 'New connection' }).click()
    const name = `Forms ${tag}`
    await page.locator('#sso-name').fill(name)
    await page.locator('#sso-client-id').fill(`f-${tag}`)
    await page.locator('#sso-client-secret').fill('s3cret')
    const save = async (issuer, domains, words) => {
      await page.locator('#sso-issuer').fill(issuer)
      await page.locator('#sso-domains').fill(domains)
      await page.getByRole('button', { name: 'Save connection' }).click()
      if (words) await says(page, words)
    }
    await save('HTTPS://SSO.TEST', '', 'The issuer must be an absolute URL starting with https://')
    await save('https://sso.test?x=1', '', 'The issuer cannot have a query')
    await save('https://sso.test', `acme_${tag}.com`, `“acme_${tag}.com” is not a domain name, such as acme.com.`)
    await save('https://sso.test', Array.from({ length: 51 }, (_, i) => `d${i}-${tag}.test`).join('\n'), 'At most 50 domains; this list has 51.')
    await save('https://sso.test', `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`, 'A domain can be at most 253 characters; one has 254.')
    expect(await page.getByTestId('sso-row').count(), 'a refused connection was saved').toBe(rows)

    // The connection is saved and its domain refused: it exists now, so saving
    // again with the domain corrected finishes it rather than making another.
    await save('https://sso.test', held, 'A domain is already registered on another connection')
    const fresh = `fresh-${tag}.test`
    await save('https://sso.test', fresh, null)
    await expect(page.getByTestId('sso-row').filter({ hasText: name })).toHaveCount(1)
    await expect(page.getByTestId('sso-row').filter({ hasText: name })).toContainText(fresh)
    const all = await (await api.get(`/api/owner/companies/${t.companyId}/sso-connections`, echo())).json()
    expect(all.filter(c => c.name === name), 'the half-refused save made two connections').toHaveLength(1)
  })
})
