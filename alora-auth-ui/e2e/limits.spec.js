import { test, expect } from '@playwright/test'
import { owner, seedCompany, suffix } from './seed.js'
import { apiClient, bearer, signIn, signedIn, tokenFor } from './helpers.js'
import { LIMITS, LIST_LIMITS, domainProblem, keyProblem, urlProblem } from '../src/utils/limits.js'

// The forms stop where the API would refuse. Every limit in the SPA's list is
// the one the API enforces — a value of exactly that length is accepted and one
// character more is refused — and every input carries its limit, so nobody
// types a name only to be told "Invalid request".

const fqdn = n => {
  // A valid domain of exactly n characters: labels of up to 63, joined by dots.
  const labels = []
  let left = n
  while (left > 0) {
    const take = Math.min(63, left === 64 ? 62 : left)
    labels.push('a'.repeat(take))
    left -= take + 1
  }
  return labels.join('.').slice(0, n)
}
const url = n => { const head = 'https://limits.test/'; return head + 'p'.repeat(n - head.length) }

test.describe('the forms stop where the API would refuse', () => {
  let t
  let api
  let admin
  let ownerToken
  const echo = () => ({ headers: { Authorization: `Bearer ${ownerToken}`, 'X-Alora-Target-Company': t.companyId } })

  test.beforeAll(async () => {
    t = seedCompany({ productPort: 9 })
    api = await apiClient()
    admin = await tokenFor(api, t.email, t.password)
    const o = owner()
    ownerToken = await tokenFor(api, o.email, o.password)
  })
  test.afterAll(() => api?.dispose())

  // Each limit, probed at the API: [the value at the limit, one past it].
  const probes = {
    groupName: n => api.post('/api/admin/groups', { data: { name: 'g'.repeat(n) }, ...bearer(admin) }),
    groupDescription: n => api.post('/api/admin/groups', { data: { name: `G ${suffix()}`, description: 'd'.repeat(n) }, ...bearer(admin) }),
    apiClientName: n => api.post('/api/admin/api-clients', { data: { name: 'c'.repeat(n) }, ...bearer(admin) }),
    apiClientDescription: n => api.post('/api/admin/api-clients', { data: { name: `C ${suffix()}`, description: 'd'.repeat(n) }, ...bearer(admin) }),
    companyName: n => api.post('/api/owner/companies', { data: { name: suffix() + 'n'.repeat(n - 8) }, ...bearer(ownerToken) }),
    domain: n => api.post('/api/owner/companies', { data: { name: `D ${suffix()}`, domain: `${suffix()}.${fqdn(n - 9)}` }, ...bearer(ownerToken) }),
    productKey: n => api.post('/api/owner/products', { data: { key: 'K' + suffix().toUpperCase() + 'A'.repeat(n - 9), name: 'P' }, ...bearer(ownerToken) }),
    productName: n => api.post('/api/owner/products', { data: { key: `PN${suffix().toUpperCase()}`, name: 'p'.repeat(n) }, ...bearer(ownerToken) }),
    productDescription: n => api.post('/api/owner/products', { data: { key: `PD${suffix().toUpperCase()}`, name: 'P', description: 'd'.repeat(n) }, ...bearer(ownerToken) }),
    url: n => api.post('/api/owner/products', { data: { key: `PU${suffix().toUpperCase()}`, name: 'P', base_url: url(n) }, ...bearer(ownerToken) }),
    policyName: n => api.post(`/api/owner/companies/${t.companyId}/login-policies`,
      { data: { name: 'p'.repeat(n), allow_password: true, allow_google: false, priority: 321 }, ...echo() }),
    ssoName: n => api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: 's'.repeat(n), issuer: 'https://sso.invalid', client_id: `l-${suffix()}`, client_secret: 's', is_active: true }, ...echo() }),
    ssoIssuer: n => api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `S ${suffix()}`, issuer: url(n), client_id: `l-${suffix()}`, client_secret: 's', is_active: true }, ...echo() }),
    ssoClientID: n => api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `S ${suffix()}`, issuer: 'https://sso.invalid', client_id: suffix() + 'i'.repeat(n - 8), client_secret: 's', is_active: true }, ...echo() }),
    ssoClientSecret: n => api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `S ${suffix()}`, issuer: 'https://sso.invalid', client_id: `l-${suffix()}`, client_secret: 'x'.repeat(n), is_active: true }, ...echo() }),
    ssoScopes: n => api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `S ${suffix()}`, issuer: 'https://sso.invalid', client_id: `l-${suffix()}`, client_secret: 's', scopes: 'o'.repeat(n), is_active: true }, ...echo() }),
  }

  test('every limit in the SPA is the one the API enforces', async () => {
    for (const [key, probe] of Object.entries(probes)) {
      const n = LIMITS[key]
      expect(n, `LIMITS.${key}`).toBeGreaterThan(0)
      const at = await probe(n)
      expect(at.status(), `${key}: exactly ${n} is accepted — ${await at.text()}`).toBe(201)
      const past = await probe(n + 1)
      expect(past.status(), `${key}: ${n + 1} is refused`).toBe(400)
    }
    // An address past its limit is refused too (an address at 320 cannot be a
    // valid one to begin with, so only the refusal is checked).
    const long = await api.post('/api/admin/invitations',
      { data: { email: 'a'.repeat(64) + '@' + fqdn(LIMITS.email - 64), group_ids: [] }, ...bearer(admin) })
    expect(long.status()).toBe(400)
  })

  // A list's limits, and the format rules the SPA checks before sending, are
  // the API's own: the SPA never refuses what the API would take, and says in
  // words what the API would refuse with a bare "Invalid request".
  test('every list limit and format rule in the SPA is the API’s', async () => {
    test.setTimeout(180_000)
    const tag = suffix()
    const pr = await api.post('/api/owner/products', { data: { key: `LL${tag.toUpperCase()}`, name: 'Lists' }, ...bearer(ownerToken) })
    const pid = (await pr.json()).id
    const sso = await api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `L ${tag}`, issuer: 'https://sso.invalid', client_id: `ll-${tag}`, client_secret: 's', is_active: true }, ...echo() })
    const sid = (await sso.json()).id
    const put = {
      redirectURIs: list => api.put(`/api/owner/products/${pid}/redirect-uris`, { data: { redirect_uris: list }, ...bearer(ownerToken) }),
      roles: list => api.put(`/api/owner/products/${pid}/roles`, { data: { roles: list }, ...bearer(ownerToken) }),
      domains: list => api.put(`/api/owner/companies/${t.companyId}/sso-connections/${sid}/domains`, { data: { domains: list }, ...echo() }),
    }
    const entry = {
      redirectURIs: (i, n = 40) => url(n).replace('limits.test', `l${i}.limits.test`).slice(0, n),
      roles: (i, n = 10) => ('R' + i + 'r'.repeat(n)).slice(0, n),
      domains: (i, n = 20) => `${i}x${tag}.${fqdn(Math.max(n - `${i}x${tag}.`.length, 2))}`.slice(0, n),
    }
    for (const [key, { most, each }] of Object.entries(LIST_LIMITS)) {
      const many = n => Array.from({ length: n }, (_, i) => entry[key](i))
      expect((await put[key](many(most))).status(), `${key}: ${most} entries`).toBe(204)
      expect((await put[key](many(most + 1))).status(), `${key}: ${most + 1} entries`).toBe(400)
      const at = await put[key]([entry[key](0, each)])
      expect(at.status(), `${key}: an entry of ${each} — ${await at.text()}`).toBe(204)
      expect((await put[key]([entry[key](0, each + 1)])).status(), `${key}: an entry of ${each + 1}`).toBe(400)
    }
    await put.domains([])

    // The SPA's verdict on each sample is the API's: taken (or merely taken by
    // someone else, a 409) exactly when the SPA finds nothing wrong.
    const agree = async (what, samples, spa, send) => {
      for (const s of samples) {
        const r = await send(s)
        const apiTakes = r.status() !== 400
        expect(spa(s) === null, `${what} ${JSON.stringify(s)}: the SPA says ${JSON.stringify(spa(s))}, the API ${r.status()}`).toBe(apiTakes)
      }
    }
    await agree('domain', [`${tag}.test`, `${tag}-x.test`, `x-${tag}.test`, `${tag}.c0m`, `${tag}.test.`, `xn--${tag}.test`,
      `${tag}.t-st`, fqdn(253), `-${tag}.test`, `${tag}`, `${tag}.123`, `${tag} x.test`, `${tag}..test`, `.${tag}.test`,
      `${'a'.repeat(64)}.${tag}.test`, `ü${tag}.test`, `${tag}_x.test`, fqdn(254)],
    domainProblem, d => put.domains([d]))
    await put.domains([])
    await agree('redirect URI', ['https://crm.acme.test/cb', 'http://localhost:4100/cb', 'https://crm.acme.test/cb?x=1',
      'https://[::1]:8443/cb', 'https://crm.acme.test:99999/cb', 'HTTPS://CRM.ACME.TEST/CB', 'Https://crm.acme.test/cb',
      'https://crm.acme.test/cb#', 'https://crm.acme.test/cb#f', 'https://@crm.acme.test/cb', 'https://u:p@crm.acme.test/cb',
      'crm.acme.test/cb', '/cb', 'ftp://crm.acme.test/cb', 'https://', 'javascript:alert(1)', 'https:/crm.acme.test'],
    u => urlProblem('A redirect URI', u), u => put.redirectURIs([u]))
    await agree('issuer', ['https://sso.test', 'https://sso.test/tenant/v2', 'http://localhost:9000', 'https://sso.test?',
      'https://sso.test?x=1', 'https://sso.test#', 'HTTPS://SSO.TEST', 'ftp://sso.test', 'sso.test'],
    u => urlProblem('The issuer', u, { query: false }),
    u => api.post(`/api/owner/companies/${t.companyId}/sso-connections`,
      { data: { name: `I ${suffix()}`, issuer: u, client_id: `i-${suffix()}`, client_secret: 's', is_active: true }, ...echo() }))
    await agree('product key', [`K${tag}`, `k-${tag}_x`, `9${tag}`, `K${tag}`.padEnd(40, 'Z'), `K${tag}`.padEnd(41, 'Z'),
      'K', `-${tag}`, `_${tag}`, `K${tag}!`, `K ${tag}`, `Ä${tag}`],
    keyProblem, k => api.post('/api/owner/products', { data: { key: k, name: 'P' }, ...bearer(ownerToken) }))
  })

  test('every input carries its limit, and the browser stops there', async ({ page, browser }) => {
    test.setTimeout(180_000)
    const res = await api.post('/api/admin/groups', { data: { name: `Limits ${suffix()}` }, ...bearer(admin) })
    const groupId = (await res.json()).id
    const cl = await api.post('/api/admin/api-clients', { data: { name: `Limits ${suffix()}` }, ...bearer(admin) })
    const clientId = (await cl.json()).id

    const check = async (p, ids) => {
      for (const [id, key] of Object.entries(ids)) {
        await expect(p.locator(`#${id}`), `#${id}`).toHaveAttribute('maxlength', String(LIMITS[key]))
      }
    }
    // Before sign-in: the sign-in form.
    await page.goto('/login')
    await check(page, { email: 'email' })
    await signedIn(page, t.email, t.password)
    for (const [path, ids] of [
      ['/admin/groups', { 'group-name': 'groupName', 'group-description': 'groupDescription' }],
      [`/admin/groups/${groupId}`, { 'edit-group-name': 'groupName', 'edit-group-description': 'groupDescription', 'member-email': 'email', 'manager-email': 'email' }],
      ['/admin/api-clients', { 'api-client-name': 'apiClientName', 'api-client-description': 'apiClientDescription' }],
      [`/admin/api-clients/${clientId}`, { 'edit-api-client-name': 'apiClientName', 'edit-api-client-description': 'apiClientDescription' }],
      ['/admin/invitations', { 'invite-email': 'email' }],
      ['/admin/company', { 'company-name-input': 'companyName' }],
      ['/profile', { 'current-password': 'password', 'new-password': 'password', 'confirm-password': 'password' }],
    ]) {
      await page.goto(path)
      await check(page, ids)
    }
    // The browser itself stops typing at the limit.
    await page.goto('/admin/groups')
    await page.locator('#group-name').pressSequentially('x'.repeat(LIMITS.groupName + 7))
    await expect(page.locator('#group-name')).toHaveValue('x'.repeat(LIMITS.groupName))

    const o = owner()
    const op = await (await browser.newContext()).newPage()
    await signIn(op, o.email, o.password)
    await expect(op.getByTestId('me-email')).toHaveText(o.email)
    const pr = await api.post('/api/owner/products', { data: { key: `LIM${suffix().toUpperCase()}`, name: 'Limits' }, ...bearer(ownerToken) })
    const productId = (await pr.json()).id
    for (const [path, ids, open] of [
      ['/owner', { 'company-name': 'companyName', 'company-domain': 'domain' }],
      [`/owner/companies/${t.companyId}`, { 'co-name': 'companyName', 'co-domain': 'domain' }],
      [`/owner/companies/${t.companyId}/policies`, { 'policy-name': 'policyName' }, 'New policy'],
      [`/owner/companies/${t.companyId}/sso`, { 'sso-name': 'ssoName', 'sso-issuer': 'ssoIssuer', 'sso-client-id': 'ssoClientID', 'sso-client-secret': 'ssoClientSecret', 'sso-scopes': 'ssoScopes' }, 'New connection'],
      ['/owner/products', { 'product-key': 'productKey', 'product-name': 'productName', 'product-description': 'productDescription', 'product-base-url': 'url', 'product-initiate': 'url' }],
      [`/owner/products/${productId}`, { 'edit-product-name': 'productName', 'edit-product-description': 'productDescription', 'edit-product-base-url': 'url', 'edit-product-initiate': 'url' }],
    ]) {
      await op.goto(path)
      if (open) await op.getByRole('button', { name: open }).click()
      await check(op, ids)
    }
  })
})
