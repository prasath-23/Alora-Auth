import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Seeding goes through cmd/bootstrap, connected as the schema owner, exactly
// as an operator provisions a real deployment: companies and their first Admin
// are what App Central deliberately has no API for. Everything after that —
// invitations, groups, grants — the specs do through the API or the UI.

// Must match scripts/e2e-up.sh, which writes stack.json here.
const STATE_DIR = process.env.ALORA_E2E_STATE || join(tmpdir(), 'alora-e2e')

let cached = null
export function stack() {
  if (!cached) {
    const file = join(STATE_DIR, 'stack.json')
    try {
      cached = JSON.parse(readFileSync(file, 'utf8'))
    } catch {
      throw new Error(`the e2e stack is not running (no ${file}) — run: bash ../alora-auth-api/scripts/e2e-up.sh`)
    }
  }
  return cached
}

export const suffix = () => randomBytes(4).toString('hex')

export const PASSWORD = 'e2e-Password-123'

/**
 * A company with one Admin, and a product registered for a sample-product
 * backend at http://127.0.0.1:<productPort>: its launch address, its exact
 * redirect URI, its role catalogue and a client secret. The company subscribes
 * to it and its Admins group opens it with the first role.
 *
 * Every call is unique (addresses, names and product keys all carry a random
 * suffix) unless `email` is given — which is how a spec gives one address
 * accounts in two companies.
 */
export function seedCompany({ email, password = PASSWORD, productPort, roles = ['Admin', 'Editor', 'Viewer'] } = {}) {
  const s = suffix()
  const company = `E2E Co ${s}`
  const productKey = `E2E-${s}`
  const productName = `Sample ${s}`
  const origin = `http://127.0.0.1:${productPort}`
  email = (email ?? `admin-${s}@e2e-${s}.test`).toLowerCase()

  const out = execFileSync(stack().bootstrap, [
    'demo',
    '-company', company,
    '-email', email,
    '-product', productKey,
    '-product-name', productName,
    '-base-url', `${origin}/`,
    '-initiate-login-uri', `${origin}/login/initiate`,
    '-redirect-uri', `${origin}/callback`,
    '-roles', roles.join(','),
  ], {
    encoding: 'utf8',
    env: { ...process.env, DATABASE_URL: stack().ownerDsn, BOOTSTRAP_PASSWORD: password },
  })

  const id = label => out.match(new RegExp(`^\\s*${label}\\s+.*\\(([0-9a-f-]{36})\\)`, 'm'))?.[1]
  const value = label => out.match(new RegExp(`^\\s*${label}\\s+(\\S+)`, 'm'))?.[1]
  const seeded = {
    company, companyId: id('company'), email, password, adminId: id('admin'),
    productKey, productName, productId: value('client_id'), clientSecret: value('client_secret'),
    origin, productPort, roles,
  }
  for (const [k, v] of Object.entries(seeded)) {
    if (v === undefined) throw new Error(`bootstrap demo printed no ${k}:\n${out}`)
  }
  return seeded
}

/** The platform Owner that e2e-up.sh provisioned. */
export const owner = () => stack().owner
