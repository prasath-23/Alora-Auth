import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'

// Seeding talks to Postgres directly rather than through the API: creating the
// FIRST tenant and its first admin is a bootstrap operation the API deliberately
// does not expose (there is no self-service tenant signup).
const CONTAINER_DB = ['-U', 'postgres', '-d', 'alora_e2e']

let _cid = null
function containerId() {
  if (_cid) return _cid
  _cid = execFileSync('docker', ['ps', '-q', '--filter', 'publish=55432'], { encoding: 'utf8' })
    .trim().split(/\r?\n/)[0]
  if (!_cid) {
    throw new Error('e2e Postgres is not running — run: bash ../alora-auth-go/scripts/e2e-up.sh')
  }
  return _cid
}

function psql(sql) {
  const out = execFileSync(
    'docker',
    ['exec', containerId(), 'psql', ...CONTAINER_DB, '-t', '-A', '-c', sql],
    { encoding: 'utf8', env: { ...process.env, MSYS_NO_PATHCONV: '1' } },
  ).trim()
  // psql emits the RETURNING value AND a command tag ("INSERT 0 1"); only the
  // first line carries the value we asked for.
  return out.split(/\r?\n/)[0].trim()
}

export const suffix = () => randomBytes(4).toString('hex')

/**
 * Creates an isolated tenant plus a global-admin user.
 *
 * Every call uses a unique name/email/domain: verified domains and per-tenant
 * emails are unique indexes, so shared fixtures would collide across specs.
 */
export function seedTenant({ password = 'e2e-Password-123' } = {}) {
  const s = suffix()
  const email = `admin-${s}@e2e-${s}.test`

  const clientId = psql(
    `INSERT INTO tbl_clients (name, is_active) VALUES ('E2E ${s}', true) RETURNING id`)
  const productId = psql(
    `INSERT INTO tbl_products (key, name, base_url, is_active)
     VALUES ('E2E-${s}', 'E2E Product', 'http://127.0.0.1:5173', true) RETURNING id`)
  psql(`INSERT INTO tbl_client_products (client_id, product_id, is_active)
        VALUES ('${clientId}','${productId}',true)`)

  // The hash is produced by the Go binary itself, so the seeded password is
  // hashed with EXACTLY the argon2id parameters the API verifies against —
  // a hard-coded hash would silently rot if those parameters ever changed.
  const passwordHash = execFileSync('go', ['run', './internal/tools/hashpw', password], {
    cwd: '../alora-auth-go', encoding: 'utf8',
  }).trim()

  const userId = psql(
    `INSERT INTO tbl_users (client_id, email, password_hash, account_type, is_active, is_global_admin)
     VALUES ('${clientId}','${email}','${passwordHash}','EMAIL',true,true) RETURNING id`)

  return { clientId, productId, userId, email, password, suffix: s }
}

/**
 * Adds a second user to an EXISTING tenant.
 *
 * Mutations that change permissions (a grant, a group membership) bump the
 * target's permissions_version, which immediately invalidates their access
 * token. Tests must therefore act on somebody OTHER than the caller, or they
 * invalidate the very token they are using — which is correct behaviour, not a
 * bug, and exactly what the freshness check exists to do.
 */
export function seedExtraUser(clientId) {
  const s = suffix()
  const email = `member-${s}@e2e.test`
  const id = psql(
    `INSERT INTO tbl_users (client_id, email, account_type, is_active)
     VALUES ('${clientId}','${email}','OAUTH_ONLY',true) RETURNING id`)
  return { id, email }
}

export function query(sql) {
  return psql(sql)
}
