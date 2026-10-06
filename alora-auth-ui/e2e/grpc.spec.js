import { test, expect } from '@playwright/test'
import { execFile, spawn } from 'node:child_process'
import { seedCompany, stack, suffix } from './seed.js'
import { acceptAPIClients, readyAPIClient } from './helpers.js'

// gRPC end to end, with real binaries built from alora-auth-go: the demo
// product — an inventory whose every call is checked by the Go helper's
// Verifier — and the demo application, which gets its token from App Central's
// gRPC TokenService through the same helper and puts it on every call.

/** Starts the demo product for one product key, on a port of its choosing. */
function startInventory(productKey) {
  return new Promise((resolve, reject) => {
    const child = spawn(stack().demo.server, ['-addr', '127.0.0.1:0', '-issuer', stack().issuer, '-product', productKey], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let log = ''
    const timer = setTimeout(() => { child.kill(); reject(new Error(`the inventory did not start:\n${log}`)) }, 15_000)
    child.stdout.on('data', d => {
      log += d
      const m = log.match(/inventory listening on (127\.0\.0\.1:\d+)/)
      if (m) {
        clearTimeout(timer)
        resolve({ addr: m[1], stop: () => child.kill(), log: () => log })
      }
    })
    child.stderr.on('data', d => { log += d })
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`the inventory exited (${code}):\n${log}`)) })
  })
}

/** Runs the demo application; resolves its exit code and the JSON it printed. */
function application(args, secret) {
  return new Promise(resolve => {
    execFile(stack().demo.client, args, { env: { ...process.env, ALORA_CLIENT_SECRET: secret }, timeout: 30_000 },
      (err, stdout, stderr) => {
        const last = stdout.trim().split('\n').pop() ?? ''
        let out = null
        try { out = JSON.parse(last) } catch { out = { unparsed: stdout, stderr } }
        resolve({ code: err ? (err.code ?? 1) : 0, out })
      })
  })
}

test.describe('an application over gRPC', () => {
  let t
  let inventory

  test.beforeAll(async () => {
    t = seedCompany({ productPort: 9 })
    await acceptAPIClients(t.productId)
    inventory = await startInventory(t.productKey)
  })
  test.afterAll(() => inventory?.stop())

  const args = (c, addr, ...command) =>
    ['-central', stack().grpc, '-client-id', c.id, '-product', t.productKey, '-addr', addr, '-insecure', ...command]

  test('reads the inventory with grpc:read, and is refused a change without grpc:edit', async () => {
    const c = await readyAPIClient(t, { name: `Reader ${suffix()}`, productIds: [t.productId], scopes: ['grpc:read'] })
    const list = await application(args(c, inventory.addr, 'list'), c.secret)
    expect(list.code, JSON.stringify(list.out)).toBe(0)
    expect(list.out.caller).toBe(c.id)
    expect(list.out.items.length).toBeGreaterThan(0)

    const add = await application(args(c, inventory.addr, 'add', 'Forklift'), c.secret)
    expect(add.code).toBe(1)
    expect(add.out).toMatchObject({ code: 'PermissionDenied', reason: 'insufficient_scope' })
  })

  test('changes the inventory once it holds grpc:edit', async () => {
    const c = await readyAPIClient(t, { name: `Writer ${suffix()}`, productIds: [t.productId], scopes: ['grpc:edit'] })
    const name = `Forklift ${suffix()}`
    const add = await application(args(c, inventory.addr, 'add', name), c.secret)
    expect(add.code, JSON.stringify(add.out)).toBe(0)
    expect(add.out.item.name).toBe(name)
    // grpc:edit brings grpc:read, so it can read too.
    const list = await application(args(c, inventory.addr, 'list'), c.secret)
    expect(list.out.items.map(i => i.name)).toContain(name)
  })

  test('is refused by App Central with a wrong secret, and by another product with this one’s token', async () => {
    const c = await readyAPIClient(t, { name: `Stranger ${suffix()}`, productIds: [t.productId], scopes: ['grpc:read'] })
    const wrong = await application(args(c, inventory.addr, 'list'), c.secret + 'x')
    expect(wrong.code).toBe(1)
    expect(wrong.out.code).toBe('Unauthenticated')

    // Another product's inventory: the token is for this product alone.
    const elsewhere = await startInventory(`OTHER-${suffix()}`)
    try {
      const refused = await application(args(c, elsewhere.addr, 'list'), c.secret)
      expect(refused.code).toBe(1)
      expect(refused.out).toMatchObject({ code: 'Unauthenticated', reason: 'invalid_token' })
    } finally {
      elsewhere.stop()
    }
  })
})
