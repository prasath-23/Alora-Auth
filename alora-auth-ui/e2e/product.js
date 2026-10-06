import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { stack } from './seed.js'

const SAMPLE = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'sample-product.cjs')

/** A port nothing is listening on, so each spec's product gets its own. */
export function freePort() {
  return new Promise((ok, fail) => {
    const srv = createServer()
    srv.on('error', fail)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => ok(port))
    })
  })
}

/**
 * Runs sample-product.cjs as a separate process — a real backend on
 * 127.0.0.1, a different host from App Central's localhost, so the browser
 * keeps their cookies apart exactly as it would two real sites.
 */
export async function startProduct(seeded) {
  let log = ''
  const child = spawn(process.execPath, [SAMPLE], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      ALORA_ISSUER: stack().issuer,
      ALORA_CLIENT_ID: seeded.productId,
      ALORA_CLIENT_SECRET: seeded.clientSecret,
      ALORA_PRODUCT_KEY: seeded.productKey,
      PRODUCT_HOST: '127.0.0.1',
      PRODUCT_PORT: String(seeded.productPort),
    },
  })
  child.stdout.on('data', d => { log += d })
  child.stderr.on('data', d => { log += d })

  const origin = `http://127.0.0.1:${seeded.productPort}`
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`sample product exited:\n${log}`)
    try {
      if ((await fetch(`${origin}/health`)).ok) {
        return { origin, log: () => log, stop: () => child.kill() }
      }
    } catch {
      // not listening yet
    }
    await new Promise(r => setTimeout(r, 100))
  }
  child.kill()
  throw new Error(`sample product did not start:\n${log}`)
}
