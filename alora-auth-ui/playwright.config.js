import { defineConfig, devices } from '@playwright/test'

// End-to-end tests drive the REAL App Central SPA against the REAL Go/Gin API,
// a real Postgres, and real product backends (sample-product.cjs). Nothing is
// mocked: the point is to prove the browser, the SPA, the proxy, the API and a
// product integration agree.
//
// Prerequisites (see e2e/README.md):
//   1. bash ../alora-auth-api/scripts/e2e-up.sh   — Postgres, the API, the Owner
//   2. npx playwright test                        — Vite is started below
export default defineConfig({
  testDir: './e2e',
  // Serial: specs share one API and one database, and a race between workers
  // would test the scheduler rather than the app.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [['list']],
  timeout: 45_000,
  expect: { timeout: 10_000 },

  use: {
    // localhost, not 127.0.0.1: the products under test run on 127.0.0.1, and
    // two different hosts are what keep App Central's cookies away from them.
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  // Vite serves App Central and proxies /api, /auth, /oauth, /.well-known and
  // /health to the Go API, so the browser sees one origin, as in production
  // behind a reverse proxy.
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
})
