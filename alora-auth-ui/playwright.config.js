import { defineConfig, devices } from '@playwright/test'

// End-to-end tests drive the REAL React app against the REAL Go/Gin API and a
// real Postgres. Nothing is mocked: the point is to prove the browser, the SPA,
// the proxy and the backend agree on the contract.
//
// Prerequisites (see e2e/README.md):
//   1. Postgres with migrations applied
//   2. The Go API running on :3001
//   3. `npx playwright test`  — Vite is started automatically below
export default defineConfig({
  testDir: './e2e',
  // Serial: the suite mutates shared tenant state, so parallel workers would
  // race each other rather than test the app.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [['list']],
  timeout: 30_000,
  expect: { timeout: 10_000 },

  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  // Vite proxies /auth, /admin and /health to the Go API, so the browser sees a
  // single origin exactly as it would in production behind a reverse proxy.
  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
})
