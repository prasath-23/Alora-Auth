import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// App Central and its API share ONE origin, as in production behind a reverse
// proxy: the SPA's pages everywhere, the API under the prefixes below. That is
// what keeps the session cookie host-only and every sign-in POST same-origin.
//
// Backend target: the Go/Gin API (alora-auth-api), which listens on :3001.
// Override with VITE_API_URL in .env.local, e.g. VITE_API_URL=http://127.0.0.1:4001
const API_PREFIXES = ['/api', '/auth', '/oauth', '/.well-known', '/health']

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const target = env.VITE_API_URL || 'http://127.0.0.1:3001'

  return {
    plugins: [react()],
    server: {
      // Loopback only: this development server must not be reachable from the
      // network. "localhost" still works — browsers and Node fall back from ::1
      // to 127.0.0.1 — and it is the issuer, so the SPA must be opened at it.
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      allowedHosts: ['auth.alora.test'],
      proxy: Object.fromEntries(API_PREFIXES.map(prefix => [prefix, { target, changeOrigin: true }])),
    },
  }
})
