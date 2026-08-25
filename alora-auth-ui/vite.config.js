import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  // Backend target: the Go/Gin API (alora-auth-go), which listens on :3001.
  // Override via VITE_API_URL in .env.local, e.g. VITE_API_URL=http://127.0.0.1:4001
  const apiTarget = env.VITE_API_URL || 'http://127.0.0.1:3001'

  const proxyOpts = {
    target:       apiTarget,
    changeOrigin: true,
  }

  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0',
      allowedHosts: ['auth.alora.test'],
      port: 5173,
      proxy: {
        '/auth': proxyOpts,
        '/admin': {
          ...proxyOpts,
          // Browser navigations (Accept: text/html) must serve the SPA, not the API.
          bypass: (req) => req.headers.accept?.includes('text/html') ? req.url : null,
        },
        '/health': proxyOpts,
      },
    },
  }
})
