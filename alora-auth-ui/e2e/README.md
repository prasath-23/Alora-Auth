# End-to-end tests (Playwright)

Drives the real React SPA against the real Go/Gin API and a real Postgres.

## Run

```bash
# 1. Database (throwaway container) + migrations
bash ../alora-auth-api/scripts/e2e-up.sh

# 2. Tests (Vite starts automatically)
npx playwright test
```

`e2e-up.sh` starts Postgres on :55432, applies the migrations, generates an RSA
keypair, and boots the Go API on :3001 — the port the Vite proxy targets.

## Design

- **Nothing is mocked.** A mocked API cannot catch contract drift, which is the
  main risk when replacing a backend.
- **Serial execution.** The suite mutates shared tenant state.
- Each spec seeds its own tenant/user via `e2e/seed.js` so tests do not collide
  on the tenant-unique indexes.
