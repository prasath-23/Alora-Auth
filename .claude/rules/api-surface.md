---
paths:
  - "alora-auth-api/cmd/api/main.go"
  - "alora-auth-api/internal/core/*/controller/**"
  - "alora-auth-api/internal/config/**"
  - "alora-auth-api/.env.example"
  - "*_controller.go"
---

# Changing the API surface

- A route: regenerate the OpenAPI document with swag, give a new `/api/admin` route
  a row in `adminRoutes` (`cmd/api/scopes_test.go`), and pick its rate limiter. Read
  `docs/agents/playbooks/route-change.md`.
- A configuration variable: validate it in `config.go` so a bad value stops the
  boot, and document it in `.env.example` with a valid value. Read
  `docs/agents/playbooks/config-variable.md`.
