---
type: Playbook
title: Add or change an HTTP route
description: Router, guard, OpenAPI annotations, the scope table and the tests that enumerate every route; and how to add a scope.
tags: [api, routes, openapi, scopes, rate-limits]
status: stable
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-03T17:47:32Z }
stale_after: 2027-01-03T00:00:00Z
sources:
  - id: main
    resource: ../../../alora-auth-api/cmd/api/main.go
    title: newRouter — route registration and per-route budgets
  - id: scopestest
    resource: ../../../alora-auth-api/cmd/api/scopes_test.go
    title: adminRoutes and TestEveryAdminRouteNeedsItsScope
  - id: docstest
    resource: ../../../alora-auth-api/cmd/api/docs_contract_test.go
    title: TestTheAPIDocumentDescribesExactlyTheRouter
  - id: registry
    resource: ../../../alora-auth-api/internal/core/shared/scopes.go
    title: The scope registry
---

# Add or change an HTTP route

1. **Handler** in `internal/core/<feature>/controller/`. Bind JSON with
   `shared.BindJSON`, which refuses unknown fields and non-JSON bodies. Fail with
   `exceptions.Fail(c, err)` and let `MapError` choose the status — never write
   an error body yourself.
2. **Register it** in `newRouter` (`alora-auth-api/cmd/api/main.go`), in its
   group:[^main]
   - `/api/admin/…` — guarded with `need(shared.Scope…)`. A read scope never
     opens an edit route.
   - `/api/owner/…` — behind `RequireOwner`. A write under a company must take
     the `X-Alora-Target-Company` echo, as the Owner controller's other writes do.
   - `/auth/…` — cookie-bearing and same-origin; every route here has a rate
     limiter.
   - `/oauth/…` — form-urlencoded bodies and HTTP Basic, for products and
     applications.
3. **Annotate** the handler for the OpenAPI document (`@Summary`, `@Param`,
   `@Success`, `@Failure`, `@Router /path [method]`, as the neighbouring handlers
   do), then regenerate it:
   ```bash
   cd alora-auth-api
   go run github.com/swaggo/swag/cmd/swag@v1.16.6 init -g cmd/api/swagger.go -o docs --parseInternal --parseDepth 2
   ```
   `TestTheAPIDocumentDescribesExactlyTheRouter` fails until the document and the
   router agree.[^docstest]
4. **Scope table.** A new `/api/admin` route needs a row in `adminRoutes` in
   `cmd/api/scopes_test.go`. `TestEveryAdminRouteNeedsItsScope` compares that
   table with the router and fails on a route that has no row.[^scopestest]
5. **Free coverage.** `hostile_input_test.go`, `credentials_matrix_test.go`,
   `docs_contract_test.go` and `scopes_test.go` walk `a.r.Routes()`, so a new
   route is sent hostile input and bad credentials automatically. It must answer
   4xx, never 5xx.
6. **Rate limit.** Per-route budgets are built in `newRouter` with
   `scaled(max, window)`. A budget an attacker would want to multiply — password
   guesses, client secrets — should be `rateLimiter(m.rlStore, "<unique-name>", max, window)`,
   so that `RATE_LIMIT_STORE=database` shares it across instances.
7. **The SPA**: calls live in `alora-auth-ui/src/services/`. Input limits must equal
   the API's: `src/utils/limits.js`, checked by `e2e/limits.spec.js`.
8. **The contract**: list the endpoint in SPEC.md §1, and update §2 if a
   security invariant changes.

## Adding a scope

Scopes form a closed catalogue kept in three places that must agree:

- the registry, `internal/core/shared/scopes.go`;[^registry]
- the `tbl_scopes` seed rows (`SEEDS` in `alora-auth-db/gen_tables.py`; run the
  [database-change](./database-change.md) steps);
- the SPA's labels, `alora-auth-ui/src/utils/scopes.js`.

`TestTheScopeCatalogueMatchesTheRegistry` keeps the first two in step. Update the
scope table in SPEC.md §2 as well. An edit scope always brings its read scope with
it.

[^main]: newRouter — route registration and per-route budgets
[^docstest]: TestTheAPIDocumentDescribesExactlyTheRouter
[^scopestest]: adminRoutes and TestEveryAdminRouteNeedsItsScope
[^registry]: The scope registry
