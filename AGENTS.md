# AGENTS.md — Alora App Central

Instructions for AI coding agents in this repository. People: start at
[README.md](README.md).

Alora App Central is the identity provider for Alora's B2B products. It handles
sign-in (password, Google, company SSO), a launcher, company administration and
the platform Owner's console, and it is an OpenID Provider that gives each
product tokens of its own. Four projects share this repository; each builds and
tests on its own.

| Project | Role | Stack |
|---|---|---|
| `alora-auth-db` | The schema and every stored procedure — the only SQL there is | PostgreSQL 16 |
| `alora-auth-api` | App Central's API, the OpenID Provider, the gRPC token door | Go 1.26, Gin, pgx, sqlc |
| `alora-auth-ui` | The SPA and a sample product backend; the Playwright suite | React 18, Vite |
| `alora-auth-go` | What products and applications import: protos, token verifier, client credentials | Go 1.26, gRPC |

## Read first

- [SPEC.md](SPEC.md) — the contract: endpoints (§1) and the security invariants
  that must survive (§2). Update it whenever you change behaviour.
- [alora-auth-api/ARCHITECTURE.md](alora-auth-api/ARCHITECTURE.md) — layers,
  middleware order, security architecture.
- [BACKLOG.md](BACKLOG.md) — work not built yet.
- [docs/agents/](docs/agents/index.md) — an architecture map, change playbooks and
  gotchas. Open only the one you need.

## Rules the build enforces

| Rule | Enforced by | How to comply |
|---|---|---|
| The API runs no ad-hoc SQL. Every database call is a stored procedure or function, bound by sqlc and reached through a table service. | `TestArchitecture`, `check-generated.sh` | [database-change](docs/agents/playbooks/database-change.md) |
| Database objects are generated. Edit `alora-auth-db/gen_*.py`, never the `.sql` under `Tables/`, `Views/`, `Programmability/Functions/`, `Programmability/StoredProcedures/`, nor `build.sql`. | `scripts/check-generated.sh` | same |
| Layering, e.g. `middlewares` imports only `exceptions` and `core/shared`, only `internal/database` imports `sqlc`, gin and gRPC stay in controllers, middlewares and `cmd/api`. | `TestArchitecture` | [architecture map](docs/agents/architecture.md) |
| A new table is granted to `alora_app` in `Security/roles.sql`, which starts from `REVOKE ALL`. | tests run as `alora_app`; `TestAppRoleHoldsWhatTheRoutinesNeed` | database-change |
| A new enum value needs `enums.sql` and a migration. | built databases never re-run `enums.sql` | database-change, "Enum values" |
| Every variable `Load()` reads is documented in `alora-auth-api/.env.example`, with a valid value. | `TestEnvExampleMatchesWhatLoadReads` | [config-variable](docs/agents/playbooks/config-variable.md) |
| The OpenAPI document matches the router, and every `/api/admin` route has a row in the scope table. | `TestTheAPIDocumentDescribesExactlyTheRouter`, `TestEveryAdminRouteNeedsItsScope` | [route-change](docs/agents/playbooks/route-change.md) |
| Generated code is checked in and current: sqlc bindings, the OpenAPI document, the protos' Go code. | `check-generated.sh` | regenerate, never hand-edit |
| `alora-auth-go` never imports App Central. | `TestTheGoModuleStandsAlone` | — |

## Changing the agent files

`CLAUDE.md`, this file, `.claude/rules/`, `.claude/agents/` and `docs/agents/` are
the agent files. They follow the `okf-open-knowledge-format` skill in
`.claude/skills/`: load it, or read its `SKILL.md`, before your first edit to them.
Two rules go further than OKF: every relative link resolves, and links in
`docs/agents/` are relative, because GitHub reads a leading `/` from the repository
root. `bash .claude/hooks/agent-knowledge.sh check` checks all of it, the skill's
validator included. In Claude Code, the project hooks in `.claude/settings.json`
refuse an edit to an agent file until the session has loaded the skill, and check
each edit as it lands.

## Commands

```bash
cd alora-auth-api && bash scripts/integration-test.sh     # API suite as alora_app on a throwaway Postgres; add -run 'Pattern'
cd alora-auth-db && python gen_procedures.py && python gen_build.py   # after editing a generator (run the ones you edited)
cd alora-auth-api && sqlc generate && go build ./...      # after changing alora-auth-db/api/*.sql or a routine's signature
bash scripts/check-generated.sh                           # every generated file matches its source
cd alora-auth-go && go test ./...                         # the Go helper
```

End to end: `alora-auth-api/scripts/e2e-up.sh`, then `npx playwright test` in
`alora-auth-ui`, then `e2e-up.sh --down`. Integration tests skip without
`ALORA_TEST_DB`, so a one-second `ok` means nothing ran. For faster loops, see
[dev-and-test](docs/agents/playbooks/dev-and-test.md).

## Done means

- The behaviour is covered by a test, and the suites pass after really running.
- `bash scripts/check-generated.sh` passes.
- SPEC.md is updated when the contract or a security invariant changed;
  ARCHITECTURE.md and the README when structure or operations changed.
- BACKLOG.md: delete an item only when every one of its "Done when" lines holds,
  and add any future work you found.
- An agent file changed: `bash .claude/hooks/agent-knowledge.sh check` passes.

## Conventions

- The company always comes from the token, never from a request body. Another
  company's ids answer 404.
- Services return sentinels or `exceptions.APIError`; controllers call
  `exceptions.Fail`; `MapError` decides the status. Internal error text never
  reaches a response.
- Keep SPEC.md §2's invariants exactly as written unless changing one is the point,
  and then change SPEC.md with it.
- Windows: run the shell scripts from Git Bash.
