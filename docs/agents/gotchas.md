---
type: Reference
title: Gotchas
description: Behaviour, test and environment traps, each with what to do instead.
tags: [testing, tokens, owner, rate-limits, pitfalls]
status: stable
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-03T17:47:32Z }
stale_after: 2027-01-03T00:00:00Z
sources:
  - id: harness
    resource: ../../alora-auth-api/cmd/api/integration_test.go
    title: Integration test harness — testEnv, newApp, newAppWith
  - id: rotation
    resource: ../../alora-auth-api/internal/core/session/service/session_service.go
    title: Refresh rotation and the grace window
  - id: csrf
    resource: ../../alora-auth-api/internal/middlewares/csrf.go
    title: SameOriginOnly
  - id: gate
    resource: ../../alora-auth-db/Views/vw_SessionFamilyGate.sql
    title: The session gate
---

# Gotchas

Each entry: the surprise, then what to do. Environment and tooling traps are in
[dev-and-test](./playbooks/dev-and-test.md).

## Tests

- **A one-second `ok` means the integration tests skipped.** `testEnv` skips
  unless `ALORA_TEST_DB`, `ALORA_TEST_PRIV` and `ALORA_TEST_PUB` are set; a real
  `cmd/api` run takes minutes.[^harness] Use `scripts/integration-test.sh`, or
  export the variables for a dev database.
- **Fixtures fail the test when the database refuses.** `newMember`, `join`,
  `grant`, `grantGroup`, `subscribe` and the other fixtures call `t.Fatalf` on any
  error. To assert a refusal, call the table service on `a.owner` and inspect the
  error — `seats_test.go` does this with `exceptions.IsSeatLimit`.
- **The global rate limit trips before route budgets.** It counts every request
  per address (`RATE_LIMIT_GLOBAL_MAX`, default 100 a minute). A test sending
  hundreds of requests needs `newAppWith(t, map[string]string{"RATE_LIMIT_GLOBAL_MAX": "100000"}, nil)`,
  or `hostileEnv` in `hostile_input_test.go`.

## Tokens and sessions

- **A replayed refresh token is 409 inside the grace window.** For 30 seconds after
  a rotation (`PrevTokenGrace`) a replay counts as a benign concurrent refresh: 409,
  and the session survives. Only later is it theft — 401, and the whole login
  burned.[^rotation] Tests age `revoked_at` with SQL rather than sleep (see
  `TestCentralRefreshRotatesAndDetectsReplay`).
- **`aud` is an array.** Check membership, not equality. A product token
  (`product:<key>`) is refused at `/api`, and an App Central token by products — by
  design.
- **The session gate reads `is_active`, not `subscription_status`.** Sign-in, the
  gate and product access all check `tbl_clients.is_active`;[^gate] nothing at
  runtime reads `subscription_status`. The Owner console's Suspend is
  `is_active: false`, which also ends the company's sessions in the same
  transaction (reason `SUSPENDED`).

## Requests

- **Same-origin is decided by headers.** A state-changing request whose
  `Sec-Fetch-Site` is anything but `same-origin` or `none`, or whose `Origin` is
  foreign, gets 403; one with neither header is treated as a non-browser client and
  passes.[^csrf] JSON routes refuse other content types (415) and unknown fields
  (400).
- **The token endpoint takes forms and HTTP Basic only.** `/oauth/token`, `/revoke`
  and `/introspect` refuse JSON bodies, answer `invalid_client` to a
  `client_secret` in the body, and ignore query-string parameters. The id and the
  secret are each form-encoded before the base64 step.
- **Owner writes echo the company.** Every write under
  `/api/owner/companies/:cid` must send `X-Alora-Target-Company: <cid>`; a missing
  or different value is 400. The Owner console also needs a sign-in younger than
  `OWNER_MAX_AUTH_AGE` (12 hours).

## Limits

- **A seat is taken at invitation accept, not at invite.** `max_seats` is checked
  in `stp_CreateUser` (accepting an invitation) and `stp_SetUserActive`
  (reactivating). `seat_limit` is checked on every grant that widens product access.
  Over a limit is SQLSTATE `AL001`, which `MapError` turns into 409.
- **A limiter on the shared store needs a unique name.** With
  `RATE_LIMIT_STORE=database`, keys are stored as `<name>:<key>`, so two limiters
  sharing a name would share a budget. Build one with
  `rateLimiter(m.rlStore, "<name>", max, window)`.

[^harness]: Integration test harness — testEnv, newApp, newAppWith
[^rotation]: Refresh rotation and the grace window
[^gate]: The session gate
[^csrf]: SameOriginOnly
