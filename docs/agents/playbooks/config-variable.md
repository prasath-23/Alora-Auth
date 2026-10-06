---
type: Playbook
title: Add a configuration variable
description: Read it in config.go with a failing validator, document it in .env.example, and keep the parity test green.
tags: [config, environment]
status: stable
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-03T17:47:32Z }
stale_after: 2027-01-03T00:00:00Z
sources:
  - id: config
    resource: ../../../alora-auth-api/internal/config/config.go
    title: Load and its helpers
  - id: configtest
    resource: ../../../alora-auth-api/internal/config/config_test.go
    title: TestEnvExampleMatchesWhatLoadReads
  - id: example
    resource: ../../../alora-auth-api/.env.example
    title: The documented environment
---

# Add a configuration variable

All configuration is read once, by `Load()` in
`alora-auth-api/internal/config/config.go`. The server refuses to start on
anything missing, retired or invalid, so a misconfiguration fails at boot rather
than at the first request.[^config]

1. **Read it with a helper**: `getenv(key, default)`, `intEnv(key, def, min, max)`,
   `boolEnv` or `durationEnv`. The typed helpers fail on a value that is set but
   invalid; they never fall back to the default silently.
2. **Fixed choices**: validate with a `switch` allowlist and return an error that
   names the variable, as `NODE_ENV` and `RATE_LIMIT_STORE` do — a typo must stop
   the boot.
3. **Required** variables go in `requiredEnv`. Replacing an old variable? Put the
   old name in `retiredEnv` with a message, so starting with it set fails instead
   of being ignored.
4. Add the field to the config structs and set it in `Load()`.
5. **Document it** in `alora-auth-api/.env.example`, with a comment and a valid
   value. `TestEnvExampleMatchesWhatLoadReads` fails if `Load` reads a variable the
   example lacks, or the example sets one `Load` never reads, and it loads the
   example to prove it starts.[^configtest]
6. **Tests**: `testEnv` in `cmd/api/integration_test.go` sets the integration
   environment. Override per test with
   `newAppWith(t, map[string]string{"NAME": "value"}, nil)`.
7. **Operators** need to know about anything that matters in production: add it to
   the README's production notes, or ARCHITECTURE.md §8.

[^config]: Load and its helpers
[^configtest]: TestEnvExampleMatchesWhatLoadReads
