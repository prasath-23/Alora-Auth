---
paths:
  - "alora-auth-db/**"
  - "gen_*.py"
  - "*.sql"
---

# Working in alora-auth-db

- The `.sql` files under `Tables/`, `Views/`, `Programmability/Functions/`,
  `Programmability/StoredProcedures/`, and `build.sql`, are generated. Edit the
  owning `gen_*.py`, then run it and `python gen_build.py`. Hand-written files:
  `Programmability/Types/enums.sql`, `Security/roles.sql`, `Migrations/*`, `api/*.sql`.
- Before changing anything here, read
  `docs/agents/playbooks/database-change.md`. It covers `TABLE_ORDER`, the
  `roles.sql` grants, the sqlc `RETURNS TABLE` trap, enum migrations, and the
  proof steps.
