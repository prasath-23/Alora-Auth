# Update log

## 2026-10-04
- **Tooling**: Project hooks guard the agent files. An edit to one is refused until the session has loaded the OKF skill, each edit is checked as it lands, and `bash .claude/hooks/agent-knowledge.sh check` checks them all.

## 2026-10-03
- **Tooling**: The Open Knowledge Format skill (Apache-2.0) lives at `.claude/skills/okf-open-knowledge-format/`, so the bundle can be validated from the repository.
- **Creation**: Bundle created: the architecture map, gotchas, and playbooks for database changes (including enum values), HTTP routes and scopes, configuration variables, and running the stack and the tests.
- **Verification**: Commands, paths, test names and generator formats checked against the repository the same day, with `scripts/check-generated.sh` passing and the full API suite green.
