@AGENTS.md

## Claude Code

- Rules in `.claude/rules/` load just in time: `database.md` when you open
  anything under `alora-auth-db/`, and `api-surface.md` for routes, controllers
  and configuration.
- Skill `okf-open-knowledge-format` (`.claude/skills/`): the format of the agent
  files. Hooks in `.claude/settings.json` refuse an edit to `CLAUDE.md`,
  `AGENTS.md`, `.claude/rules/`, `.claude/agents/` or `docs/agents/` until you
  load it, then check each edit (`.claude/hooks/agent-knowledge.sh`).
- Subagents in `.claude/agents/`:
  - `qa-tester` — black-box QA of the running stack on localhost: the HTTP API
    plus Playwright.
  - `change-verifier` — proves a change: generated files, build, and the focused
    and full suites, summarised.
- The full API suite, Playwright, and the first build after sqlc changes take
  minutes. Run them in the background or hand them to `change-verifier`.
- Personal working preferences live in auto-memory, not in this file.
