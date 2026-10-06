---
okf_version: "0.2"
---

# Alora App Central — agent knowledge

How to change this repository safely, for AI agents and the people working with
them. Open the one concept you need; each points to the authoritative document
for what is true — [SPEC.md](../../SPEC.md) for behaviour,
[ARCHITECTURE.md](../../alora-auth-api/ARCHITECTURE.md) for structure.

- [Architecture map](./architecture.md) - The four projects, the request path, the API's layers and the data path, with pointers to the authoritative docs
- [Gotchas](./gotchas.md) - Behaviour, test and environment traps, each with what to do instead
- [Playbooks](./playbooks/index.md) - Step-by-step change procedures, each ending in the check that proves the change
- [Update log](./log.md) - Changes to this bundle, newest first

When a change alters a procedure described here, update the concept in the same
change, refresh its `generated` and `stale_after`, and add a line to the log.
Link relatively (`./gotchas.md`, `../../SPEC.md`): OKF reads a leading `/` from
the bundle root, GitHub from the repository root. Then check the agent files:
`bash .claude/hooks/agent-knowledge.sh check` runs the skill's validator and checks
every link.
