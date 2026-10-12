# MyOwnPKI

Self-hosted PKI platform in Go: CA engine, ACME server + client, optional agent,
templ + htmx web UI, multiple SQLite databases. Status: phase 0 (foundation) complete – phase 1 next.

- **Source of truth:** `docs/PLAN.md` (architecture, ADR-01…20, roadmap).
- **Always use the `myownpki` skill** (`.claude/skills/myownpki/`) before working on code,
  schemas, APIs, certificates or reviews – it holds the non-negotiables and the reference rules.
- `legacy/` is the original Bash suite (offline root tool, reference for presets and on-disk format).

## Working agreement

- Talk to the owner in **German**; write code, comments, UI text, docs and commits in **English**.
- The owner is a systems integrator, not a developer: explain in operations terms, give verification
  commands, and teach PKI concepts when relevant (not Go).
- Ask before adding dependencies, changing an ADR, or anything that publishes.
- Commit only when asked; **never push** without explicit confirmation.

## Environment

- Dev machine: Windows Server 2025, Git Bash + PowerShell. Targets: Linux, macOS, Windows, FreeBSD.
- Builds are pure Go (`CGO_ENABLED=0`), except the `hsm` build tag.
