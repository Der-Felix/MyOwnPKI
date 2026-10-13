# MyOwnPKI

Self-hosted PKI platform in Go: CA engine, ACME server + client, optional agent,
templ + htmx web UI, multiple SQLite databases. Status: phase 0 (foundation) complete – phase 1 next.

- **Source of truth:** `docs/PLAN.md` (architecture, ADR-01…20, roadmap); current work plan in `docs/PHASE1.md`.
- **Always use the `myownpki` skill** (`.claude/skills/myownpki/`) before working on code,
  schemas, APIs, certificates or reviews – it holds the non-negotiables and the reference rules.
- `legacy/` is the original Bash suite (offline root tool, reference for presets and on-disk format).

## Contribution rules

- Code, comments, UI text, docs and commit messages in **English** (ADR-17, US spelling).
- Ask the maintainer before adding a dependency, changing an ADR, or anything that publishes
  (pushes, releases, container images).
- Conventional Commits; small commits that each build and pass `task check`.
- Don't commit or push on your own unless the maintainer asked for it.

## Build and environment

- Builds are pure Go (`CGO_ENABLED=0`), except the `hsm` build tag. Targets: Linux, macOS, Windows, FreeBSD.
- Development must work the same on Windows (PowerShell, Git Bash), Linux and macOS – that's why
  the task runner is Taskfile. Start with `task` (list), `task check` (before every commit),
  `task dev` (UI gallery on http://127.0.0.1:9443/design).

## Personal settings

Personal preferences (conversation language, level of explanation, local machine) belong in
`CLAUDE.local.md` in the repository root. It is gitignored and loaded by Claude Code after this file.
