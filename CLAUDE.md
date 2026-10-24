# MyOwnPKI

Self-hosted PKI platform in Go: CA engine, ACME server + client, optional agent,
templ + htmx web UI, multiple SQLite databases. Status: phases 1 and 2 complete (v0.1.0 released;
v0.2.0 ACME server released; v0.2.1-rc.1 systemd installation in production; v0.2.2 = own TLS, daily backup, trust page – built, not released); phase 3 (agent, monitoring) next.

- **Source of truth:** `docs/PLAN.md` (architecture, ADR-01…20, roadmap); work plans of the finished phases in `docs/PHASE1.md` and `docs/PHASE2.md`.
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
  `task dev` (UI prototype on http://127.0.0.1:9443/, gallery at /design).

## Personal settings

Personal preferences (conversation language, level of explanation, local machine) belong in
`CLAUDE.local.md` in the repository root. It is gitignored and loaded by Claude Code after this file.
