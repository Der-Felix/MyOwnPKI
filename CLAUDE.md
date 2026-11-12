# MyOwnPKI

Self-hosted PKI platform in Go: CA engine, ACME server + client, optional agent,
templ + htmx web UI, multiple SQLite databases. Status: phases 1 and 2 complete (v0.1.0 …
v0.2.2 released); phase 3 (agent, monitoring) in progress: v0.3.0 Linux agent, v0.3.1 packages and
guided installation, v0.3.2 agent package fix, v0.3.3 monitoring (alerts, e-mail and webhook
notifications) current; next v0.3.4 TLS scan (see docs/PLAN.md §10.1).

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

## Branches and worktrees

- The **main checkout** (the clone itself) always stays on `main`. Never `git checkout` or
  `git switch` another branch there. Work happens in a worktree next to it
  (forward slashes work in PowerShell and Git Bash):
  `git worktree add ../MyOwnPKI-wt/<branch> -b <branch> origin/main`
- One branch per release or topic, named only like this:
  - `release/vX.Y.Z` – preparing a release and the features of that release
  - `fix/<short>` – a single fix
  - `deps/<short>` – dependencies

  No more `night/` branches: a night run works on the `release/` branch of the planned release.
- If an open branch or PR already exists for the goal, keep working there – don't start a second one.
- After the merge GitHub deletes the branch; remove the worktree with `git worktree remove` and the
  local branch with `git branch -d`.
- The session never pushes, merges, tags or deletes remote branches – the maintainer does.

## Build and environment

- Builds are pure Go (`CGO_ENABLED=0`), except the `hsm` build tag. Targets: Linux, macOS, Windows, FreeBSD.
- Development must work the same on Windows (PowerShell, Git Bash), Linux and macOS – that's why
  the task runner is Taskfile. Start with `task` (list), `task check` (before every commit),
  `task dev` (UI prototype on http://127.0.0.1:9443/, gallery at /design).

## Personal settings

Personal preferences (conversation language, level of explanation, local machine) belong in
`CLAUDE.local.md` in the repository root. It is gitignored and loaded by Claude Code after this file.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
