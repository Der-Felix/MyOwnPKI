---
name: myownpki
description: Project guide for MyOwnPKI, a self-hosted PKI platform in Go (CA engine, ACME server/client, agent, templ+htmx web UI, multi-SQLite storage). Use this skill for ANY work in the MyOwnPKI repository – implementing features, designing APIs or database schemas, writing Go, templ, CSS or TypeScript, touching X.509 certificates, CSRs, CRL/OCSP, ACME, agent enrollment, authentication or key handling, planning a phase, or reviewing a change – even for small edits, because the architecture decisions (ADRs), PKI correctness rules and security constraints apply everywhere and are easy to violate by accident.
---

# MyOwnPKI

MyOwnPKI turns the Bash PKI suite in `legacy/` into a self-hosted, enterprise-grade PKI
platform: secure web UI, REST API, ACME server for the internal CA, ACME client for
Let's Encrypt, and an optional agent that deploys and monitors certificates.
The full plan, all ADRs and the roadmap are in `docs/PLAN.md` – that file is the source of truth.

## How to work in this repository

The maintainer makes the product and operations decisions. Personal preferences (conversation
language, level of explanation, local environment) are in `CLAUDE.local.md` if present – follow it.

- Write all code, comments, commit messages, UI text and docs in **English** (ADR-17).
- Explain decisions in **operations terms**: what changes for an admin, how to verify it, what can break.
- Give **commands to verify** each step (`task check`, `go test ./...`, `openssl x509 -in … -text`, `curl …`).
- When a change rests on a PKI rule (why a key usage is critical, why a root can't be revoked),
  name the rule and its source (RFC, CA/B Forum) – reviewers check against it.

## Before starting any task

1. **Find the phase.** Check the roadmap in `docs/PLAN.md` §10. Build what the current phase
   needs; don't pull later-phase features forward unless asked. A small seam for later (an
   interface, a TODO with an ADR reference) is fine – a half-built feature is not.
2. **Check the ADRs** (`docs/PLAN.md` §2). If the task conflicts with one, stop and say so.
   Propose an ADR change instead of silently deviating – the ADRs exist because each was a
   deliberate, documented trade-off.
3. **Read the reference file** for the area you are touching (table below). They are short.
4. **Ask before**: adding a dependency, changing an ADR, changing a released DB schema or API,
   anything that publishes (git push, releases, container pushes).

## Non-negotiables (and why)

| Rule | Why |
|---|---|
| One issuance path: **ACME** (ADR-19). UI/API issuance and the agent go through the same policy engine | One place to enforce policy and audit; no back door that bypasses domain rules |
| **CSR contents, uploads and ACME payloads are attacker input** | A CN like `<script>` or a SAN outside the allowed domains must never reach the UI unescaped or the certificate unchecked |
| Extensions come from the **preset/policy**, never copied from the CSR | Copying a CSR's `basicConstraints CA:TRUE` would mint a rogue CA |
| **Pure Go builds** (`CGO_ENABLED=0`); CGO only behind the `hsm` build tag | Single static binary for Linux/macOS/Windows/FreeBSD (ADR-01) |
| **No Node.js/Bun** in the product or the build; TypeScript is bundled with esbuild as a Go library | No npm supply chain in a CA (ADR-04). Node is tolerated only for optional E2E tests |
| **No inline styles, no inline scripts**; only the global classes in `web/styles/` | Strict CSP and consistent design (ADR-12) |
| **Status colours are fixed**, themes only change tokens | A theme must never make "expired" look like branding |
| **One transaction = one database** | SQLite files are separate (ADR-06); cross-DB atomicity doesn't exist |
| **No secrets in logs**, keys never written unencrypted | Logs end up in SIEMs and support tickets |
| **Licenses:** only permissive dependencies (MIT, BSD, Apache-2.0, ISC, MPL-2.0 file-level OK); no GPL/AGPL | Project is Apache-2.0 and must stay embeddable (ADR-14) |
| **UTC everywhere**, injectable clock | Certificate validity tests must not depend on wall time |

## Reference files – read the one(s) you need

| File | Read when |
|---|---|
| `references/pki-rules.md` | Anything with certificates, CSRs, presets, CAs, CRL, OCSP, ACME, validity, name constraints, the legacy importer |
| `references/security.md` | Auth, sessions, RBAC, key storage/unseal, uploads, agent trust, ACME validation (SSRF), audit log |
| `references/go-conventions.md` | Writing Go: layout, errors, logging, config, SQLite/sqlc/migrations, testing, build, CI |
| `references/frontend.md` | templ pages, htmx, layouts A/B/C, CSS classes and tokens, themes, charts/islands |

## Definition of done (every change)

- `task check` green (formatting, `golangci-lint` incl. vet, tests, build); `task vuln` clean
- Tests for the change: unit tests, plus an integration test when certificates are produced
  (parse the output with `crypto/x509` **and**, when available, cross-check with `openssl verify`)
- Generated code is regenerated and committed (`task generate`: templ, later sqlc). API handlers are hand-written – contract tests keep them in line with `api/openapi.yaml`
- API changes are in `api/openapi.yaml` first, then implemented
- `docs/PLAN.md` updated if a decision or the scope changed
- A short summary: what changed, how to verify it, what's next
- A proposed commit message (Conventional Commits, English) – commit only when asked, never push without asking

## Legacy script

`legacy/` holds the original Bash suite (`pki.sh` + `lib/*.sh`). It is the reference for presets
(`lib/presets.sh`), extensions (`lib/issue.sh`, `lib/ca.sh`), deployment guides (`lib/export.sh`)
and the on-disk format the importer must read. Keep it working as the offline root tool, but put
new features into the Go code.
