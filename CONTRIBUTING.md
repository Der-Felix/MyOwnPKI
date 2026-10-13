# Contributing to MyOwnPKI

Thanks for your interest. MyOwnPKI is a certificate authority, so the bar for correctness and
security is high – but the rules below are short.

**Security problems are not reported here:** please follow [SECURITY.md](SECURITY.md) and report
them privately, never as a public issue or pull request.

## Before you start

- Read [docs/PLAN.md](docs/PLAN.md): the architecture, the decisions (ADRs, §2) and the roadmap
  (§10). The current work plan is [docs/PHASE1.md](docs/PHASE1.md).
- For anything larger than a small fix, open an issue first and describe what you want to change.
  Features from a later phase are usually not merged early.
- **ADRs are deliberate trade-offs.** If your change conflicts with one, propose an ADR change in
  the issue instead of working around it.

## Development setup

Requirements: Go (the toolchain is pinned in `go.mod` and downloaded automatically),
[Task](https://taskfile.dev) and [golangci-lint](https://golangci-lint.run) – versions in
`Taskfile.yml`. Everything works the same in PowerShell, Git Bash, Linux and macOS.

```sh
task              # list all tasks
task check        # formatting, lint, tests, build – must pass before every commit
task dev          # UI prototype at http://127.0.0.1:9443/ (no TLS, no login, loopback only)
```

## Rules for changes

- **`task check` passes** for every commit. CI additionally runs the race detector, the
  generated-code check, `govulncheck`, the cross-compile matrix and the legacy suite checks.
- **English** for code, comments, UI text, docs and commit messages, US spelling (ADR-17).
- **Pure Go**: builds use `CGO_ENABLED=0`; CGO only behind the `hsm` build tag (ADR-01).
- **New dependencies need approval first** (open an issue). Only permissive licenses (MIT, BSD,
  Apache-2.0, ISC, MPL-2.0); no GPL/AGPL (ADR-14). No Node.js/Bun in the product or build (ADR-04).
- **Web UI**: no inline styles or scripts, only the global classes in `web/styles/` (ADR-12);
  tests enforce this.
- **Certificates**: extensions come from presets and policy, never from the CSR; CSRs, uploads
  and ACME payloads are untrusted input. Tests that produce certificates parse them with
  `crypto/x509` and, where available, cross-check with `openssl verify`.
- **Time**: UTC everywhere, with an injected clock in tests – no sleeping, no wall time.
- **Generated code** (templ, later sqlc and the OpenAPI code) is regenerated with `task generate`
  and committed.
- **API changes** go into `api/openapi.yaml` first (ADR-05).

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/) in English, for example
  `feat(ca): enforce name constraints on issuance` or `fix(web): keep filters after paging`.
  Types in use: `feat`, `fix`, `docs`, `test`, `build`, `ci`, `chore`, `refactor`.
- Small commits that each build and pass `task check`; explain the *why* in the body.
- Pull requests describe what changed, how to verify it, and link the issue.

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), like the rest of the project.
