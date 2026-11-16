# Go conventions

## Module and layout

- Module path: `github.com/Der-Felix/MyOwnPKI` (matches the repository URL).
- Use the current stable Go release; set it in `go.mod` and CI.
- Layout as in `docs/PLAN.md` §8: `cmd/<binary>/main.go` stays thin (flags, config, wiring);
  logic lives in `internal/<area>`. Nothing is exported outside `internal/` until there's a reason.
- Dependencies point inward: `api`/`web` → services → `store`/`ca`/`keys`. Services don't import HTTP packages.

## Errors

- Wrap with context: `fmt.Errorf("issue certificate %q: %w", name, err)`.
- Domain errors as sentinel values or typed errors in the owning package (`ca.ErrNameConstraint`, `policy.ErrDenied`).
- HTTP API errors use RFC 9457 `application/problem+json`; ACME errors use the ACME problem types
  (`urn:ietf:params:acme:error:*`). Map domain errors in one place per surface.
- Never put secrets, key material or full CSRs in error strings.
- Message form: starts in lower case unless the first word is an acronym or a proper name (`URI is longer than …`,
  `ARI returned …`), no trailing punctuation, no newline.
- `%w` whenever an error is returned that has a cause; `errors.New` for a constant text (a `fmt.Errorf` without a verb
  is a lint finding, `perfsprint`).
- Wrap once, at the boundary that adds context (the function that knows the name, the path or the step), not again on
  every level on the way up.
- Texts that reach a client or the UI (`deny`, `problemErr`, `badRequest`, ACME and API problem details) are sentences
  with ` – ` between the clauses, written for the person who reads them. They are part of the API, tests and docs pin
  them, and they are changed only when they are wrong, never for style.

## Logging

- `log/slog` with JSON output in production, text in development.
- Structured fields (`slog.String("ca", name)`), no string concatenation.
- A redaction helper for anything that might carry secrets; audit events go to the audit log, not slog.

## Configuration

- One config file in **YAML** (decided in phase 0; strict decoding, unknown keys are errors) plus environment overrides (`MYOWNPKI_*`). Dev mode is a CLI flag only, never a config key.
- `internal/config`: `config.Load(path, os.Environ())` returns a validated `Config`; every key has a
  variable named after its path (`admin.listen` → `MYOWNPKI_ADMIN_LISTEN`), unknown `MYOWNPKI_*` names are
  errors. New keys go into the struct, `envFields`, `deploy/config.example.yaml` and the tests together.
- Parse into typed structs, validate at startup, fail fast with a clear message.
- No shell sourcing, no templating of config.

## Time

- UTC everywhere. Inject a clock (`interface{ Now() time.Time }`) into anything that checks validity,
  schedules renewals or writes audit entries, so tests can control time: `internal/clock`
  (`clock.System{}` in production, `clock.NewFake(t)` in tests). `time.Now` is a lint error elsewhere.

## SQLite (ADR-06)

- Driver `modernc.org/sqlite` (pure Go). One database per purpose and tenant (`system`, `pki`, `acme`, `audit`, `metrics`).
- Pragmas on open: `journal_mode=WAL`, `busy_timeout`, `foreign_keys=ON`, `synchronous=NORMAL`.
- Per database: one writer connection (`SetMaxOpenConns(1)` on the write handle) and a separate read pool.
- Migrations with the own runner `internal/store/migrate` (forward only, one transaction per migration,
  SHA-256 of every applied file is stored – a changed file stops the start), one set per database type in
  `internal/store/schema/<kind>/`, embedded via `embed.FS` and applied to every tenant DB at startup
  (`myownpki db migrate` does the same by hand).
- Queries with `sqlc`: one package per kind (`internal/store/<kind>db`), generated from the migration files
  and `internal/store/queries/<kind>/`. SQL files are ASCII only (sqlc bug, enforced by a test).
  New database type: see the comment on `store.Kinds`.
- A transaction never spans two databases. Use an outbox table + worker when a flow touches two
  (e.g. issuance in `pki.db` → audit entry in `audit.db`).
- Hot-path state (agent heartbeats, ACME nonces if needed) stays in memory; persist changes, not every tick.

## HTTP

- Standard library `net/http` with method + pattern routing; small middleware chain
  (recover, request ID, logging, auth, CSRF, security headers).
- One `http.Server` and one mux per listener (public / agent / admin).
- REST handlers generated from `api/openapi.yaml` (spec first).
- Agent protocol: Connect-RPC over mTLS, protobuf definitions in `proto/`.

## Crypto

- `crypto/x509`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/rsa`, `crypto/rand` only – no hand-rolled ASN.1
  unless the standard library lacks the extension (then use `golang.org/x/crypto/cryptobyte` and test against OpenSSL).
- Serial numbers: 159-bit random positive integers (fits the 20-octet limit with a leading 0 bit).
- OCSP: `golang.org/x/crypto/ocsp`. ACME client: `github.com/go-acme/lego/v4`.

## Testing

- Table-driven tests; `t.Parallel()` where safe; no sleeping – use the injected clock.
- Test keys and certificates are **generated in the test**, not committed (exception: fixed fixtures
  for parser regression tests, clearly marked and never real).
- Certificate output: assert on parsed fields with `crypto/x509`, and in integration tests cross-check
  with `openssl verify` / `openssl x509 -text` when OpenSSL is on the PATH (skip otherwise).
- Legacy importer: build a fixture PKI with `legacy/pki.sh` in CI and import it.
- ACME: integration tests with real clients (lego in-process; certbot/acme.sh in CI containers).
- `go test -race ./...` in CI.
- **Fuzz** every function that reads bytes from outside the trust boundary (CSR, upload, ACME payload, REST body,
  agent report, legacy archive): `func FuzzXxx(f *testing.F)` in a `_test.go` file next to it, one line in
  `scripts/ci/fuzz-targets.txt`. The target calls the production function **unchanged** (no copied logic, no lower
  limit), checks with code of its own what an accepted input must satisfy (round trip, canonical form, a bound), keeps
  an error text to a short piece of the input, and does no I/O. Seeds are `f.Add` calls in code; the only files under
  `testdata/fuzz/` are the inputs a crash produced, committed **with** the fix and a plain unit test of the rule.
  Details and the checklist: `docs/PHASE3.md` §18.2.
- `task cover` is a report, not a gate: a coverage table per package with integration tests credited to the code they
  exercise (`-coverpkg`). Read `task cover:func` for the gaps; don't chase a percent. A Windows number is not a Linux
  number (the table prints how many tests skipped). `task deadcode` lists functions nothing reaches: delete them or move
  a test-only helper into a `_test.go` file.

## Build and CI

- `CGO_ENABLED=0` for all default builds; `-tags hsm` + CGO only for the HSM variant.
- Task runner: **Taskfile** (decided in phase 0; runs the same in PowerShell and Git Bash). `task check` before every commit.
- CI (GitHub Actions): gofmt check, `go vet`, `golangci-lint`, `govulncheck`, tests with `-race`,
  `templ generate` / `sqlc generate` diff check, no-inline-style check, cross-compile matrix
  (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, freebsd/amd64), legacy ShellCheck (severity warning) and `legacy/tests/smoke.sh` (Linux; needs openssl),
  actionlint on the workflows (`task lint:ci`) and vacuum on the OpenAPI spec (`task lint:api`, rules in `api/vacuum.yaml`).
  Pull requests that change only documentation (`.claude/**`, `docs/**/*.md`, root `*.md`) skip the heavy jobs; `main` never does (`scripts/ci/changes.sh`, CONTRIBUTING.md).
- Releases with GoReleaser + cosign + SBOM; container image `ghcr.io/der-felix/myownpki`.

## Commits

- Conventional Commits in English (`feat(ca): add name constraint enforcement`).
- Small, reviewable commits; each one builds and passes tests.
