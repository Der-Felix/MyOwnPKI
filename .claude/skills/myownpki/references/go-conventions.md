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

## Logging

- `log/slog` with JSON output in production, text in development.
- Structured fields (`slog.String("ca", name)`), no string concatenation.
- A redaction helper for anything that might carry secrets; audit events go to the audit log, not slog.

## Configuration

- One config file (YAML or TOML – decide in phase 0) plus environment overrides (`MYOWNPKI_*`).
- Parse into typed structs, validate at startup, fail fast with a clear message.
- No shell sourcing, no templating of config.

## Time

- UTC everywhere. Inject a clock (`interface{ Now() time.Time }`) into anything that checks validity,
  schedules renewals or writes audit entries, so tests can control time.

## SQLite (ADR-06)

- Driver `modernc.org/sqlite` (pure Go). One database per purpose and tenant (`system`, `pki`, `acme`, `audit`, `metrics`).
- Pragmas on open: `journal_mode=WAL`, `busy_timeout`, `foreign_keys=ON`, `synchronous=NORMAL`.
- Per database: one writer connection (`SetMaxOpenConns(1)` on the write handle) and a separate read pool.
- Queries with `sqlc`; migrations with `goose`, embedded via `embed.FS`, one migration set per database type,
  applied to every tenant DB at startup.
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

## Build and CI

- `CGO_ENABLED=0` for all default builds; `-tags hsm` + CGO only for the HSM variant.
- Cross-platform task runner (Taskfile or Make – decide in phase 0; the owner develops on Windows).
- CI (GitHub Actions): gofmt check, `go vet`, `golangci-lint`, `govulncheck`, tests with `-race`,
  `templ generate` / `sqlc generate` diff check, no-inline-style check, cross-compile matrix
  (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, freebsd/amd64), legacy ShellCheck.
- Releases with GoReleaser + cosign + SBOM; container image `ghcr.io/der-felix/myownpki`.

## Commits

- Conventional Commits in English (`feat(ca): add name constraint enforcement`).
- Small, reviewable commits; each one builds and passes tests.
