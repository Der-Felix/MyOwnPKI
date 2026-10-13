# Trial: ogen vs. hand-written API handlers (phase 1, step 3)

**Decision (owner, 2026-10-13): hand-written handlers with `net/http`, no generator.** The spec
stays the source of truth through contract tests (PHASE1 step 16, PLAN §14 "API draft"). The trial
code lived on the branch `trial/ogen`, which was deleted after the decision; this page keeps the
results.

2026-10-13. Same three endpoints in both variants – `GET /health`,
`GET /presets`, `GET /presets/{presetName}` – checked by one shared test
(`internal/api/trialcompare`): 200, 401 (missing and wrong token), 404, 400 (invalid
parameter), 405 with `Allow`, unknown endpoint; all errors as RFC 9457 problems. Both pass.

| | ogen v1.24.0 | hand-written (`net/http`, `encoding/json`) |
|---|---|---|
| Code for 3 endpoints | 4,034 generated lines + 164 own | 178 own |
| Whole API | 45,440 generated lines (server only); **2 of 49 operations not supported**: `issueCertificate` (oneOf csr_pem/key), `startLegacyImport` (multipart with `ca_passphrase[<name>]` fields) | grows with the endpoints; shared helpers (problem, auth, JSON) are written once |
| Runtime modules in the server binary | **27** (ogen runtime, OpenTelemetry, zap, fatih/color, go-faster/*, two extra YAML libraries incl. unmaintained `ghodss/yaml` and deprecated `gopkg.in/yaml.v2`, regexp2, `golang.org/x/exp` from 2023, …) | **0** |
| Licenses | all permissive (MIT, BSD-3, Apache-2.0) | – |
| Binary size (linux/amd64, 3 endpoints) | 12.1 MB (+1.8 MB, +18 %) | 10.3 MB |
| RFC 9457 errors | possible, but the default error handler writes `{"error_message": err.Error()}` (not RFC 9457, may leak internals) – must always be replaced; typed problem responses per status | written directly; ServeMux 404/405 wrapped into problems |
| Input validation | generated from the schema (pattern, enum, length, required) | written by hand per field; must be guarded by contract tests |
| Fit with net/http and our middleware | the server is an `http.Handler` with its own router, mounted with a path prefix – our middleware wraps it unchanged. Handlers get `ctx` and typed params, **no `ResponseWriter`/`Request`**: cookies (login, logout, session rotation) and headers (`Content-Disposition`) only if declared as response headers in the spec (none today) | ServeMux patterns (`GET /api/v1/presets/{presetName}`) like the UI; full access to request and response |
| Security requirements | spec security (session+CSRF or bearer) enforced by generated code; `x-required-role` is not understood (roles only via security scopes) | middleware per route; role per route, checked against the spec by a test |
| Spec changes needed | rename security scheme `session` (name clash with schema `Session`); restructure the two unsupported operations; declare `Set-Cookie`/`Content-Disposition` headers | none |
| govulncheck / lint | clean / clean (generated files are skipped) | clean / clean |
