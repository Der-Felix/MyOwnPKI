# Night log – Phase 0, steps 4–8

> Autonomous run, night of 2026-10-12 → 2026-10-13. Rules: local commits only, never push,
> only approved dependencies (templ, govulncheck, go.yaml.in/yaml/v3), no ADR changes,
> reversible choices documented here.
>
> This file is written in English (ADR-17); the morning summary for the owner is in German
> at the end.

## Step 4 – CI (GitHub Actions) and Dependabot

### Done
- `.github/workflows/ci.yml` with jobs:
  - `check`: `task check` (tools, fmt, lint, test, build) + `task generate:check`
  - `race`: `task test:race` (CGO only here – the race detector needs a C compiler)
  - `test-os`: `go test ./...` natively on `windows-2025` and `macos-15`
  - `cross`: `task cross` (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, freebsd/amd64)
  - `vuln`: `task vuln` – on every push/PR **and daily at 04:17 UTC** (all other jobs skip the schedule)
  - `shellcheck`: legacy sources + the compiled standalone script
- `.github/actions/setup/action.yml`: shared setup (Go, Task, optional golangci-lint and sqlc)
- `.github/dependabot.yml`: weekly grouped PRs for Go modules and GitHub Actions
- `Taskfile.yml`: `SQLC_VERSION` 1.31.1; `tools:check` verifies sqlc once `sqlc.yaml` exists

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| Third-party actions pinned to **commit SHA** (checkout v7.0.1, setup-go v7.0.0), not tags | A tag can be moved to malicious code after the fact; a SHA cannot. For a CA's build pipeline that matters | Replace SHA with tag |
| Only GitHub's own actions; golangci-lint, ShellCheck and sqlc downloaded with **pinned SHA-256** instead of their marketplace actions | Fewer third parties with code execution in CI; checksum detects a swapped release file | Use `golangci/golangci-lint-action` etc. |
| `GOTOOLCHAIN=local` in CI | CI must use exactly the Go installed by setup-go; `tools:check` then proves it is 1.27.2 | Remove the env var |
| `permissions: contents: read`, `persist-credentials: false` | Least privilege: a compromised step cannot push or read a token from `.git/config` | – |
| Runner images pinned (`ubuntu-24.04`, `windows-2025`, `macos-15`) instead of `*-latest` | "latest" changes underneath us; failures should come from our changes | Use `*-latest` |
| ShellCheck at **severity error**, not warning | Legacy currently has 25 warnings (see below); CI would be red from day one. Errors are still blocked | Raise to `--severity=warning` after fixing |
| sqlc installed in CI only if `sqlc.yaml` exists | sqlc is not used in phase 0; owner installs it in phase 1 | – |
| No `actionlint` | Not an approved dependency/tool. Instead YAML was parsed with go.yaml.in/yaml/v3 (scratch program, not in the repo) and every `uses:` was checked for SHA pinning | Proposal: add actionlint as a pinned CI tool |

### Not verifiable tonight
The workflow has **never run** – it only runs after a push, which is the owner's decision.
Locally simulated: `task check`, the ShellCheck command (exit 0), YAML parsing, SHA pinning.
Risk: small typos in shell steps of the workflow would only show on the first run.

### Findings in legacy (not changed)
ShellCheck 0.11.0 on the modular sources: 71× SC2034 (variables set in one file and used in
another – false positives of the modular layout), 22× SC2207 (completions), notes only otherwise.
On the compiled standalone script only 3 warnings remain:
- `C_MAG`, `C_CYN` in `lib/core.sh` – colour constants never used
- `rootder` in `lib/export.sh:148/158` – assigned, never used (harmless leftover; possibly the
  guide was meant to mention the DER root `publish/root.crt`)

## Step 5 – Presets as YAML, loader, tests

### Done
- `presets/*.yaml` – the 12 legacy presets, each with comments explaining *why* (key usages, SANs,
  validity); `presets/README.md` describes the format; `presets/presets.go` embeds the files.
- `internal/ca/preset` – strict loader (`Builtin()`, `Load(fs)`, `Parse()`), resolved accessors
  `KeyUsageFor(alg)`, `ExtKeyUsages()`, `ExtKeyUsageOIDs()`.
- Tests:
  - `TestLegacyParity` parses `legacy/lib/presets.sh` and compares every field of every preset
    (mutation-tested: changing one YAML value makes it fail).
  - `TestParseRejects` – 28 broken presets, each must be rejected with a specific message.
  - `TestPresetCertificates` – 12 presets × 3 key types (RSA 2048, ECDSA P-256, Ed25519): issue a
    throw-away certificate, parse it with crypto/x509, and run `openssl verify -purpose <purpose>`.
  - `TestPresetCertificatesWrongPurpose` – 6 negative checks (e.g. a client certificate must fail
    `sslserver`), so the OpenSSL check is not a rubber stamp.
- New dependency: `go.yaml.in/yaml/v3 v3.0.5` (approved; MIT/Apache-2.0). govulncheck: clean.

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| YAML schema with `key_usage.rsa` / `key_usage.other` | Legacy only knew RSA and Ed25519 (`KU_RSA`, `KU_ED`); pki-rules.md says the non-RSA column applies to ECDSA too | Rename fields |
| `required_any_of` instead of legacy `"dns\|ip"` string | A list is unambiguous and validates per element | – |
| EKUs by name; dotted OID only for EKUs without a name (`1.3.6.1.5.5.8.2.2`) | One spelling per usage → duplicates detectable | Allow OIDs for known EKUs |
| `ipsecIKE` as a name for 1.3.6.1.5.5.7.3.17 | Readable; crypto/x509 has no constant, so it goes into `UnknownExtKeyUsage` | Write the OID |
| `keyAgreement`, `encipherOnly`, `decipherOnly` rejected | `other` covers Ed25519, which can't do key agreement; no legacy preset uses them | Split `other` into `ecdsa`/`ed25519` and allow it for ECDSA |
| Cross-field rules (serverAuth ⇒ DNS/IP SAN, emailProtection ⇒ e-mail SAN, timeStamping only + critical, ocsp_no_check ⇒ OCSPSigning, openssl_purpose ⇔ EKU, customizable ⇒ family custom) | Each encodes an RFC/CA-B Forum requirement; all 12 legacy presets already satisfy them | Remove the rule in `validate.go` |
| `validity_days` 1–3650 | Sanity bound only; real lifetime policy is phase 1/2 | Change constants |
| Preset files limited to 64 KiB, one YAML document per file | Cheap protection once presets can be uploaded | – |
| No `sort_order` field, `Names()` sorted alphabetically | The UI order is a UI decision for phase 1 | Add a field |

### Findings for phase 1 (important)
- **crypto/x509 always writes extendedKeyUsage as non-critical.** The `timestamp` preset needs a
  critical EKU (RFC 3161), so the CA engine must build that extension by hand – exactly what the test
  helper `issue()` in `x509_test.go` does (`ExtKeyUsageOIDs()` + `asn1.Marshal`). Same for
  `id-pkix-ocsp-nocheck` (via `ExtraExtensions`).
- crypto/x509 always marks keyUsage and basicConstraints critical – matches pki-rules.md.

## Step 6 – OpenAPI draft for phase 1

### Done
- `api/openapi.yaml` (OpenAPI 3.1.0, 49 operations): system (health, status, seal/unseal), auth
  (login, TOTP, WebAuthn, step-up, session, logout), users (CRUD, roles, own password, TOTP and
  passkey enrollment), API tokens, presets, CAs (create root/intermediate, offline-signing flow,
  import, certificate/CSR/CRL download, CRL regeneration), certificates (list with filters, issue
  from CSR or server-generated key, download public parts, export with key, revoke, renew, CSR
  inspection), imports (legacy pki/ archive as background job, external certificates), audit log
  (list, chain verification).
- `api/api.go` embeds the spec (`api.Spec`) for serving it later.
- `api/openapi_test.go` – structural checks without a new dependency: valid YAML, version 3.1.x,
  every local `$ref` resolves, operationIds unique and lowerCamelCase, declared tags, every operation
  has `x-required-role`, `none` ⇔ `security: []`, authenticated ops document 401, step-up ops
  document 403, request bodies document 400, all error responses are shared problem+json responses,
  no password/passphrase query parameters, every `format: password` property is `writeOnly`.
  Mutation-tested (missing role, broken $ref, password query parameter are all caught).

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| Problem types as URNs `urn:myownpki:problem:<name>` | RFC 9457 allows any URI; a URL would need a domain, and the project domain is still an open point (PLAN §12) | Switch to `https://<domain>/problems/<name>` |
| `x-required-role` and `x-step-up` vendor extensions on every operation | Makes RBAC and step-up reviewable in the spec and testable; code generation can read them later | Remove the extensions |
| `/health` unauthenticated, returns only `{"status":"ok"}`; version/seal state only via authenticated `/system/status` | Load balancers need a health check; an anonymous endpoint must not reveal version info | – |
| Export with private key is `POST /certificates/{id}/export` with password in the body | Passwords in URLs end up in proxy logs and browser history | – |
| Issuance with CSR **or** server-generated key (`oneOf`) | Phase 1 replaces pki.sh, which generates keys server-side; CSR is documented as preferred (ADR-11 spirit) | Drop the `key` variant |
| `certificateHold` not offered as revocation reason | "Temporary revocation" is poorly supported and confusing; RFC 5280 lists it but CA/B BR forbid it | Add it to the enum |
| Role scopes only `tenant` and `ca` | Domain and agent-group scopes belong to phases 2/3 | Extend enum |
| No tenant in any path | security.md: tenant comes from the authenticated context | – |
| Not included: batch upload (PLAN §6.1), encrypted backup download, ACME, domains, agents | Not in the phase 1 row of the roadmap or belong to later phases | Add in phase 1 if wanted (open question) |
| No OpenAPI linter (vacuum/spectral) | Not an approved dependency; structural test instead | Proposal: add `vacuum` (MIT, Go) as a pinned CI tool |

### Open points for phase 1 (see docs/PHASE1.md)
- Code generator: oapi-codegen supports OpenAPI 3.1 only partially; ogen supports it. Needs a decision
  and approval (new dependency).
- Does the UI really need server-side key generation, or only CSR signing? (security trade-off)

## Step 7 – Design tokens, component CSS, /design, serve --dev

### Done
- `web/styles/tokens.css` (brand/neutral tokens themeable, **status tokens fixed**, light + dark via
  `prefers-color-scheme` and `data-theme`, density via `data-density`), `base.css`, `components.css`
  (buttons, badges, tables, toolbar, KPI tiles, forms, notices, key/value details, PEM blocks, empty
  state, chart box, dev banner, gallery helpers), `layouts.css` (shell B "Standard" only).
- `web/icons.svg` – sprite with 6 outline icons (ok, warn, crit, info, download, search).
- templ: `internal/web/components` (Icon, Badge, Stat, Note, FormRow, DevBanner),
  `internal/web/layout` (shell B), `internal/web/pages/design` (gallery with realistic homelab data).
  Generated `*_templ.go` files are committed; `go generate ./...` / `task generate` regenerates them.
- `internal/web` – handler with `/design`, `/static/…`, redirect `/` → `/design`; security headers on
  every response (CSP from security.md + `img-src 'self'; form-action 'self'`, nosniff,
  Referrer-Policy, X-Frame-Options, COOP/CORP, Permissions-Policy); request logging; panic recovery.
- `myownpki serve --dev [--listen 127.0.0.1:9443]`; `task dev` runs it.
- Tests: routes and headers (also on 404/redirects), dev banner only in dev mode, **no inline
  style/script/event handler/javascript: URL** in the rendered page and in all `.templ` sources, every
  used CSS class is defined, every `var(--x)` exists in tokens.css, no hard-coded colors outside
  tokens.css, listen-address validation (14 cases), graceful shutdown, UTC log timestamps.
  Mutation-tested: an inline `style=` and an undefined class are both caught.
- Visually checked in the built-in browser: light, dark, compact, 375 px phone width – no console/CSP
  errors, no horizontal overflow; serials and dates don't wrap inside tables.

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| `--dev` is a CLI flag only; dev mode accepts only the IP literals `127.0.0.1` / `::1` (no names, no zones, no port 0) | Owner's rule: a name like `localhost` can resolve elsewhere; nothing unauthenticated may reach the network | – |
| `serve` without `--dev` refuses to start (exit 2) | TLS and login don't exist yet | Phase 1 |
| Dev banner on stderr at start **and** sticky on every page (`role="alert"`) | Owner's rule | – |
| Default dev port 9443 (the future admin port), plain HTTP | Same URL habit as later; only loopback | Change `defaultDevListen` |
| No JavaScript at all in phase 0; dark mode shown as a second preview with `data-theme="dark"` | Islands need esbuild (not approved yet); no theme switch needed for a gallery | Add an island in phase 4 |
| No htmx vendored yet | Not needed for a static page; vendoring needs owner approval (third-party file) | Vendor in phase 1 |
| Status colors fixed per light/dark mode | ADR-12 forbids themes changing them, but dark mode needs different shades for contrast | – |
| System font stack, no web fonts | Nothing to download/licence, no CSP exception | – |
| US English spelling in UI and code (`color`) | misspell linter is set to US (ADR-17) | Change locale |
| Static assets `Cache-Control: no-cache`, explicit Content-Type for .css/.svg | Asset URLs aren't fingerprinted yet; on Windows Go would take MIME types from the registry, and with `nosniff` a wrong type breaks the page | Fingerprint assets later |
| HSTS not sent | Only meaningful over TLS (phase 1) | – |
| Log timestamps converted to UTC | go-conventions "UTC everywhere" – the first run logged `+02:00` | – |
| Sample data uses `it-admin@homelab.lan` | No real names in demo data | – |

### Notes
- `favicon.ico` returns 404 (browser request). Harmless; a real icon can come with the branding work.
- Screenshots in the built-in browser only worked intermittently (window in the background), so the
  checks were done mainly via computed styles; a few screenshots were possible.

## Step 8 – Documentation

- `docs/PLAN.md`: status, roadmap (phase 0 ✅), repository layout, §12 open points updated, new §13
  "Tooling and conventions" (explicitly *not* ADRs; the ADR table is unchanged).
- `README.md`: status, layout, development quick start. `CLAUDE.md` and
  `.claude/skills/myownpki/references/go-conventions.md`: the two "decide in phase 0" items resolved.
- `docs/PHASE1.md`: written proposal for phase 1 (data model, step order, dependencies, open questions).
  No phase 1 code was written.

---

# Morgenbericht (Deutsch)

## Was fertig ist

Phase 0 ist abgeschlossen. Alle Commits sind lokal, **nichts wurde gepusht**.

| Commit | Inhalt |
|---|---|
| `da49e0f` | Projektplan, Legacy-Suite und Skill importiert (gestern mit dir) |
| `da70e43` | Go-Modul und drei Binaries (gestern mit dir) |
| `ae24c5e` | Taskfile, Go 1.27.2, templ/govulncheck fest eingebunden (gestern mit dir) |
| `2da5807` | golangci-lint-Konfiguration (gestern mit dir) |
| `627e8ae` | **Schritt 4:** CI (GitHub Actions) und Dependabot |
| `371494d` | **Schritt 5:** 12 Presets als YAML, Ladecode mit Prüfregeln, Paritätstest gegen Legacy, OpenSSL-Gegenprobe |
| `adb324a` | **Schritt 6:** OpenAPI-3.1-Entwurf (49 Operationen) mit Strukturtest |
| `39e9f59` | **Schritt 7:** Design-Tokens, Komponenten-CSS, `/design`, `serve --dev` |
| `398d0c5` | **Schritt 8:** PLAN.md, README, CLAUDE.md aktualisiert |
| (letzter Commit) | Dieses Protokoll und `docs/PHASE1.md` |

Nach jedem Schritt war `task check` grün. `task vuln` meldet keine Schwachstellen.

## Was nicht geklappt hat

- **Die CI ist nie gelaufen.** Sie startet erst nach einem Push, und den entscheidest du. Lokal
  nachgestellt habe ich alle Befehle, die YAML-Syntax, die festgelegten Action-Hashes und den
  ShellCheck-Schritt. Tippfehler in den Shell-Zeilen des Workflows würden sich erst beim ersten Lauf zeigen.
- **ShellCheck läuft vorerst nur mit Schweregrad „error“.** Das Legacy-Skript hat 25 Warnungen,
  meist unbenutzte Variablen. Mit „warning“ wäre die CI vom ersten Tag an rot. Den Legacy-Code
  habe ich nicht angefasst.
- **Screenshots im eingebauten Browser** gingen nur zeitweise (App-Fenster im Hintergrund). Die Seite
  habe ich deshalb überwiegend über berechnete Styles geprüft: hell, dunkel, kompakt, Handybreite,
  keine CSP-Fehler. Einige Screenshots sind gelungen und sahen gut aus.

Keinen Schritt musste ich verwerfen.

## Entscheidungen, die ich allein getroffen habe

Die vollständigen Tabellen mit Begründung und „wie rückgängig machen“ stehen oben pro Schritt.
Die wichtigsten:

1. **CI-Sicherheit:** Fremde Actions per Commit-Hash statt Tag, Werkzeuge mit SHA-256-Prüfung,
   Token nur lesend.
2. **Presets:** strengere Regeln als Legacy, alle 12 Presets erfüllen sie bereits. Zum Beispiel:
   serverAuth braucht eine DNS/IP-SAN, timeStamping muss allein und kritisch sein, CA-Key-Usages sind
   in Presets verboten. `keyAgreement` ist vorerst gesperrt.
3. **API:** Fehlertypen als URN (`urn:myownpki:problem:…`), weil es noch keine Projekt-Domain gibt.
   Schlüssel-Export per POST, damit Passwörter nie in der URL stehen. `certificateHold` wird nicht angeboten.
4. **UI:** kein JavaScript in Phase 0, Dunkelmodus als zweite Vorschau auf der Seite, Systemschriften,
   US-Schreibweise („color“), Log-Zeiten in UTC (der erste Lauf hatte Ortszeit, das ist korrigiert).
5. **Dev-Modus:** wie von dir vorgegeben, zusätzlich auch Port 0 und IPv6-Zonen abgelehnt. `task dev` startet ihn.

## Wichtigster Fund für Phase 1

`crypto/x509` schreibt die Extended Key Usage **immer als nicht kritisch**. Das Preset `timestamp`
braucht nach RFC 3161 aber eine kritische EKU. Die CA-Engine muss diese Extension deshalb selbst
bauen. Der Testcode in `internal/ca/preset/x509_test.go` zeigt bereits, wie das geht.

## Offene Fragen an dich

Ausführlich mit Empfehlungen in `docs/PHASE1.md` §4. Kurz:
1. Soll der Server Schlüssel selbst erzeugen (wie pki.sh), oder nur CSRs signieren?
2. Wo liegen Schlüssel: verschlüsselt in `pki.db` (Empfehlung) oder im Ordner `keys/` (PLAN §4)?
3. Ersten Admin per `myownpki init` anlegen?
4. TLS beim ersten Start: selbstsigniertes Bootstrap-Zertifikat und/oder eigenes Zertifikat?
5. OpenAPI-Generator: ogen oder oapi-codegen?
6. Standardlaufzeiten (397/730 Tage) beibehalten oder schon Richtung SC-081 kürzen?
7. Standardalgorithmus ECDSA (P-256/P-384) statt RSA?
8. Die 25 ShellCheck-Warnungen im Legacy-Code beheben?
9. Wann soll der erste Push kommen, damit die CI einmal läuft?
10. Projekt-Domain für Fehlertypen jetzt festlegen oder bei der URN bleiben?

Dazu Vorschläge für neue Abhängigkeiten (nicht hinzugefügt): `actionlint` und `vacuum` als CI-Werkzeuge
sowie die Phase-1-Liste in `docs/PHASE1.md` §3.
