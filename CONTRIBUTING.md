# Contributing to MyOwnPKI

Thanks for your interest. MyOwnPKI is a certificate authority, so the bar for correctness and
security is high – but the rules below are short.

**Security problems are not reported here:** please follow [SECURITY.md](SECURITY.md) and report
them privately, never as a public issue or pull request.

## Before you start

- Read [docs/PLAN.md](docs/PLAN.md): the architecture, the decisions (ADRs, §2) and the roadmap
  (§10). The current work plan is [docs/PHASE3.md](docs/PHASE3.md); phases 1 and 2 are finished
  ([docs/PHASE1.md](docs/PHASE1.md), [docs/PHASE2.md](docs/PHASE2.md)).
- For anything larger than a small fix, open an issue first and describe what you want to change.
  Features from a later phase are usually not merged early, and from v0.9.0 until v1.0.0 no feature
  is merged at all: see [Feature freeze](#feature-freeze-from-v090-until-v100).
- **ADRs are deliberate trade-offs.** If your change conflicts with one, propose an ADR change in
  the issue instead of working around it.

## Development setup

Requirements: Go (the toolchain is pinned in `go.mod` and downloaded automatically),
[Task](https://taskfile.dev), [golangci-lint](https://golangci-lint.run) and [sqlc](https://sqlc.dev) – versions in
`Taskfile.yml`. Everything works the same in PowerShell, Git Bash, Linux and macOS.

```sh
task              # list all tasks
task check        # formatting, lint, tests, build – must pass before every commit
task dev          # UI prototype at http://127.0.0.1:9443/ (no TLS, no login, loopback only)
```

## Feature freeze (from v0.9.0 until v1.0.0)

The tag v0.9.0 starts the beta. The beta is made of ordinary releases (v0.9.0, v0.9.1, …), and from
the first of them the feature set is **frozen**: what is in v0.9.0 is what v1.0.0 will be, minus the
defects testers find. The point is that testers test one thing, not a moving target. The rules are in
[docs/PHASE3.md](docs/PHASE3.md) §19.4.

| Allowed | Not allowed without an exception |
|---|---|
| **Fixes**: `fix:` or `fix(<area>):`, and the commit says what was wrong | Features, new pages, new settings or configuration keys, new CLI commands |
| **Docs** (`docs:`), **tests** and the CI that runs them (`test:`, `ci:`) | REST additions (a path, a field) and changes to `api/openapi.yaml`, except to correct it |
| **Security hardening** that only narrows what is accepted (`fix(security):` in the title of the pull request) | Schema changes. A **new** migration that fixes a defect is allowed; a released migration file is never edited |
| **Dependency security updates** (branch `deps/<short>`, `chore(deps):`) | New dependencies, protocol changes in `proto/` beyond what `buf breaking` accepts, new agent profiles or recipes, any ADR change |

- **An exception is the owner's decision.** The owner writes "freeze exception" on the issue or the pull
  request and adds the label `freeze-exception`; the commit body names the issue and the CHANGELOG
  lists the change under *Changed*. A contributor, and a coding session, never decides it.
- **Ideas and wishes are welcome**, but they are not built during the beta. They get the label `post-1.0`
  and are looked at after v1.0.0; the list is in [docs/PLAN.md](docs/PLAN.md) §10.1 and §12.
- **Fixes only narrow.** A fix that changes behavior a client may have relied on is named in the CHANGELOG.
- The pull request template asks you to tick one box: this is a fix, docs, a test, a security
  hardening, a dependency security update, or it has a freeze exception.

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
  `crypto/x509` and, where available, cross-check with `openssl verify`. The cross-checks need
  **OpenSSL 3.0 or newer** (skipped locally without it, required in CI) – macOS ships LibreSSL,
  there: `brew install openssl@3` and put it first on `PATH`.
- **Time**: UTC everywhere, with an injected clock in tests – no sleeping, no wall time.
- **Generated code** (templ, sqlc) is regenerated with `task generate`
  and committed.
- **API changes** go into `api/openapi.yaml` first (ADR-05) and pass `task lint:api` (vacuum).
- **Workflow changes** put new or changed steps in `scripts/ci` and register them in
  `scripts/ci/local.sh`. Run `task ci:local` and `task lint:ci` (actionlint), and report every
  SKIP line. Use `task ci:local -- --list` or `-- --only JOB` to inspect or select jobs. Both
  lint tools are pinned binaries – versions in `Taskfile.yml`; CI runs them on every push.
  `MYOWNPKI_CI_REMOTE_HOST` is reserved for a future remote Linux runner; remote execution
  requires owner approval and is not implemented. Set `MYOWNPKI_CI_DISPOSABLE=1` **only on a
  machine that will be discarded afterwards**: the guarded systemd/install steps replace units,
  binaries and state as root. Without GitHub Actions or this explicit opt-in they are skipped;
  the scripts also refuse to overwrite a pre-existing installation.

## Coverage, fuzzing and dead code

Three tasks measure the quality of the tests and the code. None of them is part of `task check`; CI
runs the fuzz targets and you run the other two when you touch the code they measure.

- **`task cover`** runs every test with `-coverpkg`, so an integration test is credited to the
  package it exercises, and prints one line per package (statements, covered, percent), the total
  and the number of tests that skipped on this machine (a Windows number is not a Linux number).
  It needs several minutes. `COVER_PKGS=./internal/ca/...` limits it to a few packages and
  `COVER_SKIP=<regexp>` leaves packages out. Afterwards `task cover:func` lists the functions with
  the most uncovered statements and `task cover:html` opens the merged profile in the browser.
  There is no minimum and no CI gate: the ranked list of gaps is the use of it, not the percent.
- **`task fuzz`** runs the Go fuzz targets listed in `scripts/ci/fuzz-targets.txt`, one after the
  other, 10 seconds each by default. A fuzz target (`func FuzzXxx(f *testing.F)`) feeds random
  input to a parser that reads data from outside the trust boundary (a CSR, an ACME request, an
  uploaded CRL, a REST body) and checks what the parser promises: no panic, bounded work, and what
  it accepted holds what the parser says it holds. A **seed** is one input the target starts from:
  seeds are added in code with `f.Add`, or, when the fuzzer found a crash, as the file it wrote
  under `testdata/fuzz/<Target>/`. Both run as ordinary tests in `go test ./...`, so a crash that
  was fixed stays a regression test. To fuzz one target for longer, for example for an hour before
  a release:

  ```sh
  task fuzz FUZZTIME=1h FUZZ_ONLY=FuzzParseCSR
  ```

  A new `func Fuzz...` needs one line in `scripts/ci/fuzz-targets.txt` (`bash scripts/ci/fuzz.sh
  --check` and the CI job `fuzz` fail otherwise). If a run finds a crash, keep the file the fuzzer
  wrote, fix the parser and commit both, plus a plain unit test of the rule that was broken. A
  target calls the production function unchanged and never loosens a limit to pass.
- **`task deadcode`** lists the functions that no binary and no test reaches (`go run` of
  `golang.org/x/tools/cmd/deadcode`, `go.mod` stays as it is) and fails on any that is not in
  `scripts/ci/deadcode-known.txt`. Delete the function, or move it into a `_test.go` file when only
  tests use it; add it to the list only with a reason, for example a build-tagged test that uses it.

## The upgrade test

An installation made by a released version must keep working after the update: the job `upgrade`
(`test/upgrade/run.sh`, `docs/PHASE3.md` section 19.5) lets the binaries of old releases make an
instance, fills it, takes it over with the binary of your branch and checks it (A1 to A10). Release
files come from `scripts/upgrade/releases.txt` with a pinned SHA-256; a released migration file
never changes (`internal/store/testdata/released-migrations.txt`). A pull request runs three start
versions when it touches the store, backup, keys, configuration, the CLI, `proto/`, `deploy/` or the
test itself (`scripts/ci/changes.sh`); `main` and the nightly run every version. It is not a required
check, and a red run is a bug to fix, not a flake to restart. Locally it needs Linux (amd64), Go,
Task, curl and OpenSSL: `task upgrade:lego` once, then `task upgrade UPGRADE_ONLY=0.3.12` (`-- --dry-run`
shows the plan). Read the SKIP lines of its table: a skipped check is not a passed one.

## Documentation-only pull requests

A pull request that changes **only** documentation skips the heavy CI jobs (tests, race
detector, cross-build, conformance, agent end-to-end, install, upgrade, image, Salt formula); the job `changes`
(`scripts/ci/changes.sh`) decides. "Documentation" is exactly: `.claude/**`, `docs/**/*.md` and
`*.md` files in the repository root. Everything else counts as code, including other Markdown
files such as `presets/README.md` and `assets/brand/README.md`, `.github/**` and `scripts/**`;
so does an empty or unreadable diff. Skipped jobs show as skipped, which counts as success for
branch protection, and `vuln` always runs. Pushes to `main` and the daily schedule are never
reduced. To force a full run on any branch, start the CI workflow by hand
(*Actions → CI → Run workflow*, `workflow_dispatch`).

## Documentation site

The guides at <https://der-felix.github.io/MyOwnPKI/> are built from `site/` and deployed to GitHub Pages.

- **Source.** Markdown pages in `site/`, one small Jekyll layout (`site/_layouts/default.html`), the
  configuration `site/_config.yml`, one style sheet `site/assets/site.css` and the navigation
  `site/_data/nav.yml`. There is no theme, no plugin of ours, no JavaScript, no web font and nothing
  loaded from other hosts. Links go through the `relative_url` filter; the examples use only
  `homelab.lan`, `192.0.2.x`, `pki.homelab.lan` and `minion-01.homelab.lan`, never real names,
  addresses or secrets.
- **One source of truth.** The operations guide, the release notes and the example configuration are not
  copied by hand. `scripts/ci/site-prepare.sh` generates `site/reference/` and `site/_data/release.yml`
  from `docs/OPERATIONS.md`, `CHANGELOG.md` and `deploy/config.example.yaml` (not committed, see
  `.gitignore`) and rewrites their relative links. Edit those files, not a copy.
- **Build.** `.github/workflows/pages.yml` runs on changes to these files. A pull request runs only the
  `build` job: the self-tests of the scripts, the generation, `scripts/ci/site-check.sh` (every link and
  anchor of the sources), GitHub's Jekyll action and a check of the built HTML. On `main` the `deploy`
  job publishes the result; it is the only job with `pages: write`. Only GitHub's own actions are used,
  pinned to a commit SHA.
- **Preview.** There is no local Jekyll. Push the branch, open a pull request and read the `build` job.
  `task ci:local -- --only pages` runs the part that needs only bash and awk: the generation and the
  link check.
- GitHub Pages is switched on once by the owner (*Settings → Pages → Source: GitHub Actions*).

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/) in English, for example
  `feat(ca): enforce name constraints on issuance` or `fix(web): keep filters after paging`.
  Types in use: `feat`, `fix`, `docs`, `test`, `build`, `ci`, `chore`, `refactor`.
- Small commits that each build and pass `task check`; explain the *why* in the body.
- Pull requests describe what changed, how to verify it, and link the issue.

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), like the rest of the project.
