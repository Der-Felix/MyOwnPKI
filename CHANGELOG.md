# Changelog

All notable changes to MyOwnPKI are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
change the API, the configuration and the database schema; the release notes say how to upgrade.

## [Unreleased]

### Fixed

- **Documentation on `low_ports`:** the Salt page, the upgrade page and the formula README said that an enrolled host
  loses `20-low-ports.conf` at the next package update when `low_ports: true` is missing from its pillar. That is not so
  since agent 0.3.5: `setup` leaves the file as found and removes it only for `sandbox.low_ports: false`. A live update
  from 0.3.5 to 0.3.10 of a host without the key kept the file. The key still installs the file where it is missing and
  lets the pillar state what a host needs.

## [0.3.12] - 2026-11-16

The quality round before the beta. There is no new feature: the parts of the program that read data from outside the trust
boundary (a CSR, an ACME request, an uploaded CRL, a REST body, the legacy archive) are now **fuzzed**, the test gaps that the
first coverage table showed are closed, dead code and copied code are gone, and the lint rules are stricter. Fuzzing and the
new tests found a dozen real defects; the largest group is answers that repeated what the sender wrote without a limit, and
there are uploads that were accepted although they held more than one object. All of them are fixed in this release and none
changes a documented behavior of the API. The release adds **no migration, no REST change, no configuration key and no
dependency**.

### Added

- **24 fuzz targets** (`func Fuzz...`) in nine packages: the ACME request envelope, its key and account-binding parts
  (`internal/acme/jose`), the ACME payload helpers and the CSR check, and one target that sends fuzzed payloads through the
  real handlers with a real database (`internal/acme`); the CSR, certificate, name, name-constraint and CRL parsers
  (`internal/ca`); the legacy archive, key-value, `index.txt` and private key readers (`internal/ca/legacy`); the agent's CSR
  key check, report limits and host name patterns (`internal/agents`); the REST body decoder (`internal/httpapi`); the file
  upload of the issue wizard (`internal/web`); the User-Agent reader and the generated commands of the trust page
  (`internal/trustkit`); and the guide parser (`internal/guides`). Each target calls the production function unchanged, has
  seeds that are written in the test, and checks what an accepted input must satisfy. What the fuzzer found stays in the
  repository as a regression test.
- **`task fuzz`** runs them all, 10 seconds each (`FUZZTIME=30m FUZZ_ONLY=FuzzParseCSR` for one target and longer). The one
  list is `scripts/ci/fuzz-targets.txt`; `bash scripts/ci/fuzz.sh --check` (and CI) fails when a `func Fuzz...` of the tree is
  not in it, or the list names one that does not exist, and a crash prints the new input files into the log.
- **CI job `fuzz`** (every pull request and push that changes code, 10 seconds per target, parallel to `check`) and **job
  `fuzz-long`** (the daily 04:17 run and a manual run with an input `fuzztime`, 2 minutes per target by default). `task check`
  does not fuzz.
- **`task cover`** prints one table of the coverage per package, with integration tests credited to the package they exercise
  (`-coverpkg`), the number of skipped tests, and no gate; `task cover:func` lists the functions with the most uncovered
  statements and `task cover:html` opens the profile. More than 130 new test functions closed the gaps that the first table
  showed in the security-relevant code. The combined numbers (integration tests credited) moved from 77.8 % to 87.1 % for
  `internal/acme`, 83.6 % to 86.3 % for `internal/ca`, 81.9 % to 84.2 % for `internal/agents`, 82.3 % to 84.2 % for
  `internal/auth` and 84.7 % to 85.8 % for `internal/server`; `internal/backup` is at 87.2 %. The whole tree is at 85.3 % of
  31,181 statements (generated code and test helpers left out). These are numbers from Windows, where 23 tests skip (the
  legacy tests need `pki.sh`) and `internal/publish` could not be run; the first Linux table comes from CI.
- **`task deadcode`** lists the functions that no binary and no test reaches and fails on one that is not on a reviewed list
  (`scripts/ci/deadcode-known.txt`, empty today). It runs through the module cache; `go.mod` and `go.sum` are unchanged.
- **Stricter lint rules** (`.golangci.yml`), every new linter with a one-line reason: `contextcheck`, `containedctx`,
  `errchkjson`, `wastedassign`, `recvcheck`, `unparam`, `intrange`, `perfsprint`, `mirror`, `canonicalheader`, `dogsled`,
  `fatcontext`, `dupl` (copied blocks of 100 tokens or more, tests excluded), `revive` with five rules (`error-strings`,
  `error-naming`, `redefines-builtin-id`, `context-as-argument`, `package-comments`), six more `gocritic` checks, and
  `exhaustive` without the `default:` shortcut. The tree reports 0 issues on Linux, macOS, FreeBSD and Windows.
- **Documentation:** `CONTRIBUTING.md` and the site page *Contributing* describe the three tasks, what a seed is and how to run
  one target for an hour; `docs/RELEASING.md` has an optional fuzz run of one hour per target before a tag; the site page
  *Security* says what is fuzzed and what is not; the error message rule and the fuzz and coverage rules are in
  `go-conventions.md`.

### Changed

- **`SECURITY.md` says which versions get fixes:** the latest release and `main`. It said "no release yet".
- **Error messages follow one rule** (`.claude/skills/myownpki/references/go-conventions.md`): lower case unless an acronym,
  no trailing punctuation, `%w` for an error that is returned, `errors.New` for a constant text. The 22 `fmt.Errorf` calls
  without a verb are `errors.New` now; `perfsprint` and `revive` keep it so. **No text that a client sees was reworded.**
- **`myownpki config check` stops on Ctrl-C.** It took no context; a check that waits for a network answer can be interrupted now.
- **Dead code is removed:** `Server.Host` of the DNS test server, `PlaceholderNames` of the guides, `LegacyCRLURL` and
  `LegacyCertURL` of the CA package and the `ACME` accessor of the server; the functions that only tests used moved into
  test files. Two pairs of copied code are one function each (the `ca` and `db` dispatch in `cmd/myownpki`, the two
  INSERTs of `settingsver`).
- **Code modernized by `golangci-lint --enable-only modernize`:** `errors.AsType`, `slices.Contains` and `slices.Backward`,
  `strings.SplitSeq`, `maps.Copy`, `sync.WaitGroup.Go`, `new(value)` for the pointer helpers and the like, 126 Go files, no
  change of behavior (the tests of every package that changed pass unchanged).
- Seven tests checked that a secret is **not** in the audit log with a text that was empty when `json.Marshal` had failed, so
  they could not fail; they check the real text now.
- `api/openapi.yaml` `info.version` is 0.3.12.

### Fixed

- **An ACME client could make the server repeat 64 KiB back to it.** The refusals of a JWS with a long member name, algorithm,
  key type or curve, and of a JWS whose `url` is not the request's, repeated the offending text in full on the endpoints that
  need no account. The text is cut at 80 bytes now.
- **The same for names:** a refused DNS name, e-mail address, URI or IP address was repeated in the message in full (up to
  128 KiB through the REST body). It is cut at 80 bytes. The REST answers for an unknown field and for a value that does not
  parse repeat at most 200 bytes.
- **An ACME CSR could carry a look-alike common name.** The common name was lower-cased with a function that also folds the
  Kelvin sign onto `k`, so a CSR with a different spelling passed as the order's name and was put into the certificate's
  subject. Only `A` to `Z` are folded now.
- **A CSR, certificate or CRL upload with a second PEM block was accepted** when the first block was damaged (the PEM reader
  skips a block it cannot decode). An upload is one block now; the text in front of it (`openssl req -text`) stays accepted.
- **An uploaded CRL with data behind it was stored and served as it came,** so the signature covered only the first part of
  what the public listener handed out. It is refused.
- **A name constraint written as an IPv4-mapped IPv6 prefix** (`::ffff:10.0.0.0/104`) never applied to a name, because the
  names are converted to IPv4 and a verifier compares the length. It is refused with the hint to write the IPv4 prefix.
- **A JSON body of `null` was read as an empty request** by every REST endpoint. It answers 400 now.
- **A hostile legacy archive could stall the import for minutes:** listing a directory walked every entry, and one entry with
  500,000 levels cost quadratic time. The tree is indexed and capped at 200,000 files and directories, and an entry that is a
  file and the parent of another one is refused, as `tar` on disk would.
- **A panic while the ACME validator checked a challenge ended the whole server.** The challenge fails with `serverInternal`
  now, the audit entry names the type of the panic (never its text) and the stack is in the log. The dialer that `net/http`
  calls in a goroutine of its own is covered too.
- **The admin allow-list could panic on a connection without an address** (and read a non-IP address type from its text). Both
  are an invalid peer now, which no allowed network contains. The admin listener is TCP only, so nothing reachable was affected.
- **The ACME list of an account's orders could be incomplete:** it read the 1000 newest orders of all accounts and then kept
  the caller's, so a quiet account saw an incomplete or empty list once others had made 1000 newer orders. It reads the
  account's own orders from the database now (one new query, the index `acme_orders_account` was there already). Clients
  such as certbot and lego do not depend on the list.
- **A restore could delete a file that sits where the data directory goes.** On Windows reading a regular file as a directory
  reports "not found", so `restore` took the file for a missing directory and removed it. A target that exists and is not a
  directory is refused.
- **An empty or zeroed database was accepted as a backup** (copied as migration 0, reported as success, noticed only by a later
  verify). `backup create` refuses it and names the file.
- **The start of the server named no setting when `auth.passkey_origin` was the reason for the refusal.** It does now.
- **An ARI certificate identifier could be written in more than one way.** The decoder of the Go standard library skips
  carriage returns and line feeds, also in strict mode, so `GET /acme/renewal-info/AQ%0AID.AQ` named the same certificate as
  `AQID.AQ` (found by the fuzz job). Each part of the identifier has to be canonical base64url now (only `A-Z a-z 0-9 - _`,
  no padding, no stray bits); anything else answers 400 `malformed`. Clients that write the identifier as RFC 9773 says are
  not affected.

### Security notes

- **Findings of the fuzz targets are treated as bugs in attacker-facing code.** The answers that repeated the sender's text
  were reachable without an account (the ACME envelope is read before the account is looked up). The two findings with an
  effect beyond a long answer are the accepted second PEM block and the look-alike common name (a spelling that the order did
  not name could reach the subject of the certificate; the names in the subject alternative name were checked against the
  order exactly, as before).
- **The fixes only narrow what is accepted,** and each has the input the fuzzer found as a regression test (`testdata/fuzz/...`)
  or a plain unit test of the rule.
- **The fuzz jobs are read-only:** they keep `permissions: contents: read`, use no secret, add no third-party action and upload
  nothing; a failing input is printed into the log.
- **No new dependency**; `go.mod` and `go.sum` are unchanged.

### Known limitations

- **The live test of 0.3.11 by the maintainer is still pending** (the recipes `apache2`, `httpd` and `haproxy`, the guides, the
  demo, the certbot flags of the guides). 0.3.12 does not change any of them.
- **Fuzzing covers the parsers of data from outside, not the files an administrator writes** (the server configuration,
  `agent.yaml`, DNS credentials, the agent state). They are listed as the next step.
- **Windows numbers are not Linux numbers.** Some tests skip on Windows (the legacy suite needs `pki.sh`), and `internal/publish`
  could not be run on the development machine, so the coverage table is a first measure; CI has the full run.
- Open points that need the maintainer, not fixed here: the backup manifest is unsigned, a few input lists are not capped (see
  `docs/PHASE3.md` section 18, "Owner decisions").

### Upgrade notes

- No migration (`myownpki db status` shows the same versions as 0.3.11), no configuration change and no change to the agent
  protocol, so going back needs no restore.
- Clients see the same API. A request that was accepted by mistake (a JSON body of `null`, an upload with a second PEM block, a
  CRL with data behind it, a name constraint with a mapped IPv6 prefix) is refused with the same kind of answer that other
  malformed requests get.
- The step-by-step version is on the site page *Upgrade*.

## [0.3.11] - 2026-11-16

Apache, HAProxy, guides and the demo. The agent gets three more example recipes (`apache2`, `httpd`, `haproxy`) and a new
target, `files.combined`, one PEM file with the certificate chain and the private key, which HAProxy needs. The web UI gets
a **Help** group with *First steps*, a read-only checklist of what a new instance still needs, and six short guides that
ship inside the program. `deploy/demo/` is a throwaway Docker demo. The container image moves to a Debian 13 base. The
release adds **no migration, no REST change and no dependency**; an agent older than 0.3.11 refuses `files.combined`, so
update agents first. The recipes, the guides, the demo and the new image base have **not yet been run on a live host**; the
live test by the maintainer is pending.

### Added

- **Recipes `apache2`, `httpd` and `haproxy`** for `myownpki-agent deployment add --recipe` and the *Add host* assistant. They
  are examples until a live test: `deployment add` says so and lists what to verify. `apache2` (Debian, Ubuntu) and `httpd`
  (Red Hat family) are the `nginx` profile (`fullchain.pem` and `privkey.pem` in `/etc/ssl/myownpki/<deployment name>`) with
  the test hooks `apache2ctl configtest` and `httpd -t`, a `systemctl reload`, the local check `127.0.0.1:443` and the log
  directory of the service as a sandbox directory. `haproxy` is the file profile with one file per deployment,
  `/etc/ssl/myownpki/haproxy/<deployment name>.pem`, the test hook `haproxy -c -f /etc/haproxy/haproxy.cfg` and no sandbox
  directory. No recipe edits the configuration of its service. The notes of each recipe say what `configtest` and `haproxy -c`
  were observed to cover in CI and what not, what to set in the service's configuration, and (for `httpd`) the SELinux label of
  `/etc/ssl/myownpki`.
- **`files.combined`** (`--combined FILE`): a target of the file profile, used alone, that holds the certificate, the chain
  and the private key in one PEM file. It gets the key mode of the deployment (`0600` by default, never rights for others), its
  owner and group, and goes through the same atomic write, journal, test hook, reload hook, TLS check and rollback as every
  other target. Validation, `deployment add --dry-run`, `list`, `remove`, `sandbox sync` and the dns-01 target check know it.
- **`{name}` in every path of a recipe.** It used to be replaced in the directory only. The name becomes a path segment and
  must be a name the agent accepts, so two HAProxy deployments write two files.
- **The Help group of the web UI.** *First steps* (`/first-steps`) lists ten rows (unseal, a CA, the public base URL and CRL, a
  domain, ACME, a first certificate, a host with an agent, backup, trusting the root, notifications), each *Done*, *Open*,
  *Not detected* or *Not available to your role*, with a link to the page that finishes it and to the guide. It is computed
  on every request from calls the dashboard already makes, under the permissions of the user, and it writes and stores
  nothing. The dashboard of a new instance shows one note that points to it, and `myownpki init` ends with "Next: sign in and
  open Help, First steps." *Guides* (`/guides`, `/guides/<name>`) shows six texts: *Build a certificate authority*, *Keep the
  root offline*, *Connect certbot*, *Install the agent and add a host*, *Back up and restore* and *Using these guides*. Any
  signed-in user can read them.
- **The guide format** (`internal/guides`): a closed subset of Markdown (headings, paragraphs, lists, fenced code, tables,
  notes, bold, italic, code, links) parsed by the program itself into typed blocks, with front matter (`title`, `summary`,
  `audience`, `order`, `site`, `sources`). A new guide is a file under `internal/guides/content`; a test refuses raw HTML,
  images, scripts, unknown placeholders and links outside the UI, other guides and the project's site and repository, and
  requires that every command in a `bash` block starts with a known program and pipes into no shell (the command-prefix test).
  `{acme_directory}` and `{ca_name}` in a command are replaced from the configuration and the engine, never from the request.
- **The demo** (`deploy/demo/`: `docker-compose.yml`, `demo.sh`, `README.md`, `.env.example`). `./demo.sh run` starts a demo
  instance with a test CA, unseals it, creates the domain `demo.test`, lets `certbot` get a certificate for `www.demo.test` by
  http-01 and checks the chain against the demo root with `openssl verify`. `./demo.sh agent` is a second act: nginx served
  by `myownpki-agent` from the image's own verified package, ending with one approval click in the UI. CI runs the first act
  on the snapshot image (`scripts/ci/demo-check.sh`).
- **CI job `agent end-to-end (Apache, HAProxy)`**: the `apache2` and `haproxy` recipes against the Apache and HAProxy
  packages of the CI runner, started by the tests with a private configuration. It records its observations in the job
  summary instead of assuming them, and compares each with the notes of the recipe (a note that says the opposite fails the
  test). The first CI run, with Apache 2.4.58 and HAProxy 2.8.30 on Ubuntu 24.04, observed five facts: `apache2ctl configtest`
  passes although the key does not belong to the certificate; a graceful reload of Apache with a damaged key stopped the
  process and the agent's rollback did not bring it back (result `rolled_back`, process gone); `haproxy -c` fails on a key
  that does not match the certificate; the directory form of HAProxy's `crt` ignores the agent's temporary `.myownpki-*`
  file; and the order of certificate and key in the combined file does not matter. They are in the recipe notes and on the
  recipes page.
- **Documentation:** the site page *Guides in the UI*, the recipes page for Apache, HAProxy and `files.combined`, the upgrade
  row and the agents-first note, the Salt page and README (`combined`), operations guide chapter 17 and the updates of §12.

### Changed

- **The container image moves from `distroless/static-debian12` to `static-debian13`**, pinned by the digest of the index
  (the newest one older than two weeks, as `THIRD_PARTY.md` says). The user (65532), the data directory and the health check
  are unchanged. The CI job `image` now checks the user, `--version`, the CA bundle and the owner of the data directory in
  the built image.
- **The hint of `deployment add`** about log files and low ports is no longer printed for `haproxy -c`, and for
  `apache2ctl configtest` and `apachectl -t` it names only the log directory (Apache opens its error log even for a check).
  It is still printed for `nginx -t`.
- The `--recipe` help and the *Add host* assistant list the new recipes; the Salt formula passes `combined` through to
  `deployment add` (the recipe names need no change there).
- `api/openapi.yaml` `info.version` is 0.3.11.

### Fixed

- **Operations guide §12.1** told the admin to use *New intermediate*. The UI has **New CA** with the field *Parent CA*.
- **The offline root guide** said one number for the CRL lifetime of an imported root. The server plans 180 days (and shows
  that in the OpenSSL command it prints); `pki.sh crl` signs for `CRL_DAYS` of its `pki.conf`, 30 days by default, and the
  server's alert counts from the dates of the uploaded CRL. The page now says what each tool does.
- **`site/faq.md`** still listed v0.3.10 as planned.

### Security notes

- **No recipe edits a service configuration, and no hook takes a value from the server.** Every hook is an absolute argument
  vector run without a shell; `{name}` appears only in paths, and a name that is not lower case letters, digits and `-` is
  refused before a path is built. The only sandbox directory a recipe adds is a log directory.
- **The combined file holds a private key.** It has the key mode and the owner of the deployment, never the mode of a
  certificate, is written with an exclusive temporary file in the target directory and one rename, and is held in memory only
  while it is built; the buffers are cleared after use and the key is in no log, error, journal field or status. The journal
  backup of the old file is a `0600` state file. `combined` cannot name `state_dir`, `ca_bundle` or another deployment's file.
- **The guides cannot carry markup or a script.** The parser accepts only the closed subset, templ escapes every string, links
  are checked against a short list of targets, and a command in a guide must start with a known program.
- **First steps reads and never writes.** It is computed from calls the user may make; a role limited to one CA sees *Not
  available to your role* for tenant-wide rows, and the ACME directory in a guide is shown only to a role that reads the whole
  tenant. No secret, token, passphrase or key is on any of the pages.
- **The demo is marked as a demo for good** (banner and a warning at every start), is hardened like the production example
  (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`, no published port except `127.0.0.1:9443`), keeps its secrets in one
  file in its own volume, masks them in CI, and takes the agent for its second act from the verified package of the server image.
  The server still never reads its passphrase from a file or a variable.
- **An independent security review of the agent recipes and the guides found no blocker; its findings were fixed.** A temporary
  file left by an interrupted write (for a combined file a copy of the key, which another HAProxy version may load when `crt` is a directory; HAProxy 2.8.30 ignored it in the CI run)
  is now removed at the start of the agent; links to the site and the repository with a `..` segment are refused; the certbot
  guide warns that the EAB MAC key on a command line is visible in the process list and the shell history; the buffers of the
  combined file and the previous pair are cleared; a guide parser that took seconds on a line of braces is linear; and the ACME
  address is hidden from a CA-scoped role in the guides, as it already was in First steps.
- **No new dependency**; `go.mod` and `go.sum` are unchanged. New CI-only images (certbot, nginx, the distroless base) are
  pinned by digest in `THIRD_PARTY.md`.

### Known limitations

- **The live test by the maintainer is pending.** `apache2`, `httpd` and `haproxy` are **example recipes, not yet run on a live
  host**: the real systemd unit and its sandbox, the Red Hat layout, SELinux, a reload with a failing configuration and the
  local check against real `bind` lines are untested. CI runs the recipes against the Ubuntu packages only.
- **`apache2ctl configtest` and `httpd -t` do not detect a key that does not match the certificate** (observed in CI with Apache
  2.4.58 on Ubuntu 24.04; `httpd` on the Red Hat family was not run). The agent's check of the pair before it writes is the
  guard; a pair damaged after it reaches the reload. `haproxy -c`, in contrast, fails on such a pair.
- **A failed reload can stop Apache, and the rollback does not start it again.** In CI a graceful reload with a damaged key ended
  the Apache process; the agent restored the previous files and reported `rolled_back`, but Apache stayed down. After a
  `rolled_back` result look at `systemctl status apache2` (`httpd`). Seen with `apache2 -k graceful` on a private
  configuration, not under the real unit.
- **`apache2ctl configtest` in the agent's sandbox needs Apache to have started once since the boot.** It creates
  `/run/apache2`, `/run/apache2/socks` and `/run/lock/apache2` when they are missing; the unit runs with `ProtectSystem=strict`
  and the recipe makes only `/var/log/apache2` writable, so the test hook (and a `systemctl reload`) fails on a host where
  Apache has not been started since the boot. After one normal start the directories exist and nothing is written.
- **The six guides have not been run on a live instance**, nor have the certbot and EAB flags in them. A guide may differ from the
  program in a detail; the long page on the site is the reference.
- **The demo has not been run on the maintainer's Docker host,** and the image tag `0.3.11` exists only after the release is
  published (until then set `MYOWNPKI_IMAGE`). The agent act of the demo needs one approval click and is not in CI. `./demo.sh run`
  is not one `docker compose up`: the server never reads its passphrase from a file, and a domain needs a second factor.
- **The guides are short in-app texts that point to the site,** not copies of it. A guide can drift from the long page; each
  lists its `sources`. There is no Markdown library: the format is a small closed subset.
- **First steps cannot see a backup or the devices that trust the root** (*Not detected*), does not test the public base URL
  from outside, and has no "dismiss" and no redirect after sign-in.
- **The Salt test cases `debian-apache2` and `debian-haproxy` are not added yet** (the `salt formula` job would run them for
  the first time); `combined` and the recipe names pass through the formula unchanged.
- **The Debian 13 base image** has not been run on a live Docker host with real webhooks and SMTP over TLS (`myownpki notify test`).

### Upgrade notes

- No migration (`myownpki db status` shows the same versions as 0.3.10), no configuration change and no change to the agent
  protocol, so going back needs no restore.
- **Update the agents first** on every host that will get a `files.combined` deployment (the HAProxy recipe, `--combined`, or
  `combined` in a Salt pillar or a rendered `agent.yaml`): an older agent refuses the key and does not start. A host without
  the key is untouched. The recipe names live in the agent, so an agent older than 0.3.11 does not know `apache2`, `httpd` or
  `haproxy` either.
- The container image has a new base. `docker compose pull` and `up -d` are enough; `docker compose ps` should show `healthy`.
- The step-by-step version is on the site page *Upgrade*.


## [0.3.10] - 2026-11-15

Preview and versioned settings. The review step of the issue wizard and a new REST operation show what the policy would
do with a request before anything is signed: the verdict, every reason, the checks, the names, the key, the validity, the
extensions, the chain and the URLs. Every change to a domain and to the tenant settings is now kept as a version with who,
when and an optional reason; a structured diff compares versions, and an old version is restored as a **new** version.
Two admins editing the same object can no longer overwrite each other silently. The release adds two migrations and no
dependency. The live test by the maintainer is pending.

### Added

- **`Engine.Plan`** (`internal/ca/plan.go`): `Engine.issue` is split into `plan` (authorize, preset, CA, key, names, name
  constraints, EKU limits, validity: everything up to the refusal reasons) and `commit` (key, serial, signature, storage).
  `Issue` is plan plus commit; `Plan` runs the first half and never writes, never audits and never reads the engine's
  randomness. The checks are an ordered list (five gates and five collected checks) whose problems, concatenated, **are** the
  refusal reasons, so a preview shows the reasons of a real issuance. A sealed key ring is recorded in the plan instead of
  returned as an error.
- **`POST /api/v1/certificates/preview`** (`previewCertificate`, role operator, no second factor): the body of
  `POST /certificates`, the answer `CertificatePreview` (with `PolicyCheck`, `ChainLink` and `ExtensionInfo`). A policy
  refusal is a **`200` with `allowed: false`** and every reason, where issuing answers `422`; the permission, format and size
  answers are those of issuing. No serial number, CA ID or CSR in the answer. A sealed server previews and says `sealed: true`.
- **The review step of the wizard** lists the verdict and the reasons, a table of the policy checks (*Passed*, *Refused*,
  *Refused, stopped here*), what would be issued, the extensions, who signs, the chain with SHA-256 fingerprints and the AIA
  and CDP URLs, and the notes and warnings. A refused plan disables *Issue certificate*; a plan that cannot be made says so
  and leaves issuing possible. The page says that *Not before* is the moment minus 5 minutes and that the checks run again
  when you issue.
- **Versions of domains and tenant settings:** the append-only table `settings_versions` in `pki.db` (migration **0021**) and
  in `system.db` (migration **0015**); the package `internal/settingsver` (closed snapshot types with a schema number, canonical
  JSON and SHA-256, a field diff that compares lists as sets, `Append` with an expected-version check). Every domain create,
  update and delete and every settings change writes a version in the same transaction as the change and its audit entry; the
  first change of an object without history first writes a `baseline` version of the state before it.
- **History and restore in the REST API:** `GET /domains/{domainId}/versions`, `GET /domains/{domainId}/versions/{version}`
  (a diff against `previous`, `current` or a number, plus `restorable` and `restore_problems`),
  `POST /domains/{domainId}/versions/{version}/restore`, `GET /domains/deleted`, and the same three under `/settings/versions`.
- **History and restore in the web UI:** a *Settings* / *History* tab row on the domain page and on *Administration → Tenant
  settings*, the history list, a page per version with the diff table (*Setting*, *Before*, *After*), the restore form and its
  dry-run reasons, and *Deleted domains*, linked under the domain list. The diff table is in the `/design` gallery.
- **`ETag` and `If-Match`:** the quoted version number as `ETag` on `GET /domains/{id}`, `GET /settings` and the answers of
  their writers; an optional `If-Match` on `PATCH` and `DELETE /domains/{id}` and `PUT /settings`, required on a restore. A
  stale value is `412` `precondition-failed` (with `current_version`, `changed_at` and, for a caller with the tenant-wide audit right, `changed_by`); a weak `W/"7"` counts as `"7"`; a missing one on a restore
  is `428` `precondition-required`. Both are new problem types.
- **`reason`:** an optional write-only field of 200 characters in the `POST`, `PATCH` and `PUT` bodies and in the restore
  body, kept with the version and never copied into the audit log.
- **Audit actions** `domain.restore` and `tenant.settings_restore`.
- **Documentation:** the site pages *Preview a certificate* and *History and restore of settings*, operations guide chapter 16
  and the upgrade note, and updates to the FAQ, glossary, tour, API, troubleshooting and audit-log pages.

### Changed

- **The edit forms of a domain and of the tenant settings** carry a hidden `base_version` and an optional *Reason (optional)*
  field (also on the domain delete form). A save that is based on an older version is refused with a page *Changed meanwhile*
  (409) that says when the object was changed, and by whom for a reader of the history ("somebody else" otherwise); nothing is
  saved. A form without the field is not checked, as before.
- **The audit entries** `domain.create`, `domain.update`, `domain.delete` and `tenant.settings` carry `version` and
  `snapshot_sha256`.
- **A domain has at most 256 IP ranges** (`422` beyond that, `maxItems: 256` in the OpenAPI file), so that its snapshot always
  fits the 64 KiB limit. The audit entry of a domain change lists at most 16 ranges and counts the rest. A domain stored with more
  can be deleted; an update that leaves its `ip_ranges` as they are is refused until the list is trimmed. Its baseline and
  deleted state keep the first 256 ranges (`history_ip_ranges_kept`, `ip_ranges_total` in the audit details), and a restore of
  such a version brings back only those.
- **An invalid argument of the history,** such as a snapshot above the size limit, answers `422` `policy-violation` instead of
  `500`. A concurrent create of the same domain name during a restore gives the same `422` "domain … exists already" as the
  name check, and the audit entry of a refused domain restore names `restored_from`.
- **Changing a domain that was deleted meanwhile** now answers not found; it used to be a silent update that changed no row.
- The order of the random draws of an issuance is unchanged (key first, then the serial number), and the existing issuance,
  ACME and agent tests ran unchanged against the split of `issue`.
- `.form` lets its grid column shrink, so a wide table of the review step scrolls inside its wrapper instead of widening the
  page; no class was added.
- `api/openapi.yaml` `info.version` is 0.3.10.

### Security notes

- **A restore is a change.** It runs the ordinary writers, so every check of a normal change applies with the same reasons,
  and it needs the permission and the second factor of the same change: `ca.manage` with a fresh second factor for domains,
  `tenant.manage` plus `agent.enrollment` and a fresh second factor when the agent enrollment mode changes. **An API token
  never satisfies a second factor.** Reading a history, and so restoring a version, needs the audit right on the whole tenant,
  because versions name users: an admin of one CA may change a domain but cannot restore it. The name of the person who
  changed an object is given (in a `412` and on the *Changed meanwhile* page) only to a caller with that right.
- **Secrets cannot enter a snapshot.** A snapshot is a closed struct, never a copy of a row. Two tests fail the build when a
  field or a column is not classified (the reflection test and the `PRAGMA table_info` test of `tenants` and `domains`). The
  configuration file, with the notification secrets, is not in a database at all.
- **History cannot be edited:** triggers abort `UPDATE` and `DELETE` of a version and an `INSERT` that collides with an
  existing one (`INSERT OR REPLACE` would otherwise remove a row without the `DELETE` trigger), and a version is written in
  the transaction of its change, so a rolled-back change leaves none.
- **The preview writes nothing:** no row, key, serial number, random bytes or audit entry; tests assert the row counts and
  run the engine with a random source that fails when read. The CSR is never echoed, and names from it are escaped on the page
  and are data in the API. The preview needs the permission of issuing, and its reasons are the ones issuing gives that caller.
- **The reason is untrusted text:** at most 200 characters, no control and no invisible formatting characters (bidi overrides,
  zero-width characters), escaped on output, and kept out of the
  audit log.
- **An independent security review found no blocker; its findings were fixed before the release.**
- **No new dependency**; `go.mod` and `THIRD_PARTY.md` are unchanged.

### Known limitations

- **The live test by the maintainer is pending.** The preview, the history pages and the restore are covered by the test
  suites (and the review step was looked at in a browser at 375 px, in light and dark), not run on a live installation.
- **The wizard does not apply the tenant subject defaults that the REST path applies,** and the wizard ignores the names of a
  CSR where REST uses them. The preview shows what each path really does. Which behavior should win is an **open decision**.
- **No retention limit:** every version is kept, with no pruning, export or import. A snapshot is small (estimated at 0.5 KiB).
- **The history is admin-only** (audit right on the whole tenant): an operator, a viewer and an admin of one CA cannot read it,
  and an admin of one CA cannot restore a version of a domain they may change.
- **The actor name in a version is personal data in an append-only table** and cannot be scrubbed later, like the audit log.
- **Presets and CA limits are not versioned,** nor are per-account and per-agent settings, agent names and secrets.
- **The check is per object:** two admins editing different fields of one object still conflict.
- **`If-Match` is optional on the old calls,** so a script without it keeps last-writer-wins.
- **No preview for ACME orders, renewals or agent issuance,** and no dry run for edits; the preview has no rate limit of its
  own. A conflict page does not keep the values you typed.
- Changes made before the update are not in the history; the first change afterward stores the old state as version 1.

### Upgrade notes

- `pki.db` migration 0021 and `system.db` migration 0015 add a table each (additive). An older binary refuses the migrated
  databases, so going back means restoring the backup from before the update. No configuration change, no change to the agent.
- Scripts keep working: `If-Match` is optional on `PATCH`, `DELETE` and `PUT`. Browser forms that were open during the update
  have no `base_version` and are not checked.

## [0.3.9] - 2026-11-13

The trust portal. The page at `/` of the public listener now guesses the visitor's system from the browser, lets the
visitor choose another one, and shows the steps and commands that install a root there; iPhone, iPad and Mac get a
configuration profile. The root's page in the admin UI shows the portal's address and a message to send to users.
An agent host can put the root of this PKI into its own system trust store on request, by command or with the Salt
formula. The release adds no dependency and no migration. The live test by the maintainer is pending.

### Added

- **Trust portal** (`GET /` of the public listener, internal package `trustkit` for the generated parts): the page
  starts with a warning that it comes over plain HTTP, so nothing on it proves itself, and says where to get the
  SHA-256 fingerprint another way (the admin UI, `myownpki ca show NAME`, `openssl`). Then a table of the roots
  (name, common name, validity, DER and PEM downloads) with each root's SHA-256, the list of systems, the steps for
  the chosen system and a table of the intermediates (downloads only: servers send them, nothing is installed).
- **Platform detection** from the `User-Agent` (first 512 bytes, a fixed table, no regular expression: iPhone, iPad
  and "like Mac OS X", Android, Windows, macOS, Debian and Ubuntu, Fedora, Red Hat and CentOS, Linux or X11 as both
  Linux blocks, ChromeOS as nothing; Firefox is a flag) and a manual choice with `/?os=<value>`: `windows`, `macos`,
  `ios`, `android`, `debian`, `fedora`, `firefox`, `java` or `all`. Any other value counts as not given.
- **Install blocks per platform**, generated per root from the database: Windows (the DER as `.cer`, the certificate
  dialog, and PowerShell for the current user and for all users), macOS (profile and a Terminal block), iPhone and
  iPad (profile, and the second step under *Certificate Trust Settings*), Android (user CA store; apps that target
  API 24 or higher ignore user CAs), the Debian and RedHat families, Firefox (`security.enterprise_roots.enabled`
  on Windows and macOS only) and Java (`keytool` without `-noprompt`). Each block with a command says that the
  embedded SHA-256 only checks the download against the page.
- **Configuration profile** (`/trust/<name>/<generation>/profile.mobileconfig`, roots only): unsigned, only the public
  certificate, byte-identical for the same root, removable by the user, `application/x-apple-aspen-config`.
  Devices show it as *Not Signed*.
- **Admin UI:** a root's page shows a *Trust portal* row (the address, or why there is none) and a plain-text
  *Message for your users* with the address, the root's SHA-256 and the iPhone step.
- **Agent: `system_trust`.** Off by default. `myownpki-agent trust install --root-sha256 HEX [--no-record]`,
  `trust remove` and `trust status [--quiet]`, `setup --system-trust`, the `agent.yaml` key
  `system_trust: {root_sha256: "<64 hex digits>"}` and a `system trust` line in `config check`. Root only, never part
  of `run`. Debian-family and RedHat-family hosts, one fixed file and one fixed command per family, the pin checked
  against `ca_bundle` (one self-signed CA certificate) before anything is written, a failed command rolled back.
  `config check` exits 1 only when the key does not match `ca_bundle`.
- **Salt formula:** the pillar key `system_trust` (a boolean, default `false`) and the state
  `myownpki-agent-system-trust`; `--no-record` with `config_source`; the formula refuses a value that is not a boolean,
  `true` on a minion that is not Debian or RedHat family, and `true` with a version below 0.3.9. `false` or absent
  creates no state and the formula never removes the root.
- **Screenshots tool:** a `public` view kind (the demo instance's public handler) for the portal shots, and `-only`
  now also selects the standard shots by name.
- **Documentation:** the site page *The trust portal*, operations guide §11.2, §11.3 and §12.12, two pictures in the
  tour, and the notes in the FAQ, glossary, guide, CLI and Salt pages.

### Changed

- **The `trust_page` setting** keeps its name, default and API field. Its label is now *Trust portal at / of the public
  listener (CA certificates, fingerprints, install steps per platform)*, and its help text names the portal page, its
  `?os=` choice, the profile and the Windows helpers and says that `/ca/` and `/crl/` stay served.
- **File names:** downloads, the profile, the Linux files and the Windows helpers carry the first 8 hex digits of the
  certificate's SHA-256 (`<name>[-<generation>]-<8hex>.crt`, `myownpki-<name>[-<generation>]-<8hex>.crt` on Linux,
  `…-trust-computer.cmd`), so two certificates never share a name. The `/ca/` URLs are unchanged.
- **The page:** one block per system instead of one section per CA with a guide for the first root only. The by-hand
  Windows step is now the certificate dialog and two PowerShell blocks instead of `certutil -addstore`; the text of the
  Windows helpers is as before. The Linux commands download, check the hash and install in one `&&` chain instead of
  `sudo cp`.
- **Caching:** the page sends `Vary: User-Agent` and is `private, max-age=300` when the browser told it something,
  `public, max-age=300` otherwise; the profile and the helpers are `public, max-age=900`. `.btn-row` has a bottom margin.
- `api/openapi.yaml` `info.version` is 0.3.9, and the description of `trust_page` follows the web UI (description only).

### Security notes

- **A public page without a sign-in shows only public data:** CA certificates, their fingerprints and text. A request
  can influence two things: the platform guess (a row of a fixed table) and the `?os=` value (an entry of an
  allow-list). Nothing of the `User-Agent` or the query is written into the page, a header, a file name or a command
  (tests plant a canary in both). The `Host` header is not used: addresses come from the CA's public base URL.
- **No half-checked command.** The base URL must pass a conservative pattern and the CA name its own check; otherwise
  the block shows no command and says to compare by hand. Variables in a command are hashes, validated names and that
  address. The Linux, macOS and Java chains are joined with `&&` and start in a new `mktemp -d` directory, so a failed
  check stops them and another local user cannot swap the file between the check and the install.
- **The page does not claim more than it can.** It says first that nothing on it proves itself, and that the hash in a
  command only checks the download against the page. The Windows helpers still contain no expected value.
- **Switched off means 404**, the same as for a path that never existed; `/ca/` and `/crl/` stay. None of the portal's
  own routes redirects (Go's router still answers 307 for an unclean path before a route runs). A request writes no
  state, no log line and no audit entry. The Content Security Policy has no `script-src`.
- **Agent:** the install is a command run by root, not part of the service; the sandbox of the unit and its drop-ins
  are unchanged. The checked bytes are the ones written; the files and the command are fixed; no shell, a cleaned
  environment, a time limit, umask 022; symbolic links are refused; `remove` deletes only a file that holds the pinned
  root. What the option allows is stated: every program on the host then trusts that root for every name.
- **No new dependency**; `go.mod`, `go.sum` and the guard of the server binary's imports are unchanged.
- **An independent review found no blocker, and its findings were fixed:** a switched-off page that differed from a
  404, a helper file name built from the request's text, colliding file names, commands that ran in a shared directory,
  the trust command run again after a failure and for unchanged files, the hook's umask and the removal command, and
  a root page that offered an address for a root the portal does not list.

### Known limitations

- **The live test by the maintainer is pending.** How iOS, iPadOS, macOS, Android and Firefox show the profile and the
  menus, what a profile without a scope does on a Mac, whether Firefox on Linux honors `enterprise_roots`, and
  `update-ca-certificates` on a real host were **not tested on devices**; the menu names on the page are the vendors'
  documented ones and may differ. The page is corrected after the live test.
- **The page cannot prove itself.** It comes over plain HTTP (the public listener has no TLS), so the fingerprint must
  be compared with a value from another source, and the hash in a command checks the download only against the page.
- **No rate limit** on the public listener and no counters; limit in the reverse proxy when it is reachable from the
  internet.
- A shared cache may serve the profile and the helpers for up to 15 minutes, and a `public` page for up to 5, after the
  portal is switched off. The directory a pasted command creates with `mktemp -d` stays behind.
- Detection is a guess: an iPad that asks for the desktop version looks like a Mac, a Linux without a distribution
  shows both families, ChromeOS shows the list. The profile is unsigned (*Not Signed*); there is no MDM payload, no QR
  code and no installer script. There is no way to hide one root from the portal.
- `system_trust` supports Debian-family and RedHat-family Linux only, adds the host's own root only, and a renewed root
  needs a new `trust install` after `setup`. As non-root, `config check` cannot read a 0600 `ca_bundle` and does not
  check the key against it. The Salt render has run in CI only.

### Upgrade notes

- No migration and no configuration change; `myownpki db status` is unchanged, so going back needs no restore.
- **Update the agents before you enable `system_trust`:** an agent older than 0.3.9 refuses the key and does not start.
  Update the server first, as always. The new file names and headings change the page, not the `/ca/` URLs.

## [0.3.8] - 2026-11-13

Charts, reports and analysis: a *Reports* page with the expiry of the current week and the next 12 weeks, the issuances by source,
the certificates per CA, the alert history and the agent fleet, two of the charts on the dashboard, and an
*Analysis* page that applies ten fixed rules and says what each finding saw, why it matters and what to do.
The charts are drawn by the server as SVG; no script runs in the browser. Both pages and two new REST
endpoints compute everything from data the server already holds. The live test by the maintainer is pending.

### Added

- **Reports page** (`GET /reports`, menu *Overview*): five sections, each a fold with a chart, a sentence that
  says what is counted and a *Numbers* table with the same figures. *Expiry*: 13 weekly columns, the current ISO
  week and 12 more (UTC, Monday start), colored by the warning and critical windows of the monitor
  (`monitor.expiry_days`). *Issuances*: the last 12 weeks, stacked by source (ACME, agent, UI and API), derived from
  the ACME orders; imported and external certificates and agent identity certificates are not counted.
  *Authorities*: certificates per CA by valid, expiring, expired and revoked, with the certificates that have no CA
  of this server as *External certificates*. *Alerts*: opened per week over five weeks (the 30 days the server keeps)
  by severity, and how many are open. *Agents*: state, version against the server and deployments, only while the
  agent listener is on. *Expiry* and *Authorities* are open, the rest closed; the state is not remembered. The numbers
  are built at most once a minute per tenant and the page says when.
- **Two charts on the dashboard** (*Expiry* and *Authorities*) below the table of certificates that expire in 30 days,
  each in an open fold, with a link to the Reports page. A failed build costs the charts, not the dashboard.
- **Analysis page** (`GET /analysis`, `?rule=<id>`): a summary line, the findings (*Severity*, *Rule*, *Subject* with a
  link, *What was seen*, *Why it matters*, *What to do*), the state of every rule (`ok`, `findings` or `unknown` with the
  reason) and a short explanation. Ten rules: `orphaned_certificate`, `duplicate_certificates`, `renewal_loop`,
  `expiry_wave`, `weak_key`, `weak_signature`, `ca_cliff`, `outdated_agent`, `unused_acme_account` and `unused_domain`;
  the thresholds are in the operations guide §15.2. A rule without the data to judge says `unknown` and never produces a
  finding. The analysis is advice only: it raises no alert, sends no message, stores nothing and has no dismiss.
- **REST:** `GET /api/v1/reports` and `GET /api/v1/analysis` (with `?rule=<id>`; an unknown id is `400`), described in
  `api/openapi.yaml` (tag `monitoring`, role viewer, `403` for a role or token limited to one CA, `Cache-Control:
  no-store`, work while the server is sealed).
- **Migration `pki.db` 0020:** the indexes `certificates_created_at` and the partial `acme_orders_certificate`, for the
  issuance chart. Indexes only.
- **Chart and fold components** (`components.Chart`, `components.Fold`, `internal/web/charts`): server-rendered SVG with
  a title, a description, a legend and a numbers table under every chart; the series differ by pattern as well as by
  color; new tokens `--chart-s1` to `--chart-s3` and `--chart-w`; entries in the design gallery. Tests allow exactly one
  `<svg>` shape and check the contrast of the chart colors in the light, dark and OS-follow themes.
- **UI inventory:** `task screenshots -- -inventory` shoots every page of the real UI, light and dark, into the untracked
  `.tmp/ui-inventory/` (with the HTML of each page and `manifest.txt`), on a demo instance with extra seeds (agents,
  alerts, endpoints, back-dated issuances). A test fails when a page route is neither in the list nor on the exclusion
  list. **`docs/UI-GAPS.md`** is the ranked list of what the walk found missing or awkward; nothing in it is built.
- **Documentation:** the site page *Reports and analysis*, a new
  operations guide chapter 15, entries in the tour, FAQ, glossary and the lifetimes page.

### Changed

- **ACME new names page:** the text now says what a client does. The first order for a new name is refused with
  *unauthorized … is a new name … waits for approval*, the client does not wait, and it has to be run again after the name
  is approved.
- **Screenshots:** the certificate page (it shows *Revoke now* and *Plan revocation*) and the new names page are
  refreshed in the README, the tour and the guide.
- **Documentation:** `docs/PLAN.md` records that the charts are server-rendered SVG instead of the ECharts island (see
  Known limitations).
- `api/openapi.yaml` `info.version` is 0.3.8.

### Security notes

- **Permission before data.** The Reports and Analysis pages, the dashboard charts and both endpoints need the
  tenant-wide read permission (`pki.read`), like the Alerts page, because they name the CAs, hosts, accounts, agents and
  domains of the whole tenant. A role or an API token limited to one CA gets `403` and no menu entry. The check is the
  first thing the services do; the cache has no key that comes from a request and belongs to the tenant.
- **Names from outside are escaped.** CA, domain, agent and certificate names come from CSRs, ACME clients and agents.
  The pages escape them in the template, the findings clip them to 120 characters and carry them as plain text in JSON
  (no field holds HTML), chart texts are stripped of control and bidi characters and clipped, and a finding's link must
  be a path inside the UI.
- **SVG rules.** The only `<svg>` the UI may contain has one fixed shape; script, `<foreignObject>`, `<image>`, `<use>`,
  `<style>`, links, animation, `href`, `style` and event attributes are refused inside it, and tests render every page
  against that rule.
- **The Content Security Policy is unchanged** (`script-src 'self'; style-src 'self'`); no script was added and the
  charts need none. No new dependency: `go.mod`, `go.sum` and `THIRD_PARTY.md` are unchanged.
- **Read-only, nothing leaves the server.** The pages and endpoints are `GET` and change nothing. The two new packages
  import no network package (a test checks it) and the analysis only reads the stored result of the last TLS scan.
- **Migration 0020 changes no data.**

### Known limitations

- **The live test by the maintainer is pending.** The thresholds of the ten rules are defaults chosen without long
  experience, are constants in the program rather than settings, and are to be judged on a real installation; a finding
  that cries wolf is a bug report. Expect `orphaned_certificate` to say `unknown` without a TLS scan.
- **Charts are server-rendered SVG, not ECharts.** The plan named an ECharts island. ECharts' HTML tooltip is reported to
  write inline `style` attributes, which the strict CSP refuses (not verified for the current version), the repository
  has no JavaScript pipeline and esbuild is not an approved dependency. ECharts stays approved and unused; ADR-04 is
  unchanged. The price: no hover effects, zoom or legend toggles (a bar has the browser's own tooltip).
- The alert history is the 30 days the server keeps (five weeks). There is no dismiss or acknowledge of findings, no export
  (CSV or image), no per-CA slice (a role limited to one CA sees nothing of it), and no renewal heatmap or key algorithm
  chart. The sources of the issuance chart are ACME, agent, and UI and API together.
- A report and an analysis are built at most once a minute per tenant, so a change can take a minute to show.

### Upgrade notes

- `pki.db` migration 0020 adds two indexes and changes nothing else; there is no configuration change and no change to
  the agent. An older binary refuses the migrated database, so going back needs the backup. Update the server as always;
  nothing has to be set up for the new pages.

## [0.3.7] - 2026-11-13

dns-01 in the agent. A deployment can prove its names through a DNS TXT record, so the agent can get
**wildcard certificates**, certificates for a service **without port 80** and for a host **behind NAT**.
The agent writes the record through RFC 2136 (BIND, Knot, PowerDNS with a TSIG key) or the Cloudflare API,
waits until it is visible, lets the ACME server read it and removes it again. The server is unchanged: it
already only reads the record. The live test by the maintainer is pending.

### Added

- **`challenge: dns-01` for a deployment**, with a new top-level `dns_providers` map in `agent.yaml`: `type`
  (`rfc2136` or `cloudflare`), `credentials_file`, `nameserver` and `zone` (RFC 2136), `ttl`, `resolver`,
  `propagation` (`authoritative`, the default, `resolver` or `wait`), `propagation_wait` and
  `propagation_timeout`. A deployment names its provider with `dns_provider`. A wildcard name (`*.homelab.lan`)
  is allowed only with dns-01, a dns-01 deployment takes no `webroot`, and `config check` reports every
  problem at once. A new deployment key `check_name` sets the server name of the local TLS check, which a
  deployment of wildcard names needs.
- **A credentials file of its own** for the secret (a TSIG key, or a Cloudflare API token and optionally a
  second token that may only read zones): YAML with strict keys, never in `agent.yaml`, never on a command
  line or in the environment. The agent opens it without following a symbolic link and checks the open file:
  regular, mode 0600 or 0400, owned by root or the agent's user, at most 4 KiB, in a directory that only
  root or that user can write; the path may not be under `/home`, `/root` or `/run/user`, `state_dir`,
  `paths` or a deployment target. It is read when an issuance starts, so a rotated secret works at the next
  renewal without a restart. `myownpki-agent config check` lists the state of every credentials file
  (`ok`, `missing`, `wrong mode`, `wrong owner`, `unsafe directory`, `symbolic link`, `invalid`, ...) and
  exits 1 when a deployment uses one that cannot be used; it never prints a content.
- **RFC 2136 provider** (the agent's own, on `miekg/dns`): one TSIG-signed UPDATE over TCP adds the record and
  one removes exactly this run's value; `hmac-sha256` (default), `hmac-sha384` and `hmac-sha512`
  (`hmac-md5` and `hmac-sha1` are refused); a success is accepted only with an answer whose own TSIG
  verifies; the zone comes from `zone` or from an SOA lookup at the nameserver; a CNAME delegation of
  `_acme-challenge` is followed.
- **Cloudflare provider** (lego's, with the agent's own HTTP client): the system trust store, TLS 1.2, a
  30-second timeout and the `proxy:` of `agent.yaml`, never `HTTPS_PROXY`. Error answers are cut to their
  codes and short messages; a failed delete, which lego only logs, is reported as a cleanup failure.
- **Propagation check and cleanup:** `authoritative` waits until every authoritative name server of the zone
  has the record, `resolver` until the configured resolver has it, `wait` only sleeps. The agent uses its own
  resolver (`resolver`, else `/etc/resolv.conf`) and never falls back to public resolvers. The record is
  removed on success, failure, cancellation and timeout. Each removal gets 30 seconds; while the agent is
  stopping, all removals of one issuance share 12 seconds, so that systemd does not kill it in the middle of
  the second record. A failed removal is logged and shown in the deployment's *Last error*
  (`dns-01 cleanup failed: a TXT record may remain at _acme-challenge.<name>; …`, without provider text or
  secrets); it does not fail the issuance, the deployment stays `deployed`, and the next pass without a
  cleanup problem clears the text. With Cloudflare the notice appears when the create request may have
  worked (a network error, an answer that is not the API's JSON, a 5xx or a 2xx), not for a request the API
  refused with a 4xx. A challenge for a name that is not one of the deployment's names is refused.
- **`deployment add` flags:** `--challenge dns-01`, `--dns-provider`, `--dns-type`, `--dns-credentials`,
  `--dns-nameserver`, `--dns-zone`, `--dns-resolver` and `--check-name`. `--dns-type` defines a new provider
  entry; the same flags again change nothing and a different definition of an existing name is refused ("edit
  agent.yaml by hand"). A missing or wrongly protected credentials file is a warning, not an error, because
  a configuration tool may run `deployment add` before the secret file exists. `--dry-run` shows the diff.
- **Salt formula:** the seven options `dns_provider`, `dns_type`, `dns_credentials`, `dns_nameserver`,
  `dns_zone`, `dns_resolver` and `check_name` of a deployment, with refusals for a dns-01 deployment without
  `dns_provider` or with `webroot`, a `dns_*` option next to another challenge and a wildcard name without
  dns-01. The credentials file is not managed by the formula: place it with `file.managed` (`mode: 0600`,
  `show_changes: False`) in the host's own state.
- **Documentation:** the page [dns-01 and wildcard certificates](https://der-felix.github.io/MyOwnPKI/dns-01/)
  and the operations guide §12.11; the pages on adding hosts, the command line, recipes, the Salt formula,
  best practices, troubleshooting, upgrading, ACME explained, split DNS, the FAQ and the glossary no longer say
  that the agent has no dns-01.
- **Tests:** an in-process DNS server with a zone store (`internal/testutil/dnsserver`, imported by tests only)
  and a Cloudflare stub; the real agent against the real ACME server for a wildcard and its base name through
  RFC 2136 and through the stub, with the refusals (name missing in the agent's names, domain without
  wildcards, a record that never appears, a wrong key) and an empty zone after every case; a conformance
  test of the agent against the BIND of `test/conformance` in the job `ACME conformance`.

### Changed

- **Dependencies:** no new module and no version change. `github.com/miekg/dns` v1.1.72 is now a direct
  requirement in `go.mod` (it was indirect, through lego) and the lego packages `challenge`,
  `challenge/dns01`, `log` and `providers/dns/cloudflare` are used in addition to those of 0.3.0. lego's own
  RFC 2136 provider is **not** used: it would bring a Kerberos stack for GSS-TSIG (12 modules in the Linux
  build) that this release does not offer. The agent binary grows by about 0.6 MB. **The server binary
  carries neither lego nor `miekg/dns`**, checked by a test of `go list -deps` and a depguard rule.
  `THIRD_PARTY.md` has the details.
- `agent run` removes every environment variable that starts with `LEGO_`, `CLOUDFLARE_`, `CF_` or
  `RFC2136_`, and `SSL_CERT_FILE` and `SSL_CERT_DIR`, and logs their names, so nothing outside `agent.yaml`
  and the credentials file configures a DNS provider, turns on lego's debug output or chooses the system
  roots that the Cloudflare calls trust. The agent's own connections use the `ca_bundle` of `agent.yaml`. The
  hooks inherit the cleaned environment: they see none of these variables.
- The optional ARI lookup of a renewal pass is skipped while an issuance runs (a dns-01 issuance can wait up
  to 15 minutes) and asked again at the next pass, so it no longer stalls the pass.
- The local TLS check of a deployment uses `check_name`, else the first name that is not a wildcard, as its
  server name.

### Fixed

- **Restore instructions: run `restore` as root, then `chown`.** `myownpki restore` builds its work copy
  next to the data directory (in `/var/lib`) and renames it onto the data directory, so the service user,
  which cannot write to `/var/lib`, could not run it. The message of `install.sh` after a failed update
  (`rolled back … but it is not healthy either`), the upgrade page (*Roll back*), the operations guide
  §6 and the CLI page now say to stop the service, move the old data directory away, create an empty one,
  run `restore` as root, `chown -R myownpki:myownpki /var/lib/myownpki` and start the service. The
  program is unchanged.

### Security notes

- A TSIG key or an API token decides who may change a zone, so it is handled like a private key: a separate
  root-only file, checked on the open file, held in a type that prints as `[redacted]` in every log line,
  error, report and `%v`, removed from error texts and wiped when the issuance ends. No secret reaches the
  report to the server (the *Last error* of a deployment), `agent status`, lego's log or a panic text.
- Give the credential the least it needs: a TSIG key that may only add and remove TXT records at
  `_acme-challenge.<name>` (BIND `update-policy`), a Cloudflare token for **one** zone with *Zone / Read* and
  *DNS / Edit*. The pages say so; check the permission names against Cloudflare's documentation.
- The agent never asks the server about policy: the ACME server decides which names the agent may order. A
  wildcard is covered only by the identical `*.` pattern in the agent's names, and an enrollment pass still
  grants the host name only.
- A host that holds the key of a wildcard certificate can present itself as any name below it: give a `*.`
  pattern only to the agents that need it.
- An independent security review found no blocker; its six findings were fixed before the release. The
  fixes cover the redaction of the build error of a DNS provider (it ran after the secrets were wiped), a
  race between the wipe of a TSIG secret and a cleanup that was still running, the report of a failed
  cleanup in the deployment's status, a Cloudflare record that may remain although the agent holds no ID,
  one shared time budget for the cleanups while the agent stops, `SSL_CERT_FILE` and `SSL_CERT_DIR` in the
  agent's environment, and an ARI lookup that queued behind a running issuance; a test now pins that a CNAME
  target outside a configured `zone` is refused.

### Upgrade notes

- No migration, no change to the server's behavior and no configuration change; going back needs no restore.
  Update the server first, as always.
- **Update the agent before you add a dns-01 deployment.** An agent of 0.3.6 or older refuses an
  `agent.yaml` with `dns_providers`, `dns_provider` or `check_name` and does not start (unknown keys are
  errors on purpose). An existing `agent.yaml` works with 0.3.7 unchanged. To go back, remove the dns-01
  deployments and the `dns_providers` block first.

### Known limitations

- **The live test by the maintainer is pending.** Not tested against the real thing: the Cloudflare code
  against the real API (CI uses a stub), a BIND `update-policy` on the maintainer's server (the CI test uses
  `allow-update`), the default `propagation: authoritative` against name servers on port 53 (CI uses
  `propagation: resolver`), the Salt formula's dns-01 deployments on live minions, and macOS.
- Not supported: GSS-TSIG (Kerberos, Active Directory DNS), other DNS providers, the legacy Cloudflare global
  API key, DNS updates over HTTPS or TLS, more than one provider per deployment, **dns-01 for enrollment**
  (a host without port 80 enrolls with a join token and one approval) and dns-01 in the *Add host* assistant.
- A killed agent (`SIGKILL`, a power cut) can leave a TXT record behind, and the Cloudflare record IDs are
  kept in memory only. The record does no harm to validation; remove it by hand. There is no sweep.
- A changed option of an existing dns-01 deployment in a Salt pillar is not applied (remove it through
  `absent` first), as for every deployment.

## [0.3.6] - 2026-11-12

Salt formula: `deploy/salt/myownpki/` installs the agent from a hash-checked package, enrolls it with an
enrollment pass, adds its deployments and keeps them in step, from one `state.apply myownpki`. The
server and the agent are unchanged. The maintainer tested it live on five enrolled Debian amd64 hosts: one
`state.apply myownpki` upgraded the agent from 0.3.2 to 0.3.5, and a second apply changed nothing. The
enrollment of a new host with a pass, `rpm` hosts and other Salt versions are not tested live.

### Added

- **Salt formula for the agent** (`deploy/salt/myownpki/`: `init.sls`, `agent.sls`, `map.jinja`,
  `defaults.yaml`, `pillar.example` and a README). The pillar is `myownpki:agent`: `version`, `server`,
  `acme_directory`, `root_source` and `root_sha256`, `package.sha256` per architecture (`amd64`,
  `arm64`), optional `package.source` and `package.format`, `webroot`, `low_ports`, `enrollment_pass`,
  `config_source`, `deployments` and `absent`. On a minion it stages the package (`deb` or `rpm`, from the
  Salt file server or an `https://` URL) in `/var/cache/myownpki-agent`, **checks its SHA-256 against
  the value from your admin UI and installs only from that local file**, stages the root (which `setup`
  checks against `root_sha256`), writes the enrollment pass to `/root/myownpki-join-token` (mode 0600,
  never shown in any output or put on a command line) only while the host has no agent certificate, runs
  `setup` until it has one, and then applies the deployments with `deployment add` and `deployment
  remove` or renders a complete `agent.yaml` and runs `sandbox sync`. A second `state.apply` changes
  nothing. A new package on an enrolled host runs `setup` again, which is the update path. The formula
  never enables or starts the service (`setup` does when the host is admitted; the restart is
  `systemctl try-restart`), so a host that waits for an approval stays down until the next apply finds it
  approved. It fails closed: a missing required key, no hash for the minion's architecture, an unknown
  key, option or format, a pass that is not a string, `config_source` together with `deployments` and
  similar mistakes render one failing state, `myownpki-agent-refused`, and install nothing. Salt ignores
  `source_hash` for `salt://` sources, so the formula's explicit check, not Salt, protects the install.
  It is copied from the tag or fetched with gitfs; it is not part of the release archives.
- **CI job `salt formula`:** renders every test pillar of `deploy/salt/test/cases` (Debian amd64 with a
  pass, RedHat arm64 with `config_source`, a minimal pillar, an `https://` source and nine refusals) with
  `state.show_highstate`, checks which states exist and which must not, that the pass appears in no output,
  and runs `state.apply test=True` for the cases a Debian runner can apply. It uses a pinned Salt 3008.5
  (onedir, SHA-256 checked); `bash scripts/ci/salt-test.sh --self-test` runs the checks that need no Salt.
  It is not a required check.

### Changed

- **Container image tag `latest`:** every stable release now also moves `ghcr.io/der-felix/myownpki:latest`
  (a pre-release gets only its version tag). Production setups should keep pinning the version: `latest`
  moves with every stable release, and an update of a CA should be a decision. The example
  `docker-compose.yml` stays pinned.
- **`low_ports` on enrolled hosts:** a host that already has the systemd drop-in `20-low-ports.conf` needs
  `low_ports: true` in its pillar. Four of the five hosts of the live test did.
- **Documentation:** the Salt page is rewritten around the formula (install, minimal and full pillar, the
  first and the second apply, a host waiting for approval, removing the pass, updating, changing or
  removing a deployment, the refusals, what is and is not tested); the operations guide has a new
  chapter 12.10; the pages on adding hosts, upgrading and troubleshooting name the formula.
- `api/openapi.yaml` `info.version` is 0.3.6.

### Known limitations

- Tested live only on enrolled Debian amd64 hosts (the upgrade of the agent, and a second apply that changes
  nothing). **Not tested live:** the enrollment of a new host with an enrollment pass (`setup --token-file`,
  the removal of the pass file, a host that waits for approval), `rpm` hosts, `arm64`, `config_source` and
  the gitfs install. CI renders and applies the formula with `test=True` under Salt 3008.5 only. Try it on
  one minion first.
- A changed option of an existing deployment in the pillar is not applied: the formula adds a deployment
  only when `deployment list` does not show the name. Remove it through `absent` first, or use
  `config_source`.
- The agent's state directory must stay `/var/lib/myownpki-agent`; the formula looks for `agent.crt` there.

### Upgrade notes

- No migration, no configuration change and no change to the server or the agent. Update the server first,
  as always; going back needs no restore.
- Nothing uses the formula until you copy it to a Salt master. With it, updating the agents is a change of
  `version` and `package.sha256` in the pillar and a `state.apply`.

## [0.3.5] - 2026-11-12

Host onboarding: a new host goes from its name to a deployed certificate with an *Add host* assistant,
`myownpki-agent deployment add` writes `agent.yaml` and the systemd sandbox in one step, an enrollment
pass lets Salt, Ansible or a script enroll many hosts without a click per host, and the documentation
carries recipes for nginx, Postfix, Dovecot and Proxmox VE. The live test by the owner is pending.

### Added

- **`myownpki-agent deployment add NAME`, `list` and `remove NAME`:** `add` writes a deployment into
  `agent.yaml` and the matching entries into the systemd drop-ins in one step, instead of two hand edits
  that showed up only as `Read-only file system` after the first failed renewal. It checks the result
  with the loader of `run` and `config check` before it writes a byte, refuses a name that exists and the
  system directories (`/`, `/etc`, `/usr`, `/var`, `/home` and others) as `--dir`, `--webroot` or
  `--sandbox-write`, keeps comments and the previous file (`agent.yaml.bak`), writes the drop-ins first so
  that a crash never leaves a missing entry, runs `daemon-reload` and prints the restart command
  (`--restart` does it; the agent is never restarted by surprise). `--dry-run` prints a diff of
  `agent.yaml` and both drop-ins and writes nothing. `list` prints the deployments (no root needed);
  `remove` takes one out again, keeps `paths` unless `--prune-paths`, and never touches deployed files or
  state. All except `list` need root, also with `--dry-run`, and agent 0.3.5.
- **The sandbox model and `sandbox sync`:** `agent.yaml` gets an optional `sandbox:` block
  (`write: [dirs]` for directories only hooks write, such as `/var/log/nginx`, and `low_ports`). The
  drop-ins `10-paths.conf` and `20-low-ports.conf` are derived from `agent.yaml` by one piece of code that
  `setup`, `deployment add|remove` and `sandbox sync [--dry-run] [--adopt|--prune]` share. `sandbox sync`
  is what a configuration tool runs after it has rendered the file; `config check` prints the effective
  sandbox, whether the drop-ins match and warnings for system directories. `setup --acme-directory URL`
  writes the ACME directory into a new `agent.yaml`, so that the first deployment needs no hand edit.
- **Recipes:** `deployment add --recipe nginx|postfix|dovecot|proxmox` fills files, owner, key mode,
  hooks, the local TLS check and the sandbox directories; every explicit flag wins. The **nginx** recipe
  rests on a setup the end-to-end tests run. **Postfix, Dovecot and Proxmox VE are unverified examples,
  written from the documentation of each service and not yet run on a live host:** `deployment add` says
  so and lists what to verify, and the documentation says to try them on a non-production host first.
  The Proxmox recipe does not write into `/etc/pve`; `pvenode cert set` installs the files.
- **Enrollment pass:** one secret (`mjp_…`) that lets 2 to 25 hosts (default 10) enroll without a person
  looking at each one. An admin creates it with the second factor (*Agents → Join tokens → New enrollment
  pass*): a required label, 1 to 5 names or `*.suffix` patterns that a domain must cover, up to 7 days
  (default 24 hours). It is shown once; the server keeps the hash. A pass admits a host only after the
  server's http-01 check of that host passed (in `verified` and `auto`, never in `manual`), grants the
  host **its own name only**, and is refused for a host that already has an agent; every enrollment that
  presents it takes a use, also when it then waits in the queue. When the pass does not count, the host
  waits in the queue and `setup` prints why (`the enrollment pass has no uses left (10 of 10) – ask an
  admin for a new one`, `the pass expired`, `the pass was revoked`, `the pass is not for …`, `an agent for
  … exists – a pass admits new hosts only`). The list shows `active 3 of 10`, `used up`, `expired` or
  `revoked`, the hosts each pass admitted, and a *Revoke* button; revoking ends use at once and leaves the
  hosts as they are. Automation uses it with `setup --token-file` and reads the result with a viewer API
  token. `pki.db` migration 0019 (additive).
- **Enrollment pass in REST:** `POST /api/v1/agent-join-tokens` takes `kind` (`token` or `pass`) and
  `max_uses`; the join token schemas gain `kind`, `max_uses`, `use_count`, `state`, `revoked_at`,
  `revoked_by` and the `hosts` a pass admitted; new `POST /api/v1/agent-join-tokens/{joinTokenId}/revoke`
  (admin, second factor; `409` for one that cannot admit anybody any more); `DELETE` withdraws only a
  token or pass nobody used. **No API token can create or revoke a pass or a join token, whatever its
  role** (`403`; tests pin this for every role); give automation a viewer token. A pass without a label, with more than five names or for a name no
  domain covers is `422`; `valid_hours` above 168 for a pass and `max_uses` outside 2 to 25 are `400`.
  Audit actions `agent.token.create` (kind, uses, names, expiry) and the new `agent.token.revoke`; every
  `agent.enroll` entry names the token, its kind and the use (`3 of 10`), and the reason when it did not
  count. The secret is in no entry and no log line.
- **Add host assistant:** *Agents → Add host* (`/hosts/add`, in the menu and as a button on the agent
  list). Step 1 asks host name, service (nginx, Postfix, Dovecot, Proxmox VE, *certificate files only*),
  challenge and webroot, up to four more names and the package; step 2 checks the names against your
  domains and offers the three ways to be admitted with the approval each one still needs (a single-use
  token for this host, an existing pass that covers it, or no secret); the commands appear once, never
  cached and never in a URL: the token file, the verified root and package download, `setup`, the
  `deployment add` block and `deployment list`. The progress page `/hosts/add/<host>` follows the host
  and reloads itself every 10 seconds until the agent is online and every deployment is deployed:
  *Host enrolled* (waiting for the host, checking, waiting for your approval with *Approve* and *Refuse*
  for an admin, refused, expired, admitted), *Agent online* and one row per deployment (pending, deployed
  with serial and expiry, failed or rolled back with the agent's last error, shortened and shown as
  text). Viewers and operators can open it and get the commands for *no secret* or a pass; the token and
  the approval need an admin with a fresh second factor. *Agents → Install agent* is unchanged.
- **For scripts:** `GET /api/v1/agents` and `GET /api/v1/agent-enrollments` take `?hostname=` (exactly
  that host name), and the new `GET /api/v1/agent-install` (viewer) returns the facts for installing the
  agent without a browser: server URL, ACME directory, the root with its SHA-256 and the package files
  with theirs (`404` while the server has no packages).
- **Documentation:** operations guide §12.7 *Adding a host*, §12.8 *Enrollment passes* and §12.9
  *Recipes*, and an upgrade paragraph; the site has the page *Recipes* and rewritten pages for adding
  hosts and the Salt flow, which now uses an enrollment pass (the Salt formula is still planned for
  v0.3.6, and the page marks its sketch as an example to adapt).

### Changed

- **The systemd drop-ins come from one model (behavior change of `setup`):** `10-paths.conf` is no
  longer rewritten from `state_dir` and `paths` alone. See *Fixed* for what an operator sees after the
  update; `setup` on an existing host now reports `Kept in 10-paths.conf …` and `Added to 10-paths.conf: …`.
- The agent list has an *Add host* button next to *Install agent*, and *Join tokens* is now one page for
  tokens and passes. The generic detail and form pages can show wizard steps and reload themselves (the
  progress page uses a plain `<meta http-equiv="refresh">`; the UI still ships no script for it).
- `api/openapi.yaml` `info.version` is 0.3.5.

### Fixed

- **`setup` lost the hand-made `/var/log/nginx` entry:** it rewrote `10-paths.conf` from `state_dir` and
  `paths` on every run, and the *Update agent* commands run `setup`, so the entry that the operations
  guide tells nginx hosts to add was gone after the next update and `nginx -t` failed with
  `Read-only file system`. `setup` now keeps entries it cannot explain and says so.
- **`setup` removed `20-low-ports.conf`:** without `--low-ports` and with webroot enrollment it deleted
  the drop-in that the nginx hooks need for a listener on port 443. The file is now left as found, and
  removed only for an explicit `sandbox.low_ports: false`; a file that differs from the packaged one is
  not overwritten.
- **A standalone deployment did not count:** only the enrollment's challenge decided about
  `20-low-ports.conf`; a deployment with `challenge: standalone` failed to bind port 80. Any standalone
  challenge now installs it.
- A fresh `agent.yaml` could not hold a deployment, because `acme_directory` is required for one and
  `setup` wrote none: pass `setup --acme-directory`, or `deployment add --acme-directory`.

### Security

- **Changing the agent enrollment mode now needs a fresh second factor and is refused for an API
  token.** In `auto` mode a host that passes the enrollment check is admitted without a person, so the
  mode weighs as much as approving an enrollment (which already needed step-up) – but an API token with
  the admin role could set it, because tenant settings needed no step-up. The new permission
  `agent.enrollment` (admin only, step-up) guards exactly that change: in the UI the settings form asks
  for the code and then saves; `PUT /api/v1/settings` with a different `agent_enrollment` answers `403`
  `step-up-required` to a session without a fresh code and `403` `forbidden` to a token, and stores
  nothing. Saving the same mode, leaving the field out, and every other setting stay as they were, with a
  token too, and so does reading. **Behavior change for scripts:** one that switches the mode through the
  API stops working; change the mode in the UI. The `tenant.settings` audit entry already named the old
  and the new mode.
- **The enrollment pass is bounded on purpose.** It needs a person with the second factor to create and to
  revoke (no API token, whatever its role), admits only after a passed http-01 check, grants the host name
  and not the pattern, never replaces an existing agent, and ends at most 7 days after creation. A leaked
  pass still admits as many more hosts as it has uses left for names that match; the documentation says
  to keep it short, small and out of the pillar after the roll-out, and what to do if it leaks.

### Upgrade notes

- `pki.db` migration 0019 is additive: existing join tokens stay single-use tokens (a used one counts
  as one use), and no certificate, agent or enrollment changes. A restart leaves the server sealed, as
  always. Update the server first.
- Agents of 0.3.4 keep reporting and nothing changes on them. `deployment`, `sandbox sync`,
  `setup --acme-directory` and the `sandbox:` key need the 0.3.5 agent; **run `setup` once on every
  existing agent** (*Agents → Update*) to get the fixes above: a hand-made `/var/log/nginx` in
  `10-paths.conf` and an installed `20-low-ports.conf` stay. `myownpki-agent sandbox sync --adopt` turns
  the kept entries into `sandbox.write`.
- A script that sets `agent_enrollment` through `PUT /api/v1/settings` now gets `403`; change the mode in
  the UI.
- Going back to 0.3.4 means restoring the backup from before the update, because 0.3.4 refuses the newer
  `pki.db`, and a 0.3.4 agent binary refuses an `agent.yaml` with a `sandbox:` block (remove the block
  first).

## [0.3.4] - 2026-11-12

TLS scan: the server connects to the TLS endpoints you enter, reads the certificate each one serves and
tells you when it is not the one this PKI issued – the renewal that never reached the web server. The
live test by the owner is pending.

### Added

- **TLS scan (integration level 2):** an admin enters the endpoints that matter (host, port, optional
  SNI); the server connects to each one every 15 minutes, reads the certificate it serves and compares
  it with what this PKI issued for the name. A scan is one TCP connection and one TLS handshake, then
  close: no HTTP request, no client certificate, TLS 1.2 and 1.3. The chain is judged afterwards against
  the CAs of this PKI (`trusted`, `incomplete` when the endpoint does not send the intermediate,
  `untrusted`). The host must be covered by a domain, the domain's address policy applies at every scan,
  and only the ports of `monitor.scan_ports` are allowed. Limits: 100 endpoints, 4 workers, 10 seconds
  per scan (checking the chain afterwards has 5 seconds of its own), 4 addresses per name. Scheduling
  survives clock steps: an endpoint whose next scan lies more than twice the interval ahead is scanned
  at once. Only metadata of the served leaf is stored (fingerprint, serial,
  clipped subject and issuer, dates, chain state, TLS version) – never the certificate, a key, the names
  in it or the resolved address. Scans, evaluation and alerts work while the server is sealed.
  `pki.db` migration 0018 (additive).
- **Scan alerts:** `scan_mismatch` (the endpoint serves an older, a foreign or a wrong-name certificate,
  seen by two scans in a row once the newest certificate for the name is `scan_mismatch_after` old;
  a revoked certificate is critical after two scans, with no waiting time), `scan_expiry` (the served
  certificate ends within the `monitor.expiry_days` thresholds, unless `cert_expiry` already reports
  it), `scan_unreachable` (after `scan_unreachable_after` failed scans in a row, so a reboot stays quiet;
  critical after 24 hours) and `scan_chain` (incomplete or untrusted chain). A name this PKI never issued
  shows *Not issued by this PKI* and raises no mismatch. The text of an alert never holds subject or
  issuer of the served certificate, which the remote host chooses. They count in the dashboard's *Open
  alerts* figure and reach e-mail and webhook like every alert.
- **Endpoints page:** the new page *Endpoints* (menu *Overview*) lists every endpoint with its state,
  last scan, served fingerprint (linked to the certificate when this PKI issued it), expiry, issuer and
  last error, and has *Add an endpoint*, *Scan now* and *Remove*. Subject and issuer are shown as text.
  A certificate of this PKI that has ended with nothing newer shows as *Expired*.
- **REST:** `GET /api/v1/endpoints` (viewer), `POST /api/v1/endpoints` (admin; refusals are `422` with the
  field and the rule, never a resolved address), `POST /api/v1/endpoints/{endpointId}/scan` (operator;
  `202`, `429` with `Retry-After` within 60 seconds, `409` while scanning is off) and
  `DELETE /api/v1/endpoints/{endpointId}` (admin). New permissions `endpoint.manage` (admin) and
  `endpoint.scan` (operator, admin); no step-up, because they grant no trust. Audit actions
  `endpoint.create`, `endpoint.delete` and `endpoint.scan`; refusals are audited too, and an endpoint ID that is not well-formed is "not found" after the
  role check.
- **Settings:** `monitor.scan_interval` (default `15m`, `5m`–`24h`, or `off`), `scan_timeout` (`10s`,
  `2s`–`30s`), `scan_ports` (`443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443`; 1–32 ports),
  `scan_max_endpoints` (`100`, 1–500), `scan_unreachable_after` (`3`, 1–10) and `scan_mismatch_after`
  (`1h`, `5m`–`24h`), each also as `MYOWNPKI_MONITOR_SCAN_*`. Out-of-range values fail `config check` and
  the start. `config check` shows the TLS scan rows.
- **Operations guide:** chapter 14, *TLS scan* – set-up in the UI and with `curl`, every state and what to
  do, the alerts, settings, limits, the address ranges that are never scanned, roles, a troubleshooting
  table and an end-to-end check – and an upgrade paragraph for v0.3.3 to v0.3.4.
- **Documentation site:** the guides, the operations guide, the release notes and the example
  configuration are published at <https://der-felix.github.io/MyOwnPKI/>, built from `site/` and the
  repository files by GitHub Pages; it has a page for the TLS scan.

### Changed

- **Stricter address guard (behavior change).** The check that decides where the server may connect is
  now one package (`internal/netguard`) shared by http-01 validation, the agent enrollment check and the
  scan. It now also refuses, under every address policy: the IPv6 ranges that embed an IPv4 address or
  translate to one – IPv4-compatible (`::/96`), NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4
  (`2002::/16`), Teredo (`2001::/32`) and the IPv4-translated range (`::ffff:0:0:0/96`) – because a
  router or a client may translate them to the embedded address (`64:ff9b::7f00:1` could reach
  `127.0.0.1`); the non-global ranges `192.0.0.0/24`, `198.18.0.0/15`, `192.88.99.0/24`, `fec0::/10`,
  `100::/64` and `5f00::/16`; and an IPv6 address with a zone. **A legitimate service in such a range can
  no longer be an http-01 target, an agent enrollment host or a scan endpoint.** The documentation
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) stay allowed.
  IPv4-mapped addresses are judged as the IPv4 address they carry. The error texts of http-01 are
  unchanged.
- **Dependencies:** `connectrpc.com/connect` 1.21.1, `github.com/a-h/templ` 0.3.1100 (generated files
  regenerated), `go.yaml.in/yaml/v3` 3.0.6, `modernc.org/sqlite` 1.61.0 (SQLite 3.54.1) and
  `golang.org/x/net` 0.62.0.

### Fixed

- **Agent commands with an absolute path:** the guided installation and update commands ended with
  a bare `myownpki-agent setup …`, which failed with `command not found` where root's `PATH` lacks
  `/usr/local/bin` (seen on Debian 13), although the package had been installed. Every command the
  UI generates for root – guided install and update for deb, rpm and tarball, and the new join
  token page – now calls `/usr/local/bin/myownpki-agent`, as does the agent's "not enrolled" log
  hint and docs/OPERATIONS.md. Packages, tarball and the systemd unit already use that path; a test
  keeps them in line.
- **Join token page runs setup:** the page of a new join token showed `enroll` and
  `systemctl enable --now`, which cannot work on a fresh package or tarball host – only `setup` writes
  `agent.yaml` and installs the unit (`Unit myownpki-agent.service does not exist`). The page now
  shows the token file (by here-doc, not as an argument), the root download with its SHA-256 check and
  `setup` with the detected package format, like the guided installation.

### Upgrade notes

- No action is needed: migration 0018 is additive, and the scan connects nowhere until an admin enters
  an endpoint. A restart leaves the server sealed, as always. To keep the server from ever connecting to
  the endpoints, set `monitor.scan_interval: off`.
- Roles: tenant admins add and remove endpoints, operators and admins scan now, viewers read. A role
  limited to one CA cannot see the endpoints, as with alerts.
- If a service of yours lives in an IPv6 range of the stricter address guard (NAT64, 6to4, Teredo,
  IPv4-compatible), http-01 validation and agent enrollment for it now fail with an address-policy
  error; use an address outside those ranges.
- Container installations need no new variables; the defaults of the `MYOWNPKI_MONITOR_SCAN_*` keys apply.
  Add the variables only to change them (operations guide, §14.6).
- Going back to v0.3.3 means restoring the backup from before the update: v0.3.3 refuses the newer
  `pki.db`.

## [0.3.3] - 2026-11-12

Monitoring: the server checks itself every minute, shows what needs an admin on a new Alerts page
and tells you by e-mail or webhook – also while it is sealed.

### Added

- **Alerts:** a job evaluates the rules every minute and keeps one alert per condition (kind and
  subject, severity, first and last seen, resolved) in system.db (migration 0014, additive). Kinds:
  `cert_expiry` (a valid end-entity certificate ends and no newer valid certificate covers the same
  names; agent identity certificates never count; an expired one stays 30 days), `ca_expiry`, `crl`
  (the dashboard's existing CRL states), `sealed`, `agent_silent`, `agent_certificate` and
  `deploy_failed`. `sealed` opens after 10 minutes and turns critical when a CRL of an online CA is
  less than 24 hours from its next update, because a sealed server can't sign a new one (RFC 5280
  §5.1.2.5). Alerts rise from warning to critical, resolve when the cause is gone and never
  duplicate. The evaluation reads `pki.db` and the seal state and decrypts nothing, so it works while
  sealed. Opened, raised, lowered and resolved alerts are logged once as `alert`.
- **Thresholds:** the new `monitor:` section (also `MYOWNPKI_MONITOR_*`): `expiry_days` (default
  `14, 3`), `ca_expiry_days` (`90, 30`), `sealed_after` (10m, 1m–1h), `agent_silent_after` (1h,
  10m–24h) and `repeat_every` (24h, 1h–168h). Out-of-range values fail `config check` and the start.
- **Notifications:** the new `notify:` section (also `MYOWNPKI_NOTIFY_*`) with an e-mail channel
  (`smtp`, `security` `starttls`/`tls`/`none`, `username`, `password_file`, `from`, `to`, `ca_file`;
  `none` only without a username) and a webhook (`url`, `secret_file`, `ca_file`). Channels and secrets
  live in the configuration and in files read at each send – not in the database – so a sealed server
  can still report that it is sealed. After each evaluation one **digest** per channel lists what
  opened, became critical, is still open after `repeat_every`, or was resolved; nothing is sent when
  nothing changed. E-mail is plain text over `net/smtp`; the webhook is a JSON `POST`, signed with
  `X-MyOwnPKI-Signature: sha256=<HMAC-SHA256 of the body>`, https only (http to loopback), 10 seconds,
  no redirects, honoring `HTTPS_PROXY`/`NO_PROXY`. Messages are queued in system.db and retried after
  1 minute, 5 minutes, 30 minutes and 2 hours, then dropped and logged as an error
  (`notification dropped after the last retry`). While no channel is configured nothing is marked as
  notified, so the first message after configuring one lists every open alert.
- **Alerts page and dashboard:** *Alerts* lists the open alerts (what to do, linked to the object) and
  those resolved in the last 7 days; admins get *Send test message*. The dashboard shows an *Open
  alerts* figure and lists critical certificate alerts, silent agents and failed deployments in
  *Needs attention*, with a link to the page.
- **REST:** `GET /api/v1/alerts` (viewer and up, `?state=open|resolved`) and
  `POST /api/v1/notifications/test` (tenant admin; `409` without a channel, `429` with `Retry-After`
  within 10 seconds of the last test). New permission `notification.test` (admin); each UI or REST
  test is audited as `notification.test` with the result per channel, never a secret.
- **`myownpki notify test [--channel email|webhook]`** sends a test message through the configured
  channels with the server's configuration and secret files (run it as the service user).
- **`config check`** shows the channels (e-mail by server, security and recipient count; the webhook
  by host only) and the thresholds in effect. A missing, unreadable or empty password, secret or CA
  file fails the check (exit 1); no channel at all only warns.
- **Operations guide:** chapter 13, *Monitoring and notifications* – setup, secret files, container
  variables, the test, what each alert means and what to do, retries, troubleshooting and an
  end-to-end check.

### Changed

- **Alerts name the whole tenant,** so reading them needs a tenant-wide role (viewer or higher). A role
  limited to one CA gets `403` from the API, has no *Alerts* entry and sees no alert block on the
  dashboard.

### Fixed

- **Agent packages in the container image:** the image carries the agent packages under
  `/opt/myownpki/agent-dist`, but nothing pointed `agent.package_dir` there, so a container served
  none of them. The image now sets `MYOWNPKI_AGENT_PACKAGE_DIR=/opt/myownpki/agent-dist`.
  Installations with install.sh were not affected.

### Upgrade notes

- No action is needed: migration 0014 is additive and `notify:` is off by default. To get messages,
  configure `notify.email` and/or `notify.webhook` (operations guide, chapter 13), restart and
  unseal. A restart leaves the server sealed, as always.
- The first evaluation runs one minute after the start. A server left sealed for more than 10
  minutes (for example after an update) opens a `sealed` alert, and agents that stopped reporting
  open `agent_silent` alerts, as soon as that evaluation finds them.
- Container installations: add the `MYOWNPKI_NOTIFY_*` variables and mount the secret files
  read-only (operations guide, §13.3).

## [0.3.2] - 2026-10-29

A fix release: the server now serves the agent packages it installs.

### Fixed

- **Agent packages on the agent listener:** a v0.3.1 server answered every `/agent-packages/`
  download with 404, because it named the packages after its full version line instead of the
  release version. Guided agent installation therefore found no package, and the agent list did
  not mark older agents for update. No migrations; update the server, then the agents.

## [0.3.1] - 2026-10-28

Guided agent installation and packages, independent Windows trust confirmation, configurable
step-up and protected-action continuation, and safe predecessor handling for UI, REST, ACME and
agent deployments.

### Added

- **Independent root trust verification:** the public trust page, authenticated CA details and guided
  agent installation show authoritative SHA-256 and display-only SHA-1 for Windows certificate dialog
  comparison. Root CA details expose an exact 64-hex SHA-256 automation value; pending CAs show no
  empty fingerprints. Windows helpers no longer embed an expected hash: they compute both values and
  import only after a matching independent `-ExpectedSha256` or explicit interactive SHA-256
  confirmation. Strict argument validation, changed/mismatched certificate refusal, quiet-mode fail
  closed behavior and elevated-child reauthorization prevent accidental or self-confirmed imports.
- **Guided Linux agent setup and packages:** GoReleaser nFPM builds `.deb` and `.rpm` for Linux
  amd64/arm64 with a `noreplace` conffile, example systemd files and no maintainer scripts or
  autostart. The shared `myownpki-agent setup` verifies the independent root SHA-256, securely reads
  optional join-token files, writes configuration/units atomically, preserves custom configuration,
  polls pending enrollments and enables or restarts only enrolled agents. Tarballs and packages use
  the same implementation. `install-agent.sh` is now a deprecated verified-download forwarding
  wrapper with default version 0.3.1.
- **Verified agent distribution and guided installation:** `install.sh` stages the exact release's
  `.deb`, `.rpm` and tarballs for both Linux architectures after checking every artifact against
  `checksums.txt`, and restores the previous complete distribution when a server update rolls back.
  Docker contains the same immutable files under `/opt/myownpki/agent-dist`; `agent.package_dir`
  selects the host/container directory. The agent listener allows anonymous `GET`/`HEAD` only for
  the manifest-listed artifacts and checksums, with exact-name, size, method, traversal and symlink
  protections; RPC authentication is unchanged. *Agents → Install agent* requires admin and fresh
  step-up and generates the full verified download/install/setup flow from independent UI root and
  package hashes. Its optional exact-host token is one-use, expires after 15 minutes, appears only
  in the one-time response and is consumed through a 0600 file, never argv, URLs or logs. Agent
  reports additively carry the installed format (pki.db migration 0015 and protobuf field 5), and
  strict SemVer update hints cover only older agents, including correct prerelease ordering and no
  suggested downgrade.
- **Configurable predecessor handling on renewal:** choose immediate, delayed (1–30 days) or no
  revocation, always with reason `superseded`. Tenant defaults are independent for agent deployments
  and other certificates, with agent-wide, per-deployment and one-operation overrides. Current
  migration defaults are owner-confirmed (agent: immediately after confirmed deployment; other
  certificates: after seven days), recorded in `docs/PHASE3.md` §8.4.
  Non-agent ACME renewals require the same account and exact normalized name set, with an optional
  admin-audited per-account override in UI and REST; shared accounts should use one per host or
  `never`. Agent actions
  start only at an accepted deployed report with exact proof: a served TLS fingerprint always wins,
  with the leaf fingerprint read back after the atomic write as the check-less fallback. A written
  fingerprint never replaces a missing TLS proof and legacy agents without either field cause no action. Exact
  account/order/name mapping and a real serial transition are required; failed, rolled-back,
  currently serving, foreign-account and ambiguous certificates are protected. Delayed agent plans
  start at server-recorded deployment time and repeated reports never duplicate or move plans.
- **Planned revocations:** certificate lists/details and agent deployments show `Revocation planned`,
  the certificate filter and dashboard cover plans due within seven days, and authorized users can
  plan, cancel or revoke now with step-up and audit. The scheduler executes due plans idempotently,
  including restart/unseal catch-up; CRL publication follows the committed transaction through the
  existing CRL jobs. Additive system.db migration 0013 and pki.db migration 0014 create no revocations
  or schedules on upgrade with unchanged serials. REST adds renewal policy fields, plan/cancel
  endpoints, planned timestamps and agent/deployment policy endpoints; legacy `revoke_previous`
  remains supported.
- **Web action continuation after step-up:** protected forms show a safe action summary and run once
  after the second factor, without asking for their inputs again. In-memory pending actions use
  256-bit IDs in POST fields only, are bound to the session, user and credentials epoch, expire after
  five minutes independently of the configured proof lifetime, and are consumed atomically before
  the existing authorized handler. Replay, concurrent clicks, restart and business failure cannot
  repeat the action; downloads, one-time secrets and multipart legacy imports keep their response
  behavior. A new confirmation replaces the session's previous one, global entry/archive budgets
  reject unbounded growth, and every store operation reclaims expired state. REST step-up responses
  and the OpenAPI contract are unchanged.
- **Tenant-configurable step-up lifetime:** tenant admins can choose 5, 10, 15, 30 or 60 minutes
  (default 5) in *Tenant settings* or through the additive `step_up_minutes` REST field. Changes
  are audited and apply only to new TOTP, recovery-code and passkey proofs; each session snapshots
  the lifetime, so existing proofs are unchanged. system.db migration 0012 adds the setting and
  per-session snapshots, with five minutes retained for existing sessions.

## [0.3.0] - 2026-10-25

The Linux agent: trusted enrollment, ACME issuance, atomic deployment with rollback, scheduled
renewals and operator-requested renewal through the web UI and REST API. Linux packages and a
hardened systemd installation complete the release.

### Added

- **ACME in the agent** with lego v4.35.2 as a library: a local account key registered by
  thumbprint over mTLS, host-generated certificate keys and http-01 in standalone/webroot mode.
  Its own HTTP client ignores environment proxy and lego trust settings. Linked accounts are
  restricted to the active agent's allowed names at order creation, finalization and issuance,
  including after an unseal; ordinary ACME clients keep their normal domain policy. Account key
  rotation preserves the binding. Existing accounts cannot be captured by a new thumbprint
  reservation; denials are audited. Re-enrollment with a new agent ID and the old ACME key stops
  with an operator-action message. pki.db migration 0012 enforces unique reservations and links.
- **nginx and file deployment profiles**: contained, atomic PEM writes with owner/group/mode,
  shared test/reload hooks and a local TLS fingerprint check. Failed activations roll back the
  whole reload group; first-install failures remove the new files. Mixed groups test the restored
  configuration and reload existing deployments back to their old leaf when safe. A durable journal recovers an
  interrupted pass before new work, and local status shows deployment results. A failed rollback
  reports both errors without a retry loop.

- **Agent listener** (`agent.base_url`, `agent.listen` default `:8444`, `agent.tls_issuer`,
  `agent.ca`): Connect-RPC over TLS 1.3. Its certificate comes from `agent.tls_issuer` like the admin
  and ACME listeners'. Client certificates are accepted from the agent CA only – an intermediate with
  the EKU limit clientAuth only, checked by `myownpki config check` and at the start. Without a
  certificate only the enrollment answers; everything else is checked per request (a revoked or
  disabled agent is cut off at its next call).
- **Enrollment with proof of control** (ADR-18): the agent makes its key and CSR on the host; the
  server fetches a check file bound to that key from `http://<host>/.well-known/acme-challenge/`
  (the agent's own port 80, or the webroot of the web server already there – written only through
  an `os.Root`, so a symlink can't redirect it) with the rules of the ACME validator. Modes per
  tenant (`auto`, `verified` – the default –, `manual`; *Tenant settings*, `agent_enrollment` in
  `PUT /api/v1/settings`, system.db migration 0011). Join tokens: single-use, expiring, for name
  patterns, stored hashed, shown once. The queue holds at most 100 enrollments without a valid
  token – one with a token is never refused – and junk expires after 24 hours.
- **Agent certificates**: 7 days, renewed by the agent at 2/3 with a new key (at most 6 renewals per
  agent and hour); an agent whose certificate expired enrolls again with the key of its last one.
  Revoking an agent puts its agent certificates on the CRL. pki.db migration 0011.
- **`myownpki-agent`** `enroll [--token-file FILE]`, `run`, `status`, `config check` with
  `/etc/myownpki-agent/agent.yaml`. It ignores `HTTPS_PROXY`/`HTTP_PROXY`; a proxy only when
  agent.yaml names one.
- **REST API** `/agents`, `/agent-enrollments`, `/agent-join-tokens` (permission `agent.manage`,
  admin with step-up), and the pages *Agents*, *Enrollment requests*, *Join tokens*.
- **Reports and renewal scheduling:** a heartbeat every five minutes with jitter and one combined
  report after each deployment pass; 2/3-lifetime scheduling with ARI support, persistent failure
  backoff and a silent-agent indicator after three missed reports.
- **Renew now and Withdraw:** operator/admin actions in the UI and REST API wake the agent through
  a bounded long-poll. Versioned acknowledgements prevent stale reports from clearing newer requests;
  CSRF, role checks and audit entries cover both actions. Agent pages show deployments, disallowed
  names and removed configurations. The certificate filter hides agent identity certificates by
  default, while deployment certificates stay visible.
- **Linux packaging:** `install-agent.sh`, a hardened root systemd unit with explicit writable-path
  drop-ins, and reproducible Linux amd64/arm64 agent archives. The script verifies the downloaded
  archive against the signed checksum file, never overwrites agent.yaml and updates without
  self-update magic. The `agent end-to-end` CI job runs real ACME/agent flows and nginx rollback,
  measures `systemd-analyze security`, and checks protobuf compatibility with `buf breaking`.
- New modules (owner 2026-10-24): `connectrpc.com/connect` v1.21.0, `google.golang.org/protobuf`
  v1.36.12; buf v1.73.0 as a pinned development tool (THIRD_PARTY.md).

### Changed

- Reports and desired-state watches have per-agent rate limits (60 and 120 per 10 minutes) to
  protect the SQLite writer and audit log from a compromised agent. The dashboard excludes agent
  identity certificates from ordinary 30-day expiry views and warns per active agent when its
  current certificate has less than 48 hours left.
- pki.db migration 0013 stores reported deployments and renewal requests. The release now has 18
  assets, including the two agent archives and `install-agent.sh`.

### Fixed

- Enrollment without a matching domain stores a clear failed check instead of panicking; the
  service and Connect-RPC both return the pending enrollment with that explanation.
- Handler panics are logged at error level with the RPC procedure and stack on the agent listener;
  HTTP server panics are also logged at error level on the admin and ACME listeners. Panic messages
  remain visible when the configured log level is info, while TLS handshake noise stays at debug.
- Domain creation and editing require a signing CA whose EKU limit allows serverAuth, in the form
  and in the service and REST API. New forms start with "Please select" instead of the first CA.
- `install-agent.sh` no longer claims that a token file was kept when enrollment ran without one.
- nginx test and reload hooks need `20-low-ports.conf` for listeners below 1024, including webroot
  mode. `install-agent.sh --low-ports` installs that capability explicitly.
- Failed hooks include sanitized, bounded stderr in the agent log and deployment `last_error`:
  valid UTF-8 at every boundary, the final diagnostic lines preserved, Unicode format characters
  removed and the complete error within the server limit, including rollback failures.
- Renewal requests appear as status badges with a separate Withdraw action, deployment tables wrap
  without horizontal overflow, and removable agent names have a per-row Remove action instead of a
  separate form.
- The Windows trust-page text requires comparing the root fingerprint with an independently obtained
  value from the admin UI or an administrator, not with the file that carries the root itself.
- Agent end-to-end CI runs `nginx -t` on port 443 under the real systemd unit, first proving the
  failure without the low-port drop-in and then success with it. The exported nginx rootfs has the
  package's temporary directories, and the negative-control log is written with `tee`.

## [0.2.2] - 2026-10-24

The server can issue the TLS certificates of its own listeners from one of its intermediates, so
ACME works without a reverse proxy; a daily backup timer for systemd installations; and a public
trust page that hands out the root certificates. Without `tls_issuer` the listeners keep their
bootstrap or configured certificate, and the proxy way for ACME stays the default. **Upgrade from 0.2.1 with install.sh:** run the 0.2.2 `install.sh` as
before – backup, new binary, migration (system.db 0010), health check; it now also installs the
daily backup timer and enables it once (`--no-backup-timer` keeps it off). An installed
`public-port-80.conf` stays. This `install.sh` installs 0.2.2 and later only; for an older release
use that release's `install.sh`. **Docker installations:** back up, pull the 0.2.2 image, start; the
backup timer is for systemd installations. The trust page appears at `/` of the public listener in
both cases – switch it off in *Tenant settings* if you don't want it.

### Added

- **The server issues its own TLS certificates** from a CA of the instance: `admin.tls_issuer` for
  the admin listener (the names of `admin.tls_names`), `acme.tls_issuer` for the ACME listener (the
  host of `acme.base_url`). Through the normal CA engine – preset *server*, ECDSA P-256, the CA's
  name constraints, an audit entry by *system* – for 90 days at most (never beyond the CA's maximum
  or end), renewed at 2/3 and at once after a revocation, a name change or a CA renewal. Issued
  only while unsealed; key and fullchain lie in `<data_dir>/tls/` (key 0600), so a sealed restart
  serves them. When one expires while sealed, the listener falls back to its bootstrap
  certificate with a warning in the log and on the dashboard; the switch needs no restart.
  A **root CA** as `tls_issuer` is refused with the fix ("CA root is a root – name the issuing
  intermediate …") at the start, on the dashboard and in `myownpki config check` (a warning when
  the CA database is readable); the listener then serves its bootstrap certificate.
  docs/OPERATIONS.md §2.4.
- **ACME without a reverse proxy:** with `acme.tls_issuer`, `acme.listen` speaks TLS itself (e.g.
  `":443"`); every client may connect, the peer is the client address for rate limits and audit,
  `acme.trusted_proxies` and `X-Forwarded-For` are ignored. The proxy way stays the default.
  docs/OPERATIONS.md 10.10.

- **Daily backups:** `myownpki-backup.service` and `.timer` (daily, random delay up to an hour,
  missed runs caught up), installed and enabled by install.sh (`--no-backup-timer`,
  `--backup-keep N`, default 14). Each run writes `/var/backups/myownpki/<UTC time>`, verifies it
  and prunes; the unit has the server's sandbox and no network. docs/OPERATIONS.md §6.1.
- **`myownpki backup scheduled DIR --keep N`** (the timer's run: backup, verify, prune) and
  **`myownpki backup prune DIR --keep N [--dry-run]`**. Prune deletes only complete scheduled
  backups (named like `20261025T003512Z`, a valid `manifest.json`, exactly the listed files) –
  never install.sh's update backups, a backup that failed its check (`…-unverified`) or anything
  else.
- **Backup warnings on the dashboard:** a `…-unverified` backup in `/var/backups/myownpki`, or a
  newest timer backup older than 48 hours (timer off or failing) – once the timer is installed or
  has written a backup. The server only reads the directory; its unit needs no new rights.
  docs/OPERATIONS.md §6.1.
- **Public trust page** at `/` of the public listener, without sign-in: every active CA (roots
  first) with name, common name, validity and SHA-256 fingerprint, DER and PEM downloads, guides
  for Windows, macOS, iPhone/iPad, Android, Linux and Firefox. No JavaScript, a strict CSP,
  cached. On by default; *Tenant settings* or `trust_page` in `PUT /api/v1/settings` switch it off
  (system.db migration 0010). docs/OPERATIONS.md chapter 11.
- **Windows helpers** per root on the trust page: a `.cmd` (Batch/PowerShell in one file, ASCII,
  CRLF) for *this computer* (asks for administrator rights) or *my user only*; it checks the
  SHA-256 of the embedded root before the import and stops if the file was changed; `/check`
  only checks, an unknown switch never imports.
- `/ca/<name>/<generation>.pem`: the CA certificate as PEM.
- **`install.sh --acme https://NAME/acme`** (with `--acme-ca`, default `issuing`) writes the ACME
  keys for its own TLS into a new config and installs the drop-in for port 443.

### Changed

- `myownpki healthcheck` accepts the bootstrap and the issued admin certificate (with
  `admin.tls_issuer`); `myownpki config check` shows `tls_issuer` and the ACME mode.
- The drop-in `public-port-80.conf` is now `low-ports.conf` – for every listener on a port below
  1024 (`--public-port-80`, `--acme`). An installed `public-port-80.conf` keeps working and stays;
  the archives still carry it.
- CI: the install job installs with `--acme`, unseals through the API and reads the ACME directory
  over TLS with the root as trust anchor; `systemd-analyze security` is measured with the drop-in
  and must stay below 2.0. The conformance job runs lego and certbot directly against the own TLS
  listener.

## [0.2.1] - 2026-10-24

Install and update MyOwnPKI as a hardened systemd service with one command: `install.sh`
(docs/OPERATIONS.md §2.1) – no Docker needed. The server itself is unchanged. **Docker
installations:** nothing changes – back up, pull the 0.2.1 image, start, as before. Upgrade from
0.2.0 without Docker: as before (backup, replace the binary, start); or run `install.sh` once – it
keeps an existing `/etc/myownpki/config.yaml` and `/var/lib/myownpki`.

### Added

- **`install.sh`** – installs or updates MyOwnPKI as a systemd service with one command, on Linux
  with systemd (amd64, arm64); a release asset of its own (listed in the signed `checksums.txt`)
  and in every archive. It checks the archive's SHA-256 and, when cosign is installed, the Sigstore
  signature before it installs anything; creates the user `myownpki`, `/var/lib/myownpki` and – only
  if there is none – `/etc/myownpki/config.yaml` (admin listener on the own /24s, the names from
  `hostname -f` and the own addresses, or `--tls-names`, `--admin-listen`, `--allowed-networks`);
  enables the service without starting it and prints the next commands. An update makes a backup
  and `backup verify` first and puts the old binary back – and ends with an error – unless the
  service comes back healthy and runs the new version.
  `--archive` installs from a local archive (machines without internet). docs/OPERATIONS.md §2.1.
- **systemd unit** `deploy/systemd/myownpki.service` with a strict sandbox (no capabilities,
  read-only system except the data directory, private users and devices, a system call filter;
  `systemd-analyze security` rates it 1.2, "OK"), and the drop-in `public-port-80.conf` for the public
  listener on port 80 without a reverse proxy (`--public-port-80`).

### Changed

- The release has 13 assets (`install.sh` added); the archives also hold the unit, the drop-in and
  `install.sh`.

## [0.2.0] - 2026-10-23

The ACME server (phase 2 of docs/PLAN.md). Upgrade: back up, replace the binary, start – the
migrations run at start; ACME stays off until `acme.base_url` is set, and it runs only behind a
reverse proxy that ends TLS. Read chapter 10 of docs/OPERATIONS.md before switching it on.

### Added

- **ACME server** (RFC 8555) for certbot, acme.sh, lego, Traefik, Caddy and other clients: accounts
  (with key change and deactivation), orders, http-01 and dns-01 challenges, finalize, certificate
  download with the chain, revocation (by the account, by an account that holds the names, or with
  the certificate's own key). Issuance goes through the same policy engine as the UI.
- **Domains** (*ACME → Domains*, `/api/v1/domains`): which names ACME issues for, the signing CA,
  the challenges, wildcards (dns-01 only), the preset and validity (default 90 days), which
  addresses http-01 may reach, and IP ranges for IP certificates.
- **Approvals**: per domain *open*, *approved accounts* (default) or *new names*; queues for
  accounts and names in the UI, EAB keys (external account binding) shown once, dashboard notices
  for what waits.
- **ARI** (RFC 9773): clients ask when to renew – the window opens at 2/3 of the lifetime; a revoked
  certificate is renewed at once; renewals name the certificate they replace.
- **Rate limits** as tenant settings: new orders per account, failed validations per name, new
  accounts per client address (IPv6 per /64); `429` with the real `Retry-After`.
- A sealed server keeps taking orders: certificates of finalized orders are issued at the unseal.
- Configuration `acme.base_url`, `acme.listen` (default `127.0.0.1:8081`), `acme.trusted_proxies`,
  `acme.resolver`; examples for Caddy, nginx and Traefik in docs/OPERATIONS.md.
- *ACME → Orders* lists the newest orders with their result.
- Tested in CI against real clients: lego, certbot (http-01, dns-01 with certbot-dns-rfc2136 against
  BIND, revocation) and acme.sh; Pebble as a control.

### Changed

- `PUT /api/v1/settings` takes an optional `acme_limits`; left out, the stored limits stay
  (clients of 0.1 keep working). The answer always contains it.
- Table cells in the UI can wrap long values (error details, contacts).

### Security

- ACME runs only behind a reverse proxy that ends TLS; the plain-HTTP listener answers only the
  addresses in `acme.trusted_proxies`, and no URL is built from `X-Forwarded-Host`/`-Proto`.
- JWS and JWK in own code with the standard library only: a fixed list of algorithms (ES256,
  ES384, RS256 with at least 2048 bits, EdDSA), strict parsing (duplicate members, `b64:false`,
  unknown `crit` and `none`/HS* refused); fuzz-tested.
- The validator resolves once and connects to exactly the checked address (no DNS rebinding),
  never to loopback or link-local, only to ports 80/443, follows redirects only within the order,
  and never tells the client what a target answered – it can't be used to read the inside network.
- EAB keys are stored encrypted with the key ring and overwritten when used.
- **Unseal refuses weak key derivation parameters:** a key ring whose stored Argon2id parameters
  are below t=4, 256 MiB, p=4 is refused (audited as `denied`, reason `weak_kdf`). Every release so
  far stored exactly these values, so existing installations are not affected; weaker values come
  only from test builds. Way out: unseal with the recovery key, or `myownpki passphrase reset`, and
  set a new passphrase – it is stored with the production values.

### Fixed

- Release notes on GitHub: the release draft had an empty text, because GoReleaser's changelog
  step – the one that reads the notes from CHANGELOG.md – was disabled. (The v0.1.0 notes were
  added by hand.)

## [0.1.0] - 2026-10-22

The first release: MyOwnPKI replaces the `pki.sh` Bash suite in the browser (phase 1 of
[docs/PLAN.md](https://github.com/Der-Felix/MyOwnPKI/blob/v0.1.0/docs/PLAN.md)). Start with [docs/OPERATIONS.md](https://github.com/Der-Felix/MyOwnPKI/blob/v0.1.0/docs/OPERATIONS.md).

### Added

- **CA engine**: root and intermediate CAs (online, or an offline root with the signing bundle for
  OpenSSL), CA renewal with a new key, retirement and revocation; leaf certificates from a CSR or
  with a server-generated key; built-in presets (server, client, server-client, S/MIME, code
  signing, timestamping, OCSP, custom) ported from `pki.sh`; name constraints, CA limits and the
  policy checks of PLAN §6 – extensions always come from the preset, never from the CSR.
- **Revocation and CRLs**: revocation with RFC 5280 reasons (keyCompromise blocks the key for later
  requests), CRLs signed at once and renewed in the background, the offline root's CRL uploaded;
  CRLs and CA certificates on the public listener, including the URLs of imported `pki.sh` CAs.
- **Key protection**: every CA and certificate key encrypted (AES-256-GCM under a root key wrapped
  with an Argon2id key from the unseal passphrase, plus a recovery key); the server starts sealed;
  seal and unseal audited; `myownpki passphrase change` and `passphrase reset` (with the recovery
  key).
- **Audit log**: hash-chained instance and tenant logs with signed checkpoints;
  `myownpki audit verify` and the audit pages.
- **Sign-in**: password (Argon2id, common-password check) plus TOTP and recovery codes, passkeys as
  second factor when `auth.passkey_origin` is set (through the API only, see below), step-up for dangerous actions, lockout and
  throttling, roles per tenant (viewer, operator, admin) and instance admins; API tokens.
- **REST API** `/api/v1` (OpenAPI 3.1 in `api/openapi.yaml`, 58 operations, RFC 9457 problems).
- **Web UI**: dashboard, certificates (issue wizard, detail, revoke, renew, download, export as
  PKCS#12 or PEM with "delete the key afterwards"), CAs including the offline signing flow, presets,
  users and roles, tenant settings, audit log, legacy import, own account; light and dark theme;
  no inline styles or scripts (strict CSP).
- **Legacy import** of a `pki.sh` directory (`myownpki import legacy`, or an archive upload in the
  UI): serial numbers, revocations (time and reason) and CRL numbers stay identical; dry run first.
- **Backup and restore**: `myownpki backup` while the server runs, `backup verify`, `restore` with
  hash, integrity, audit-chain and name-index checks.
- **Operations**: `myownpki init` (interactive, `--stdin` for automation, `--demo`),
  `myownpki healthcheck`, `config check`, `db status` / `db migrate`, `user unlock` / `reset-2fa`;
  a self-signed bootstrap certificate for the admin listener with its fingerprint in the log.
- **Release**: archives for linux/amd64, linux/arm64, darwin/arm64, windows/amd64 and
  freebsd/amd64 (pure Go, reproducible), SPDX SBOMs, a checksum file signed keyless with cosign,
  and the container image `ghcr.io/der-felix/myownpki` (distroless, non-root, signed);
  `deploy/docker-compose.yml` for a single server.

### Security

- Built with Go 1.27.3 (fixes GO-2026-6809 / CVE-2026-111943: `crypto/x509` now refuses known
  compromised intermediate certificates when verifying a chain).

### Known limitations

- No ACME server yet (v0.2), no agent and no monitoring yet (v0.3) – see the release plan in
  [docs/PLAN.md](https://github.com/Der-Felix/MyOwnPKI/blob/v0.1.0/docs/PLAN.md) §10.1.
- **Passkeys work only through the REST API in v0.1** – registering one, and using it to sign in
  or to confirm an action (`/api/v1/auth/webauthn/*`, `/api/v1/users/me/webauthn`). The web UI
  has no passkey button yet: it needs a small browser script that is not approved yet (ADR-04).
  The UI lists a user's passkeys and removes them; sign-in in the browser uses the authenticator
  app (TOTP).
- One tenant (`default`); the tenant UI comes later.

[Unreleased]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Der-Felix/MyOwnPKI/releases/tag/v0.1.0
