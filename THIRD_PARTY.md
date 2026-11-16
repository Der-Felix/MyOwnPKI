# Third-party data

Data from other projects that is copied into this repository and built into the binaries,
and the modules and release tools approved one by one since phase 1 (with the modules they
bring). All Go modules are in `go.mod`; only permissive licenses are accepted (ADR-14).

## Go modules approved for phase 1 (night run 2026-10-21)

| Module | Version (release date) | License | For | Brings |
|---|---|---|---|---|
| `github.com/go-webauthn/webauthn` | v0.18.2 (2026-09-19) | BSD-3-Clause | passkeys (step 17) | `github.com/go-webauthn/x` v0.3.1 (BSD-3), `github.com/fxamacker/cbor/v2` v2.9.4 (MIT), `github.com/x448/float16` v0.8.4 (MIT), `github.com/golang-jwt/jwt/v5` v5.3.1 (MIT, metadata service), `github.com/google/go-tpm` v0.9.8 (Apache-2.0, TPM attestation), `github.com/go-viper/mapstructure/v2` v2.5.0 (MIT), `github.com/tinylib/msgp` v1.6.4 (MIT), `github.com/philhofer/fwd` v1.2.0 (MIT); `github.com/google/uuid` was already in the graph. Test-only modules of webauthn (testify, go.uber.org/mock) are not built in |

## Go modules and tools approved for v0.3.0 – the agent (owner 2026-10-24)

Two-week rule: a version older than 2026-10-10 (docs/PHASE3.md §4).

| Module / tool | Version (release date) | License | For | Brings |
|---|---|---|---|---|
| `connectrpc.com/connect` | v1.21.1 (2026-10-14) | Apache-2.0 | the agent protocol (Connect-RPC, ADR-10) in server and agent; its generator `protoc-gen-connect-go` as `go tool` | `github.com/google/go-cmp` v0.7.0 (BSD-3) – only in connect's own tests, not built in. Approved as v1.21.0; raised to v1.21.1 on 2026-11-12 (Dependabot, public for more than two weeks) |
| `google.golang.org/protobuf` | v1.36.12 (2026-08-10) | BSD-3-Clause | protobuf messages of the agent protocol; its generator `protoc-gen-go` as `go tool` | nothing |
| [buf](https://github.com/bufbuild/buf) CLI | v1.73.0 (2026-09-11) | Apache-2.0 | `task generate`: lint and code generation of `proto/` (local plugins only, no registry) – a development tool, never in `go.mod` or a binary | fetched by `internal/tools/buf` into `.tools/` and checked against the SHA-256 of the release's `sha256.txt` (pins in that file) |
| `github.com/go-acme/lego/v4` | v4.35.2 (2026-04-24) | MIT | ACME library in the agent (block C); direct imports `lego`, `certificate`, `registration` (v0.3.0) and, since v0.3.7, `challenge`, `challenge/dns01`, `log` and `providers/dns/cloudflare` (see the v0.3.7 section below); the existing contained responder implements the HTTP provider interface | `github.com/go-jose/go-jose/v4` v4.1.4 (2026-03-31, Apache-2.0), `github.com/miekg/dns` v1.1.72 (2026-01-22, BSD-3), `github.com/cenkalti/backoff/v5` v5.0.3 (2025-07-23, MIT). Existing higher `golang.org/x/*` versions stay unchanged. Only the Cloudflare provider of lego is built in since v0.3.7 (its package imports lego itself and `miekg/dns`), no provider SDK |
| `nginx:1.29.2-trixie` | 2025-10-07 | BSD-2-Clause | nginx in the Linux `agent end-to-end` CI job only; not shipped | multi-architecture index `sha256:029d4461bd98f124e531380505ceea2072418fdf28752aa73b7b273ba3048903` |

## dns-01 in the agent (v0.3.7)

No module is added and no version changes (`go list -m all` is the same; `go.sum` is unchanged). Two things
change (docs/PHASE3.md §13.3):

| Module / package | Version (release date) | License | For | Change |
|---|---|---|---|---|
| `github.com/go-acme/lego/v4` packages `challenge`, `challenge/dns01`, `log`, `providers/dns/cloudflare` | v4.35.2 (2026-04-24) | MIT | the dns-01 solver and the Cloudflare provider of the agent | more packages of a module that is already pinned; they bring no module (the linux/amd64 agent (`-s -w`) grows from 11,886,752 to 12,513,440 bytes with the two providers, the guard and the own RFC 2136 code) |
| `github.com/miekg/dns` | v1.1.72 (2026-01-22) | BSD-3-Clause | the agent's own RFC 2136 provider (UPDATE over TCP with TSIG) and the in-process test DNS server `internal/testutil/dnsserver` | `// indirect` becomes a direct requirement in `go.mod` |
| lego `providers/dns/rfc2136` | – | – | **not used**: it brings `bodgit/tsig` and a Kerberos stack (12 modules in the Linux build) for GSS-TSIG, which this release does not offer | – |

The server binaries carry neither lego nor `miekg/dns`: `cmd/myownpki/deps_test.go` and the depguard rule
`agent-only-dns` check it.

## CI-only tool for the Salt formula (v0.3.6)

Used only by the `salt formula` job of `.github/workflows/ci.yml` (`scripts/ci/salt-test.sh`); it is not
built into a binary, not shipped and not in `go.mod`. The download is checked against the pinned SHA-256.
Two-week rule: the newest release of the LTS line that is older than 2026-10-29.

| Tool | Version (release date) | License | For | Pin |
|---|---|---|---|---|
| [Salt](https://github.com/saltstack/salt) onedir | 3008.5 (2026-10-26), the 3008 LTS line | Apache-2.0 (`salt-3008.5.dist-info` in the tarball; the onedir also bundles CPython and Python libraries under their own licenses) | `salt-call --local` renders and applies (`test=True`) the test pillars of `deploy/salt/myownpki` | `salt-3008.5-onedir-linux-x86_64.tar.xz` from `packages.broadcom.com/artifactory/saltproject-generic/onedir/3008.5/`, SHA-256 `3bbc89d18ff1cef340bfe662d0e973db8387c9affbb0633df1645725bb63786e` (the digest of the file at the repository, of the asset of the same name on the GitHub release `v3008.5`, and the file matched the published `.SHA512` asset) |

## Container images of the demo (v0.3.11)

Used only by `deploy/demo/` (docs/PHASE3.md §17, steps 75 and 76) and its CI check
`scripts/ci/demo-check.sh`; not shipped in a release and not in `go.mod`. Both are pinned by the
digest of the multi-platform index (`linux/amd64` and `linux/arm64` are in both), read from the
registry API on 2026-11-16 (`registry-1.docker.io`, header `Docker-Content-Digest`, equal to the
digest of the Docker Hub tag). Two-week rule: the newest tag whose image was pushed more than 14
days before (on or before 2026-11-02); the newer `certbot` v5.10.0 (2026-11-10) and `nginx`
1.30.6-trixie (2026-11-05) were too young.

| Image | Tag pushed | License | For | Index digest |
|---|---|---|---|---|
| `certbot/certbot:v5.9.0` | 2026-10-29 | Apache-2.0 | certbot (http-01, `--standalone`) in the demo's first act | `sha256:bc93cb710b413e6b456d622f9b0133b3e109c0a78c2ed9976af43d209b0a1805` |
| `nginx:1.31.7-trixie` | 2026-10-21 | BSD-2-Clause | nginx of the demo's second act (the `web` build, `deploy/demo/web/Dockerfile`) | `sha256:8632b3314d74c61f0e27f59055bab13f7793b988c94c090154d867bc29e0f39b` |

The demo's second image (`web`) is built on the server image of the same release and adds only
the agent tarball of that release, checked against the `checksums.txt` that is in the image.

## Distribution packages of the Apache and HAProxy tests (v0.3.11)

Used only by the CI job `agent end-to-end (Apache, HAProxy)` (docs/PHASE3.md §17, step 69) and by
`scripts/ci/agent-e2e-apache.sh` and `agent-e2e-haproxy.sh`; not shipped, not in `go.mod`, not an
image. The job installs the packages of the runner's own distribution (`ubuntu-24.04`) with
`apt-get`, so the version is the one that distribution carries on the day of the run, which is
what an admin on that release gets; the tests print `apache2 -v` and `haproxy -v` into the log.
They are not pinned by digest: the tests start the service with a private configuration and
check behavior, not a version.

| Package | License | For |
|---|---|---|
| `apache2` (Debian and Ubuntu) | Apache-2.0 | the real Apache of the `apache2` recipe test (`mod_ssl`, `apache2ctl`) |
| `haproxy` (Debian and Ubuntu) | GPL-2.0-or-later (headers LGPL-2.1) | the real HAProxy of the `haproxy` recipe test (`haproxy -c`, master-worker reload) |

## Release tools and the container base image (approved for v0.1, night run 2026-10-21)

Used only by `.github/workflows/release.yml` (and locally by `task release:check` /
`task release:snapshot`); none of them is built into the binaries. Downloads are checked against
the pinned SHA-256; each project's checksum file was verified against its Sigstore signature when
the pins were chosen. Two-week rule: newest release older than 2026-10-07.

| Tool / image | Version (release date) | License | For | Pin |
|---|---|---|---|---|
| [GoReleaser](https://github.com/goreleaser/goreleaser) | v2.18.2 (2026-09-17) | MIT | builds, archives, checksums, image, draft release | `goreleaser_Linux_x86_64.tar.gz` SHA-256 `0a96edc9d9bc594e4a41cc4d59467c182062910ab24d9d1f6dd7b667d32606d3` |
| [cosign](https://github.com/sigstore/cosign) | v3.1.3 (2026-08-06) | Apache-2.0 | keyless signatures of `checksums.txt` and the image | `cosign-linux-amd64` SHA-256 `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71` |
| [syft](https://github.com/anchore/syft) | v1.54.1 (2026-10-06) | Apache-2.0 | SPDX SBOM per archive | `syft_1.54.1_linux_amd64.tar.gz` SHA-256 `c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47` |
| [distroless](https://github.com/GoogleContainerTools/distroless) `gcr.io/distroless/static-debian13:nonroot` (Debian 13 "trixie"; the index carries the tag `nonroot-48b5c0455fb00d6ea7223f1fc6862c46da736556`) | index uploaded 2026-10-31 (22:37 UTC) | Apache-2.0 (the few Debian packages inside, such as CA certificates and time zone data, keep their own licenses) | base of the container image | `sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329` |

The base image moved from `static-debian12` to `static-debian13` in v0.3.11 (2026-11-16). Two-week
rule for the image: the pin is the newest `nonroot` index uploaded more than 14 days ago, not the
newest one (on 2026-11-16 the current `nonroot` index, uploaded 2026-11-12, was too young). It
was read without Docker from the registry API: `…/tags/list` for the upload times (`timeUploadedMs`),
`…/manifests/nonroot-<commit>` for the digest (header `Docker-Content-Digest`, equal to the SHA-256
of the index body), and the index plus the per-platform manifests and config blobs for
`linux/amd64` and `linux/arm64` (`User` `65532`, `WorkingDir` `/home/nonroot`, `SSL_CERT_FILE`
`/etc/ssl/certs/ca-certificates.crt`; the layers hold that file, the time zone data, `/etc/passwd`
and `/home/nonroot` owned by 65532 with mode `0700`).

New digest of the base image (update deliberately, then wait two weeks): read the upload times and
tags, pick the newest index older than 14 days that carries a `nonroot-<commit>` tag, then read its
digest.

```bash
curl -s https://gcr.io/v2/distroless/static-debian13/tags/list
```

```bash
curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" https://gcr.io/v2/distroless/static-debian13/manifests/nonroot-<commit>
```

## Common passwords (`internal/auth/common-passwords.txt`)

New passwords are checked against a list of common passwords, case-insensitively
(NIST SP 800-63B, PHASE1 step 10).

- **Data:** the top one million of the "ten million passwords" that Mark Burnett published in
  February 2015. His post "Today I Am Releasing Ten Million Passwords" says of the data set
  "that I am releasing to the public domain"
  ([archived copy, 2017](https://web.archive.org/web/20171202083348/https://xato.net/today-i-am-releasing-ten-million-passwords-b6278bbe7495)).
  The first archived version of the post (10 Feb 2015) does not contain that sentence yet; the
  sentence is in the later version of the same post. Only the passwords are used here, no
  usernames.
- **Taken from:** [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler,
  `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt`, MIT License
  (Copyright (c) 2018 Daniel Miessler), pinned to commit
  `f1196104c5594a19d78b486c52c0794b9d947993`, SHA-256
  `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51`.
- **Changed:** only entries with 12 to 256 characters are kept (shorter ones are refused by the
  length rule anyway), lower-cased, deduplicated and sorted – 46,145 entries.
- **Rebuild** (the tool checks the SHA-256 first):

  ```bash
  curl -o xato.txt https://raw.githubusercontent.com/danielmiessler/SecLists/f1196104c5594a19d78b486c52c0794b9d947993/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt
  go run ./internal/tools/commonpasswords -in xato.txt -out internal/auth/common-passwords.txt
  ```

The MIT License of SecLists:

```text
MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
