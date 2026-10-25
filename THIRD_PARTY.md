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
| `connectrpc.com/connect` | v1.21.0 (2026-09-08) | Apache-2.0 | the agent protocol (Connect-RPC, ADR-10) in server and agent; its generator `protoc-gen-connect-go` as `go tool` | `github.com/google/go-cmp` v0.7.0 (BSD-3) – only in connect's own tests, not built in. v1.21.1 (2026-10-14) was too new |
| `google.golang.org/protobuf` | v1.36.12 (2026-08-10) | BSD-3-Clause | protobuf messages of the agent protocol; its generator `protoc-gen-go` as `go tool` | nothing |
| [buf](https://github.com/bufbuild/buf) CLI | v1.73.0 (2026-09-11) | Apache-2.0 | `task generate`: lint and code generation of `proto/` (local plugins only, no registry) – a development tool, never in `go.mod` or a binary | fetched by `internal/tools/buf` into `.tools/` and checked against the SHA-256 of the release's `sha256.txt` (pins in that file) |
| `github.com/go-acme/lego/v4` | v4.35.2 (2026-04-24) | MIT | ACME library in the agent (block C); direct imports only `lego`, `certificate`, `registration`; the existing contained responder implements the HTTP provider interface | `github.com/go-jose/go-jose/v4` v4.1.4 (2026-03-31, Apache-2.0), `github.com/miekg/dns` v1.1.72 (2026-01-22, BSD-3), `github.com/cenkalti/backoff/v5` v5.0.3 (2025-07-23, MIT). No DNS provider or provider SDK is built in; existing higher `golang.org/x/*` versions stay unchanged |
| `nginx:1.29.2-trixie` | 2025-10-07 | BSD-2-Clause | nginx in the Linux `agent end-to-end` CI job only; not shipped | multi-architecture index `sha256:029d4461bd98f124e531380505ceea2072418fdf28752aa73b7b273ba3048903` |

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
| [distroless](https://github.com/GoogleContainerTools/distroless) `gcr.io/distroless/static-debian12:nonroot` | index uploaded 2026-08-21 | Apache-2.0 (the few Debian packages inside, such as CA certificates and time zone data, keep their own licenses) | base of the container image | `sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` |

New digest of the base image (update deliberately, then wait two weeks):

```bash
curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" https://gcr.io/v2/distroless/static-debian12/manifests/nonroot
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
