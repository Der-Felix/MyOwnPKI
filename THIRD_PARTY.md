# Third-party data

Data from other projects that is copied into this repository and built into the binaries,
and the modules and release tools approved one by one since phase 1 (with the modules they
bring). All Go modules are in `go.mod`; only permissive licenses are accepted (ADR-14).

## Go modules approved for phase 1 (night run 2026-10-21)

| Module | Version (release date) | License | For | Brings |
|---|---|---|---|---|
| `github.com/go-webauthn/webauthn` | v0.18.2 (2026-09-19) | BSD-3-Clause | passkeys (step 17) | `github.com/go-webauthn/x` v0.3.1 (BSD-3), `github.com/fxamacker/cbor/v2` v2.9.4 (MIT), `github.com/x448/float16` v0.8.4 (MIT), `github.com/golang-jwt/jwt/v5` v5.3.1 (MIT, metadata service), `github.com/google/go-tpm` v0.9.8 (Apache-2.0, TPM attestation), `github.com/go-viper/mapstructure/v2` v2.5.0 (MIT), `github.com/tinylib/msgp` v1.6.4 (MIT), `github.com/philhofer/fwd` v1.2.0 (MIT); `github.com/google/uuid` was already in the graph. Test-only modules of webauthn (testify, go.uber.org/mock) are not built in |

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
