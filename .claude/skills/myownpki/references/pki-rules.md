# PKI correctness rules

Rules for everything that creates, parses or validates certificates. When in doubt, RFC 5280
(X.509 profile), RFC 8555 (ACME) and RFC 6960 (OCSP) win over convenience.

## Contents
1. Presets (ported from legacy)
2. Leaf certificate rules
3. CA rules
4. Keys and algorithms
5. Validity
6. CSR handling
7. CRL and OCSP
8. ACME specifics
9. Legacy importer

---

## 1. Presets (ported from `legacy/lib/presets.sh`)

Presets become `presets/*.yaml`. Port them faithfully first, improve later.

| Preset | KU (RSA) | KU (EdDSA/ECDSA) | EKU | Days | SAN required |
|---|---|---|---|---|---|
| server | digitalSignature, keyEncipherment | digitalSignature | serverAuth | 397 | dns or ip |
| wildcard | same as server | same | serverAuth | 397 | dns or ip |
| client | digitalSignature, keyEncipherment | digitalSignature | clientAuth | 730 | – |
| server-client | digitalSignature, keyEncipherment | digitalSignature | serverAuth, clientAuth | 397 | dns or ip |
| user | digitalSignature, nonRepudiation, keyEncipherment | digitalSignature, nonRepudiation | clientAuth, emailProtection | 730 | email |
| vpn-server | digitalSignature, keyEncipherment | digitalSignature | serverAuth, ipsecIKE (1.3.6.1.5.5.7.3.17), 1.3.6.1.5.5.8.2.2 | 730 | dns or ip |
| vpn-client | digitalSignature, keyEncipherment | digitalSignature | clientAuth, ipsecIKE | 730 | – |
| smime | digitalSignature, nonRepudiation, keyEncipherment | digitalSignature, nonRepudiation | emailProtection | 730 | email |
| codesign | digitalSignature | digitalSignature | codeSigning | 1095 | – |
| ocsp | digitalSignature | digitalSignature | OCSPSigning (+ id-pkix-ocsp-nocheck) | 365 | – |
| timestamp | digitalSignature, nonRepudiation | digitalSignature, nonRepudiation | timeStamping (**critical**) | 1825 | – |
| custom | user-defined | user-defined | user-defined | 365 | – |

The legacy "KU (Ed25519)" column applies to every non-RSA key: `keyEncipherment` only makes
sense for RSA key transport. For ECDSA leaves used in TLS, `digitalSignature` is correct
(add `keyAgreement` only for a documented static-ECDH use case).

## 2. Leaf certificate rules

- `basicConstraints = critical, CA:FALSE`
- `keyUsage` critical, from the preset (see the key type note above)
- `extendedKeyUsage` from the preset; non-critical unless the preset says otherwise (timestamp)
- `subjectKeyIdentifier` (hash) and `authorityKeyIdentifier` (keyid of the issuer)
- **SAN is mandatory for TLS.** Clients ignore the CN for hostname matching. The CN is a display name.
- AIA (`caIssuers`, `OCSP`) and CRL Distribution Point URLs come from the CA's **public base URL**.
  They are baked into every certificate and can never be changed afterwards – validate that a CA
  has a stable public base URL before it issues its first certificate.
  Layout (owner decision, step 7): `<base>/ca/<ca-name>/<generation>.crt` and
  `<base>/crl/<ca-name>/<generation>.crl` – the generation is the CA key (`ca_generations`), so a
  renewed CA doesn't break older chains and CRLs. CA names never change. No OCSP URL until phase 4.
- Subject DN: CN + optional O/OU/L/ST/C. CN at most 64 characters (RFC 5280 ub-common-name): a
  derived CN that is longer is left out, never cut; an explicit one is refused. Control characters
  and invisible formatting characters (bidi overrides) are refused in every DN field.
- DNS names: LDH only, lower case, punycode (`xn--`) for international names – Unicode is refused
  (look-alike names). Wildcards only in presets with `wildcard: true`.
- Wildcards: only one label (`*.example.com`), never `*.*.x` or `*.com`; `*.example.com` does not
  cover `example.com`, so add both (legacy behaviour).
- IP SANs: IPv4 and IPv6 in binary form, never as DNS SANs.

## 3. CA rules

- Root: self-signed, `basicConstraints = critical, CA:TRUE` (no pathlen or a deliberate one),
  `keyUsage = critical, keyCertSign, cRLSign` (+ digitalSignature if it signs OCSP directly).
- Intermediate: `basicConstraints = critical, CA:TRUE, pathlen:0` by default,
  `keyUsage = critical, digitalSignature, keyCertSign, cRLSign`.
- Optional EKU on an intermediate acts as a limit (legacy `EKU_LIMIT`).
- **Name constraints** (legacy `PERMIT_DNS`, `PERMIT_IP`): critical by default (RFC 5280), with a
  per-CA compatibility switch for clients that mishandle critical NC. Support IPv6 CIDRs (legacy only did IPv4).
- Enforce name constraints **before signing** as well – don't rely on clients to reject.
- A CA never issues beyond its own `notAfter`.
- Root key modes: offline / online-encrypted / HSM (ADR-09). In offline mode the server only
  ever holds the root **certificate**.
- **Offline signing** (step 8):
  - The server writes an OpenSSL extension file. The offline root signs with exactly that file and
    never copies the CSR's extensions (`copy_extensions none`); the digest matches the root key.
  - The uploaded certificate is compared with the order, and every difference is refused: key,
    subject, CA:TRUE, KU, pathlen, NC, EKU, AKI = root SKI, serial unused, validity inside the
    root, SHA-2/Ed25519 signature.
- **CA keys:**
  - New CAs: P-384 (default), P-256, RSA 3072/4096.
  - Imported CAs: RSA 2048 and P-521 only with a warning.
  - Ed25519 is never a CA.
- **Renewal** = new key = next generation. Never overwrite a signed generation; issuer name + serial
  stay unique across leaves and CA certificates of one issuer.
- **The offline root's CRL** can only be signed offline. It is uploaded and checked: right
  signer, number strictly increasing, nextUpdate in the future (step 9).

## 4. Keys and algorithms

| Type | Use | Notes |
|---|---|---|
| ECDSA P-256 | default for leaves and ACME | what certbot/Traefik/Caddy generate by default |
| ECDSA P-384 | CAs, high-assurance leaves | |
| RSA 2048 | compatibility only | flag in compliance view (BSI TR-02102 recommends ≥ 3000 bit) |
| RSA 3072/4096 | legacy default leaf/CA | |
| Ed25519 | SSH, internal mTLS, signing | **browsers do not accept Ed25519 TLS server certificates** – warn in the UI |

- Randomness only from `crypto/rand`.
- Signature algorithm follows the issuer key (SHA-256 for RSA/P-256, SHA-384 for P-384, SHA-512 for P-521, pure Ed25519).
- Key policy for requests (step 7): ECDSA P-256/P-384/P-521, RSA 2048–8192 with exponent 65537 only,
  Ed25519. Warn (don't refuse) for Ed25519 and P-521 on TLS server presets – browsers (Chrome) reject them.
- Minimum key policy is configurable per tenant.

## 5. Validity

- `notBefore` = now minus a small backdate (e.g. 5 minutes) for clock skew.
- Public CAs (CA/Browser Forum ballot SC-081) are capped at 200 days from 2026-03-15, 100 days
  from 2027-03-15 and 47 days from 2029-03-15. This does not bind a private CA, but our defaults
  should move in that direction because automation makes short lifetimes cheap.
- Renewal window default: at 2/3 of lifetime, with random jitter; expose the window via ARI.

## 6. CSR handling

- Verify the CSR signature (`CheckSignature`) before anything else.
- Treat every field as attacker input: length limits, character checks, escape on output.
- **Never copy extensions from the CSR.** Take the requested SANs, check them against the domain
  policy and name constraints, then build extensions from the preset (legacy: `copy_extensions = none`).
- Reject CSRs whose key violates the key policy.
- Legacy option `--no-csr-san` (ignore CSR SANs, use only explicitly given ones) stays available.

## 7. CRL and OCSP

- CRL number strictly increasing per CA; include AKI; `nextUpdate` = now + configured CRL days.
- Regenerate CRLs on every revocation **and** well before `nextUpdate` (scheduler).
- OCSP responder certificate: preset `ocsp` (EKU OCSPSigning, `id-pkix-ocsp-nocheck`), issued by the same CA.
- Answer `unknown` for serials the CA never issued, `revoked` with reason and time, `good` otherwise.
- Serve OCSP from the database; pre-sign and cache responses, rebuild on revocation (no restart –
  this fixes the legacy limitation in `lib/ocsp.sh`).
- Revocation reasons per RFC 5280 (keyCompromise, superseded, cessationOfOperation, …).
- **Revocation** (step 9):
  - Final only: no certificateHold.
  - "unspecified" is written without a reasonCode extension.
  - keyCompromise/cACompromise put the key's SPKI hash into `blocked_keys`; the engine refuses that
    key in every later request.
- **CRL per CA generation:**
  - Signed by the generation's key; **the first CRL comes with the generation** (same transaction) –
    a CDP that answers 404 makes strict clients refuse every certificate below.
  - thisUpdate backdated 5 minutes.
  - Renew after ⅓ of the lifetime; warn from ½.
  - Keep an entry until notAfter + crl_days (RFC 5280 §3.3).
  - A generation signs CRLs until its own notAfter and until the latest notAfter below it plus
    crl_days – imported legacy certificates may outlive their CA.
- **No issuingDistributionPoint yet.** OpenSSL refuses such a CRL for certificates without a CDP.
- **Offline root CRLs are uploaded and checked:**
  - signer generation via signature + AKI;
  - number strictly increasing;
  - thisUpdate not in the future, nextUpdate in the future;
  - no delta CRL.
  - Our intermediates on it are marked revoked for good; certificateHold is not supported (warning
    says so), lifting the hold later changes nothing.
- **Serving:** DER over HTTP, short max-age (15 min) with ETag/304, never cached until nextUpdate.

## 8. ACME specifics

- Implement RFC 8555 objects faithfully: directory, newNonce, newAccount, newOrder, authz,
  challenge, finalize, certificate, revokeCert, keyChange. Test against Pebble behaviour and
  real clients (certbot, acme.sh, lego, Traefik, Caddy, win-acme).
- Challenges: http-01 (port 80 only, redirects only to 80/443), dns-01 (TXT on `_acme-challenge`,
  follow CNAMEs for delegation), tls-alpn-01 (RFC 8737, port 443).
- EAB (external account binding) for account approval; ARI (RFC 9773) for renewal windows.
- Per-order manual approval doesn't work with standard clients (they time out after finalize) –
  approvals live at account level or "new hostname" level (PLAN §6.3).
- The agent is an ACME client too (ADR-19). Its extra powers (inventory, deploy) come from its
  own mTLS channel, not from a privileged issuance path.

## 9. Legacy importer

Reads the directory produced by `legacy/pki.sh` (`$PKI_DIR`, default `./pki`):

```
pki/pki.conf                      KEY="value" lines (see legacy/lib/config.sh CONF_KEYS)
pki/root/{certs/ca.crt, private/ca.key, index.txt, crlnumber, ca.meta}
pki/intermediate/<name>/{certs/ca.crt, certs/chain.pem, private/ca.key, index.txt, crlnumber, ca.meta}
pki/issued/<name>/{cert.pem, key.pem?, chain.pem, fullchain.pem, cert.meta, archive/<stamp>/}
```

- `index.txt` is the OpenSSL CA database: `status(V/R/E) \t expiry \t revocation[,reason] \t serial(hex) \t filename \t subject`.
- `cert.meta` / `ca.meta` are `KEY="value"` files – parse them like `load_kv` does (whitelisted keys, never execute).
- Preserve **serial numbers, revocation status/reason/time and CRL numbers** – otherwise existing
  CRLs and OCSP answers become wrong.
- Encrypted keys need the passphrase at import time (legacy env vars `PKI_CA_PASS_<NAME>`, `PKI_CA_PASS`).
