---
title: "Reading a certificate"
description: "The fields of a server certificate that matter (names, validity, key usage, basic constraints, key), the presets of MyOwnPKI and what each sets, and how to read openssl x509 -text."
permalink: /learn/certificate-anatomy/
sources:
  - presets/*.yaml
  - internal/ca/build.go
  - internal/ca/engine.go
  - internal/ca/keypolicy.go
  - internal/ca/validity.go
  - internal/ca/chain.go
  - internal/ca/preset/preset.go
  - docs/PLAN.md
  - .claude/skills/myownpki/references/pki-rules.md
---

This page names the fields of a TLS server certificate, says which ones a client really looks at, lists
the presets that MyOwnPKI offers, and walks through the output of `openssl x509 -text`.

* TOC
{:toc}

## The fields that matter

| Field | What it says | Remarks |
|---|---|---|
| Subject | Who the certificate is for | For a server the **common name** (CN) is only a display name. With a server preset MyOwnPKI derives it from the first DNS name; a derived name longer than 64 characters is left out, never cut. |
| Subject alternative name (SAN) | The DNS names and IP addresses it is valid for | **This is what clients match the host name against.** At least one is required for server presets. |
| Issuer | Which CA signed it | Matched with the CA's subject name and key identifier to build the chain. |
| Validity | `notBefore` and `notAfter` | MyOwnPKI sets `notBefore` 5 minutes in the past, for clients whose clock is a little behind. |
| Key usage | What the key may do mathematically (sign, encipher) | Marked **critical**. |
| Extended key usage (EKU) | Which applications may use it: `serverAuth`, `clientAuth` and others | A TLS client wants `serverAuth`. |
| Basic constraints | `CA:FALSE` for a leaf; `CA:TRUE` and a path length for a CA | Marked critical. |
| Subject and authority key identifier | A hash of this key, and of the issuer's key | Help to find the issuer's certificate. |
| Authority information access (AIA) | Where to download the issuer's certificate | |
| CRL distribution points | Where the revocation list is | [Revocation]({{ '/learn/revocation/' | relative_url }}) |
| Public key and signature algorithm | The key type, and how the CA signed | |

A **critical** extension must be understood by the client: one that does not know it must reject the
certificate (RFC 5280 §4.2). A non-critical one it does not know it may ignore.

### Why the CN is not used

Browsers match the host name only against the SAN. A certificate with the right CN and no SAN fails. The
SAN also holds IP addresses and several names, which a single CN cannot. MyOwnPKI therefore requires a SAN
for server presets. One edge case is handled for safety: when a certificate has no DNS name and its CN
looks like a host name (it contains a dot), some clients still read it as one, so the CN must then
satisfy the CA's DNS name constraints too.

### Why the extensions come from the preset

A CSR can ask for any extension, including `CA:TRUE`. If the CA copied it, a request for a "web server"
certificate would return a new CA that can sign for the whole world. So MyOwnPKI uses the CSR only for the
**public key**, the **names** and the subject, and builds every extension from the **preset** and the CA.
Names are checked against the domain policy and the name constraints before anything is signed.

## The presets

Each preset fixes the key usage, the extended key usage, the default lifetime and the names it needs. The
lifetime is a default: an explicit request is accepted or denied, never changed silently, but a default
above the CA's maximum validity (397 days unless set otherwise) is shortened to it, and a default is also
shortened to the end of the CA. A CA never issues beyond its own end. With the default maximum, the presets
of 730 days or more therefore get 397 days until the CA's maximum is raised.

| Preset | For | EKU | Days | Names required |
|---|---|---|---|---|
| `server` | Web servers, proxies, mail, LDAPS | serverAuth | 397 | DNS or IP |
| `wildcard` | `*.homelab.lan` plus `homelab.lan` | serverAuth | 397 | `*.domain` (the base name is added) |
| `server-client` | Peers that also open mutual TLS connections | serverAuth, clientAuth | 397 | DNS or IP |
| `client` | mTLS, 802.1X, API clients | clientAuth | 730 | none |
| `user` | Login and e-mail for a person | clientAuth, emailProtection | 730 | e-mail |
| `smime` | E-mail signing and encryption | emailProtection | 730 | e-mail |
| `vpn-server` | OpenVPN, IKEv2 gateways | serverAuth, ipsecIKE, IKE intermediate | 730 | DNS or IP |
| `vpn-client` | OpenVPN, IKEv2 clients | clientAuth, ipsecIKE | 730 | none |
| `codesign` | Scripts, packages | codeSigning | 1095 | none |
| `ocsp` | Signing key of an OCSP responder | OCSPSigning, with `ocsp-nocheck` | 365 | none |
| `timestamp` | RFC 3161 time stamping | timeStamping, **critical** | 1825 | none |
| `custom` | Key usage and EKU chosen per certificate | as chosen | 365 | none |

Key usage follows the key type. An **RSA** key gets `digitalSignature` and `keyEncipherment` (TLS 1.2 RSA
key exchange encrypts a secret with the server key). An **ECDSA or Ed25519** key can only sign, so it gets
`digitalSignature` alone. `user`, `smime` and `timestamp` add `nonRepudiation`; `codesign` is
`digitalSignature` only. ACME certificates use the `server` preset by default with 90 days, set per
domain.

## Keys and signatures

Leaf keys may be ECDSA P-256, P-384 or P-521, RSA 2048 to 8192 bits with exponent 65537, or Ed25519. The
server generates ECDSA P-256 when it makes the key. New CAs use P-384 by default (P-256, RSA 3072 and RSA
4096 are also offered). The signature follows the issuer's key: SHA-384 for P-384, SHA-256 for P-256 and
RSA, SHA-512 for P-521. MyOwnPKI warns, and does not refuse, for Ed25519 and P-521 in a TLS server
certificate, because browsers reject them. Serial numbers are 159 random bits.

## Reading `openssl x509 -text`

```bash
openssl x509 -in www.homelab.lan.pem -noout -text
```

An abridged example of a certificate for the `server` preset, signed by a P-384 intermediate. The key and
signature bytes are left out.

```text
Serial Number: 3f:9a:02:c7:d5:1e:88:b4:a0:61:7c:3e:9b:2d:45:f8:e1:a0:7c:93     (1)
Signature Algorithm: ecdsa-with-SHA384                                         (2)
Issuer: CN=Homelab Issuing CA                                                  (3)
Validity
    Not Before: Nov 12 09:55:00 2026 GMT                                       (4)
    Not After : Dec 14 09:54:59 2027 GMT
Subject: CN=www.homelab.lan                                                    (5)
Subject Public Key Info:
    Public Key Algorithm: id-ecPublicKey                                       (6)
        Public-Key: (256 bit)
        NIST CURVE: P-256
X509v3 extensions:
    X509v3 Basic Constraints: critical
        CA:FALSE                                                               (7)
    X509v3 Key Usage: critical
        Digital Signature                                                      (8)
    X509v3 Extended Key Usage:
        TLS Web Server Authentication                                          (9)
    X509v3 Subject Key Identifier:  2E:20:26:81:...
    X509v3 Authority Key Identifier:  F9:F4:DE:25:...                          (10)
    X509v3 Subject Alternative Name:
        DNS:www.homelab.lan, DNS:nas.homelab.lan, IP Address:192.0.2.20        (11)
    Authority Information Access:
        CA Issuers - URI:http://pki.homelab.lan/ca/issuing/1.crt               (12)
    X509v3 CRL Distribution Points:
        URI:http://pki.homelab.lan/crl/issuing/1.crl                           (13)
```

1. A random serial. Issuer name plus serial identify one certificate; revocation lists name the serial.
2. The CA signed with its P-384 key and SHA-384.
3. The issuer is the **intermediate**, never the root, for a certificate of a host.
4. Five minutes before issuance; 397 days minus a second later. The end is inclusive.
5. A display name. Do not look for the host name here.
6. The public key of the host. The private key stays on the host that uses it.
7. `CA:FALSE`: this certificate cannot sign other certificates.
8. An ECDSA key signs; there is no key encipherment.
9. Valid for TLS servers only. A client-authentication use would need `clientAuth` here.
10. Must equal the issuer's subject key identifier. This is how the chain is joined.
11. The names a client may connect to. `192.0.2.20` is an IP address, not a DNS name.
12. Where to download the intermediate's certificate. The address is built from the CA's base URL, its name and the generation of its key.
13. The same for the CRL. Both are fixed for the life of the certificate.

Narrower views of the same file:

```bash
openssl x509 -in www.homelab.lan.pem -noout -subject -issuer -dates -ext subjectAltName,extendedKeyUsage
```

```bash
openssl x509 -in www.homelab.lan.pem -noout -fingerprint -sha256
```

## Next steps

- Issue one: [Installation]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate), and
  [verify that its URLs work]({{ '/install/' | relative_url }}#verify-the-installation).
- Why a name outside the CA's limits is refused: [Name constraints]({{ '/learn/name-constraints/' | relative_url }}).
- How long to make certificates: [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).
- How the chain is checked: [How trust works]({{ '/learn/trust/' | relative_url }}).
- ACME domains choose the preset and the lifetime: [operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).
