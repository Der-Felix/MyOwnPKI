---
title: "Revocation"
description: "How a certificate is withdrawn before it expires: CRLs and OCSP in general, what MyOwnPKI serves (CRLs only), the addresses in each certificate, why a root cannot be revoked and why short lifetimes often beat revocation."
permalink: /learn/revocation/
sources:
  - internal/ca/revoke.go
  - internal/ca/crl.go
  - internal/ca/build.go
  - internal/ca/chain.go
  - internal/ca/profile.go
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - .claude/skills/myownpki/references/pki-rules.md
---

A certificate is valid until `notAfter`. Sometimes it has to stop earlier: the private key leaked, the
host was retired, the certificate was issued by mistake. **Revocation** is how a CA announces that.
It is also the weakest part of the system, because the client has to ask, and many do not.

* TOC
{:toc}

## Two mechanisms

| | CRL (certificate revocation list) | OCSP (online certificate status protocol) |
|---|---|---|
| Defined in | RFC 5280 | RFC 6960 |
| What it is | A signed file with the serial numbers of all revoked, not yet expired certificates of one CA | A signed answer for one certificate: good, revoked or unknown |
| Client behavior | Downloads the file, caches it until `nextUpdate` | Asks a responder, or the server staples a recent answer |
| Cost | Grows with the number of revoked certificates | One request per check, and the responder sees which site you visit |

A certificate says where to find each: the CRL distribution points extension holds the CRL address, and
the authority information access extension may hold an OCSP responder address.

## What MyOwnPKI serves

**CRLs only.** There is no OCSP responder in this release (it is planned for after v1.0), and the
certificates carry no OCSP address. The `ocsp` preset exists to make the signing certificate of an
OCSP responder; it does not mean the server answers OCSP requests.

- **One CRL per CA generation**, signed by that generation's key. The first CRL is created together with
  the generation, because a distribution point that answers "not found" makes strict clients refuse every
  certificate below it.
- **Address** (fixed in every certificate when it is issued): `<base URL>/crl/<ca name>/<generation>.crl`,
  for example `http://pki.homelab.lan/crl/issuing/1.crl`. The issuer's certificate is at
  `<base URL>/ca/<ca name>/<generation>.crt`. It is served by the **public listener**, as DER, over plain
  HTTP and without login, with a short cache time (`max-age` of 15 minutes). HTTP is deliberate: a client
  that needs the CRL to check the TLS certificate of the CRL server would be stuck.
- **Numbers and times.** The CRL number rises with every CRL of a CA. A CRL is renewed after a third of its
  lifetime; a warning follows from half. An entry stays until the certificate's `notAfter` plus the CRL
  lifetime has passed (RFC 5280 §3.3). Default lifetimes: 7 days for an intermediate, 30 days for an
  online root, 180 days for an offline root.
- **While the server is sealed** a revocation is stored at once, but the new CRL can only be signed after
  the unseal. Until then the UI says "not yet published". Do not assume a revoked certificate is rejected
  before the CRL lists it.
- **The offline root's CRL** can only be signed offline. You upload it; the server checks the signer, that
  the number rises and that the times are sane. A CA the root revokes stops issuing.

Look at what a certificate points to, and at the CRL itself:

```bash
openssl x509 -in www.homelab.lan.pem -noout -ext crlDistributionPoints
```

```bash
curl -s -o issuing.crl http://pki.homelab.lan/crl/issuing/1.crl
```

```bash
openssl crl -inform DER -in issuing.crl -noout -text
```

## Revoking in MyOwnPKI

A revocation is **final**. There is no "certificate hold" that can be lifted, because the CA/Browser Forum
bans it for public certificates. The reasons offered are RFC 5280 reasons:
unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation and privilegeWithdrawn,
and for a CA also cACompromise. Revoking in the UI needs a fresh second factor.

With **keyCompromise** (or cACompromise) the key is also blocked: the engine refuses it in every later
request, so a stolen key cannot come back in a new CSR. A client of the ACME server can revoke with
`certbot revoke` or `lego certificates revoke`, and the certificate's own key can revoke it too.

## A root cannot be revoked

Revocation is announced by the CA above. A root has none, and clients hold it because you installed it.
MyOwnPKI refuses to revoke a root and tells you to remove it from the trust stores and retire it. An
intermediate below an online parent is revoked by that parent; one below an offline root is revoked on the
root machine and the new root CRL is uploaded.

## Short lifetimes often beat revocation

Revocation only helps when the client checks and the check can reach the list. Short lifetimes work
without either. A certificate that lives 90 days is a smaller risk after a leak than one that lives 397
days, whatever the client does. The CA/Browser Forum is shortening the lifetime of public certificates for
the same reason (200, 100 and then 47 days, ballot SC-081); this does not bind a private CA, but
automation with ACME or the agent makes short lifetimes cheap. See
[Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).

## What clients do

General knowledge, and it varies by client and version:

- Many clients **do not check revocation at all**. Programs built on OpenSSL, for example, check no
  CRL unless told to.
- Clients that do check often **soft-fail**: when the list cannot be fetched, they accept the
  certificate. An attacker who can block the CRL address can also block the news.
- Clients that do check strictly reject certificates when the CRL has **expired** (RFC 5280 §5.1.2.5).
  That is why an old CRL is an outage, and why MyOwnPKI raises the `crl` and `sealed` alerts.

Treat revocation as a way to record and publish a decision, and a short lifetime as the protection.

## Next steps

- Keep CRLs current: [Monitoring alerts]({{ '/monitoring/' | relative_url }}#the-alerts) (`crl`, `sealed`).
- Put the base URL right before the first certificate: [Best practices]({{ '/best-practices/' | relative_url }}#choose-the-public-base-url-once).
- What to do after a key leak: [operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).
- What happens to the old certificate after a renewal: [Adding hosts]({{ '/hosts/' | relative_url }}#renewal-renew-now-and-what-the-agent-reports).
- The offline root's CRL: [Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }}).
- Check the addresses work: [Installation]({{ '/install/' | relative_url }}#verify-the-installation).
