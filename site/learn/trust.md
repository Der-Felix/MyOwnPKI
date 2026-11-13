---
title: "How trust works"
description: "How a client decides to trust a certificate: chain building, trust stores, why your root must be distributed, what a browser warning means, and the difference between trusting a root and pinning an issuer."
permalink: /learn/trust/
sources:
  - docs/OPERATIONS.md
  - api/openapi.yaml
  - internal/ca/chain.go
  - .claude/skills/myownpki/references/pki-rules.md
---

A client has no list of "good" servers. It has a list of **trust anchors**, which are CA certificates it
was told to believe, and the rule that a certificate is good if it leads to one of them. Everything on
this page follows from that.

* TOC
{:toc}

## How a client checks a certificate

When a TLS server connects, it sends its own certificate and the intermediates, usually as one file
(`fullchain`). The client then:

1. **Builds a path** from the server certificate to a trust anchor. It looks for the issuer of each
   certificate by name and by key identifier, and ends at a certificate it already holds as an anchor.
2. **Verifies each signature** along the path, with the key of the certificate above.
3. **Checks each certificate**: it is inside its validity period, a CA certificate has `CA:TRUE` and
   allows the path length, critical extensions are understood, name constraints and the EKU limit of
   every CA on the path are kept.
4. **Checks the purpose**: for a TLS server the leaf must allow `serverAuth`.
5. **Matches the host name** against the names in the SAN.
6. Optionally checks **revocation** ([Revocation]({{ '/learn/revocation/' | relative_url }})).

If any step fails the connection fails, or the browser shows a warning. A server normally does not send the root:
the client has it already, and RFC 8446 §4.4.2 allows leaving it out. For that reason MyOwnPKI's chain
downloads never contain the root; you get it on its own.

A server should send the intermediates. Some clients download a missing one from the `CA Issuers` address
in the certificate; many do not, and OpenSSL-based tools are among them. Do not rely on it.

## Trust stores

A trust store is the list of anchors. Which list a program reads depends on the program:

| Client | Where its anchors come from |
|---|---|
| Windows, macOS, iOS, Android | The operating system's store. Windows has one per computer and one per user. |
| Most Linux programs | The system bundle, filled by the distribution; on Debian and Ubuntu from `/usr/local/share/ca-certificates/` by `update-ca-certificates` |
| Firefox | Its own list by default |
| Java | Its own `cacerts` file |
| A single tool | Often a setting: `REQUESTS_CA_BUNDLE` for certbot, `LEGO_CA_CERTIFICATES` for lego, `--ca-bundle` for acme.sh |

## Why you must hand out your root

A public CA's root is already in every system, because the vendors put it there. Yours is not. Until a
client holds your root, its check ends at "unknown authority". The step cannot be skipped, and it is the
most security-critical step in the whole PKI, because **whoever adds a false root to a client can
impersonate every website to that client**.

So treat it as a decision, not a download:

- The public listener of MyOwnPKI serves a **trust page** at `/` (an admin can switch it off) with each root, its **SHA-256
  fingerprint**, downloads (DER and PEM), Windows helper scripts and guides for Windows, macOS, iOS,
  Android, Linux and Firefox. The page comes over plain HTTP so that it works before anything trusts you.
- Therefore compare the fingerprint with one you got another way, such as the admin UI or a printout:

  ```bash
  openssl x509 -in homelab-root.pem -noout -fingerprint -sha256
  ```

- Hand out the **root**, not the intermediates. Intermediates are found through the chain.

## What a browser warning means

The text differs by browser. These are the usual causes.

| What you see (examples) | Usually means | Check |
|---|---|---|
| `NET::ERR_CERT_AUTHORITY_INVALID` (Chrome), `SEC_ERROR_UNKNOWN_ISSUER` (Firefox) | The chain does not end at a trusted anchor: your root is not in this client's store, or the server did not send the intermediate | Is the root installed in the store **this** program uses? Does the server send `fullchain`? |
| `NET::ERR_CERT_DATE_INVALID`, `SEC_ERROR_EXPIRED_CERTIFICATE` | Expired or not yet valid | The certificate's dates, and the clock of the client |
| `NET::ERR_CERT_COMMON_NAME_INVALID`, `SSL_ERROR_BAD_CERT_DOMAIN` | The name you typed is not in the SAN | `openssl x509 -noout -ext subjectAltName`; did you use an IP address or a short name? |
| A warning only on some clients | Different stores, an old client, or constraints one client does not support | Test with the failing client itself |

A bypass button on such a page tells the browser to skip the check for one visit. It does not fix the
trust, and it trains people to click through warnings.

## Trusting a root versus pinning an issuer

| Approach | The client accepts | Consequence |
|---|---|---|
| Trust the root (normal) | Anything a path from that root allows | Renewing or replacing an intermediate needs no client change |
| Trust only an intermediate as the anchor | Only what that one CA signed | Needs a client that accepts a non-self-signed anchor, for example `openssl verify -partial_chain`. A new intermediate key means every client changes. |
| Pin a leaf certificate or key | One certificate or key | Breaks at every renewal unless the key is reused |

For a homelab, trust the root and limit it with name constraints. Pinning is for software you control on
both ends and can update together.

## The cost of a root in many stores

A root is trusted for **every** name unless something narrows it. If your root sits in the stores of
all your devices, then anyone who gets hold of an intermediate key can sign a certificate for
`www.example.com` that all those devices accept. Public roots are held to strict audits for that reason.

You reduce the risk with [name constraints]({{ '/learn/name-constraints/' | relative_url }}) on the
intermediates, so that a stolen key can sign only your own names, and by keeping the root offline
([Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }})). Name constraints
depend on the client enforcing them. Do not install the root on devices that should never trust your
network's names.

## Next steps

- Distribute the root: [operations guide §10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients)
  and [the public trust page]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page).
- A client says "unknown authority": [operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails).
- Check what a host serves against your PKI: [TLS scan]({{ '/tls-scan/' | relative_url }}).
- Read the fields the checks use: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).
- Narrow the root's reach: [Name constraints]({{ '/learn/name-constraints/' | relative_url }}).
