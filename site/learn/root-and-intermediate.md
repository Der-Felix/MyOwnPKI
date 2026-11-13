---
title: "Root and intermediate CAs"
description: "Why a PKI has a root and intermediates, why the root key stays offline, how MyOwnPKI models an offline root, and what happens when a CA is compromised or expires."
permalink: /learn/root-and-intermediate/
sources:
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - internal/ca/lifecycle.go
  - internal/ca/profile.go
  - internal/ca/offline.go
  - internal/ca/revoke.go
  - .claude/skills/myownpki/references/pki-rules.md
---

A PKI is usually built in two levels. The **root CA** is the anchor that clients trust. One or more
**intermediate CAs** below it sign the certificates you hand out. The point is not tidiness: it lets you
keep the one key that is hard to replace out of harm's way.

* TOC
{:toc}

## Two levels, two jobs

```text
Root CA          self-signed, in the clients' trust stores, signs only CAs and CRLs
  |
  +-- Intermediate CA "issuing"     signs the certificates of hosts and people
        |
        +-- www.homelab.lan, nas.homelab.lan, ...
```

The root signs itself, so there is nothing above it to vouch for it; clients trust it because you put it
in their trust store. In MyOwnPKI a root signs **only intermediate CAs and CRLs**. The engine refuses to
issue an end-entity certificate with a root, so the root key is not needed for daily work, and a wrongly
issued certificate is revoked by its intermediate without touching the anchor.

## Why the root stays offline

If an intermediate leaks, you revoke it, create a new one and re-issue. If the root leaks, every client
that trusts it must be changed, because a root cannot be revoked (see below). So the root key gets the
strongest protection you can give: it lives on a machine that is not on the network, and it comes out
only when an intermediate is created or renewed and when the root's own CRL must be signed.

## How MyOwnPKI models it

A CA has one of two key modes. HSM and KMS modes appear in the plan but not in this release.

| Mode | Where the key is | What the server holds | Use it for |
|---|---|---|---|
| Offline | On another machine | Only the root's **certificate** | The root, as recommended |
| Online, encrypted | In the server's database, encrypted | Key and certificate; signing needs the server to be unsealed | Intermediates; a root only for trying out or a homelab that accepts the risk |

`init --with-ca` creates an online root and an intermediate (named `root` and `issuing`) in one step, for
testing. The UI warns about an online root.

**An intermediate below an offline root** is made in these steps:

1. The server creates the intermediate's key and a request, and an OpenSSL **extension file** that states
   exactly what the CA certificate may do.
2. You take the request and the extension file to the root machine and sign with that file, with
   `-copy_extensions none`, using `pki.sh` (`legacy/` in the repository) or plain OpenSSL 3.
3. You upload the signed certificate. The server compares it with its order and **refuses any
   difference**: key, subject, CA:TRUE, key usage, pathlen, name constraints, EKU limit, the authority key
   identifier, the serial, the validity inside the root's, and the signature algorithm.

The reason for step 3: a request is attacker input even when your own server wrote it. What a CA
certificate may do is decided by the server's order, not by what comes back.

The root's **CRL** can only be signed offline. You sign it on the root machine and upload it on the root's
page. A root imported into MyOwnPKI shows its SHA-256 fingerprint, which you compare with the one on the
root machine before you trust it.

The defaults, all changeable per CA at creation:

| | Default |
|---|---|
| Key algorithm of a new CA | ECDSA P-384 (also allowed: P-256, RSA 3072, RSA 4096; never Ed25519) |
| Lifetime of a root | 7300 days (20 years) |
| Lifetime of an intermediate | 3650 days (10 years), never beyond its parent |
| Intermediate path length | 0: it may sign certificates for hosts and people, but no further CA |
| CRL lifetime | 180 days offline root, 30 days online root, 7 days intermediate |

## When something goes wrong

| Event | What follows | What you do |
|---|---|---|
| The intermediate's key may be stolen | Anyone with it can sign certificates that clients accept, within the intermediate's constraints | Revoke the intermediate at the root (for an offline root: sign the revocation on the root machine and upload the new root CRL), create a new intermediate, re-issue ([operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong)) |
| The root's key may be stolen | A root cannot be revoked: it has no issuer above it, and clients hold it by your decision. The engine says so and tells you to remove it from the trust stores and retire it | Build a new PKI and replace the root on every client |
| The server is stolen or compromised | An online CA key is encrypted and useless without the passphrase or recovery key; while the server is unsealed its master key is in memory and each CA key is decrypted for every signature | Seal, take it off the network, restore on a clean machine ([Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }})). An offline root is untouched. |
| An intermediate expires | Nothing below it validates from that day. A CA never issues beyond its own end, and the monitor warns at 90 and 30 days | Renew it before: a renewal is a **new key**, the next *generation* of the same CA name. The old generation keeps its URL and CRL, so older chains keep working |
| The root expires | Everything expires with it | Renew the root (an offline root: sign the new certificate offline and import it under the same name) and give clients the new root ([trust]({{ '/learn/trust/' | relative_url }})) |

## Next steps

- Create the CAs: [Installation]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).
- Habits for the root: [Best practices]({{ '/best-practices/' | relative_url }}#keep-the-root-offline), and
  [narrow every CA]({{ '/best-practices/' | relative_url }}#narrow-every-ca-with-name-constraints).
- Limit what an intermediate may sign: [Name constraints]({{ '/learn/name-constraints/' | relative_url }}).
- How clients decide to trust the root: [How trust works]({{ '/learn/trust/' | relative_url }}).
- Plan the CA lifetimes: [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).
- Moving from the Bash suite: [operations guide §5]({{ '/reference/operations/' | relative_url }}#5-moving-from-pkish).
