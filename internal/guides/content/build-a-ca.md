---
title: Build a certificate authority
summary: Create a root and an online intermediate in the UI, which fields matter and what can never be changed afterwards.
audience: Admins who set up the PKI
order: 10
site: /guides/ca-lifecycle/
sources:
  - docs/OPERATIONS.md
  - internal/web/app_caactions.go
  - internal/ca/profile.go
  - internal/ca/lifecycle.go
  - cmd/myownpki/ca.go
  - cmd/myownpki/init.go
---

## Two kinds of CA

A certificate authority (CA) is a key with a certificate. The **root** is the trust anchor: every client installs
it, and it signs only other CAs and its own revocation list (CRL). An **intermediate** sits below the root and
signs the certificates that servers and people use. The split matters because a stolen intermediate can be
replaced without touching a client, while a stolen root cannot be revoked at all: every client has to drop it.
That is why the recommended layout keeps the root key off this server (see [Sign with an offline root](/guides/offline-root)).

## Create them

Creating a CA needs the admin role and a fresh second factor; an API token can never do it.

1. Open [Certificate authorities](/authorities) and choose **New CA** (`/authorities/new`).
2. Leave **Parent CA** on "none: a new root" to create an **online root**, which keeps its key on this server. That
   is fine for a test or a homelab and the page warns you about it. For an **offline root** import its
   certificate instead (**Import offline root**) and read the offline guide.
3. Run **New CA** again with the root as the parent to create the intermediate that issues certificates.

| Field | What to enter |
|---|---|
| Name | Lower case letters, digits and `. _ -`. It is part of every certificate address and never changes. |
| Public base URL | The address clients use to fetch this CA's certificate and CRL, for example `http://pki.homelab.lan`. It is written into every certificate below this CA and never changes. |
| Key algorithm | `ecdsa-p384` is the default; `ecdsa-p256`, `rsa-3072` and `rsa-4096` are offered. Ed25519 is never accepted for a CA. |
| Validity in days | Empty means 7300 for a root and 3650 for an intermediate, and never beyond the parent. |
| Path length | `0` lets the intermediate issue end-entity certificates only, no further CAs. |
| Permitted DNS names, IP ranges | Name constraints. Recommended: even a stolen intermediate key then cannot sign names outside them. |
| EKU limit | Narrows what the CA may be used for, for example `serverAuth`. |
| CRL lifetime, maximum certificate validity | Empty means 7 days for an intermediate (30 for an online root) and 397 days. |

> **Warning:** Choose the name and the public base URL once and with care. Both are in every certificate the CA
> issues, so a change would orphan them. Use a DNS name that you control and will keep.

An intermediate below an online CA is signed at once. Below an offline root it waits for its signature.

## Check the result

The first command lists the authorities of this instance, the second shows one in detail. Run them on the server
as the service user.

```bash
sudo -u myownpki /usr/local/bin/myownpki ca list
```

```bash
sudo -u myownpki /usr/local/bin/myownpki ca show {ca_name}
```

The root is published on the public listener as `/ca/<root name>/<generation>.crt`. Fetch it and compare the
fingerprint with the one in **Certificate authorities**, on the page of the root, before any client trusts it:

```bash
curl --silent --output root.crt http://pki.homelab.lan/ca/root/1.crt
```

```bash
openssl x509 -inform DER -in root.crt -noout -subject -fingerprint -sha256
```

## Good to know

- A fresh instance has no CA unless `myownpki init --with-ca --ca-base-url URL` created a test root named `root` and
  an intermediate named `issuing`. Treat those as throw-away CAs.
- You can retire a CA but not delete it, and you can renew one only with a new key.

## Next

Add a [domain](/domains) so ACME clients may ask for names, then pick a client from the [list of guides](/guides).
The longer page covers renewing, replacing and retiring a CA.
