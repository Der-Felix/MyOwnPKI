---
title: Keep the root offline
summary: Why the root key stays off the server, and how to import the root and have an intermediate signed on another machine.
audience: Admins who set up the PKI
order: 20
site: /guides/offline-root/
sources:
  - docs/OPERATIONS.md
  - internal/web/app_caactions.go
  - internal/ca/offline.go
  - internal/ca/crlupload.go
  - legacy/lib/ca.sh
  - legacy/lib/cli.sh
  - legacy/README.md
---

## Why the root stays offline

The root signs only other CAs and its own revocation list (CRL). If its key is stolen, every client that trusts it has
to be changed by hand, because a root cannot be revoked. So the key lives where nothing can reach it: on a machine that
is switched off or off the network. This server gets only the root's **certificate**, which is public.

| Where | What happens | What moves |
|---|---|---|
| This server | Makes the intermediate's key and a certificate request, and writes an extension file that says exactly what the CA may do | Out: a `.csr` and a `.ext` file, both public |
| Offline machine | Signs the request with exactly that extension file | In: the two files. Out: a `.crt` file |
| This server | Checks the signed certificate against its order and activates the CA | In: the certificate |

No private key ever travels.

## 1. Make the root and import its certificate

On the offline machine create the root with `pki.sh` from the `legacy/` folder of the project. Plan its lifetime now:
the default is 7300 days and the root must outlive every intermediate below it. Protect its key with a passphrase and
keep a copy of that machine's directory in a safe place.

```bash
./pki.sh init --org "Homelab"
```

Then open [Import offline root](/authorities/import). Use the **same name** as on the offline root (the default is
`root`), paste the certificate (PEM) and enter the public base URL. The CRL lifetime is the number of days this server
plans for the root's CRL; empty means 180. The page then shows the SHA-256 fingerprint. Compare it with the one the
offline machine shows, because this import decides what the server trusts.

## 2. Create the intermediate

Open [New CA](/authorities/new) and choose the offline root as the parent. Set the name constraints for your own names.
The CA is listed as *Waits for its signature* and the **Offline signing** page opens. It shows the request, the
extension file and three values: the days, the digest and the serial. Save both files under the names shown.

## 3. Sign it on the offline machine

Copy the `.csr` and `.ext` files over, for example on a USB stick. **Before** you sign, check that the subject is the
one you ordered and read the `.ext` file: it must say `CA:TRUE` and show the path length and name constraints you chose.
Always sign with the extension file; the extensions inside the request are never copied.

```bash
openssl req -in issuing-1.csr -noout -verify -subject
```

Use the days the page shows:

```bash
./pki.sh ca-sign issuing-1.csr --ext issuing-1.ext --days 3650 --out issuing-1.crt
```

`ca-sign` refuses a file without the right extension section and a `--days` that would end after the root. The page also
prints the plain OpenSSL command for a machine without `pki.sh`. Check the result before it leaves the machine:

```bash
openssl verify -CAfile root.crt issuing-1.crt
```

## 4. Upload the certificate

On the **Offline signing** page paste the PEM into step 3 and choose **Install certificate**. The server checks it against
the order: key, subject, `CA:TRUE`, key usage, path length, name constraints and the root's signature. Anything else is
refused. On success the CA is active.

## 5. Keep the root's CRL current

Nothing renews the root's CRL automatically, because the server cannot sign it. Create it on the offline machine:

```bash
./pki.sh crl --ca root
```

Paste the contents of `publish/root.crl.pem` into **Upload the root's CRL** on the root's page (**Manage**). The server
accepts only a CRL with a higher number than the newest one, signed by this root. Renew it before half of its lifetime has
passed. The `crl` alert warns at that point, and once the CRL is past its next update, clients that check revocation reject
every certificate below the root. Put the next date in a calendar.

> **Note:** `pki.sh` signs the CRL for the number of days in its own `pki.conf` (`CRL_DAYS`, 30 by default). That is the real
> lifetime, not the 180 days the server plans for, so count your renewal interval from it.

## Check it worked

[Certificate authorities](/authorities) lists the intermediate as valid with the root as its parent. On the server:

```bash
sudo -u myownpki /usr/local/bin/myownpki ca show {ca_name}
```
