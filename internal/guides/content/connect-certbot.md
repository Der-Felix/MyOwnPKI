---
title: Connect certbot
summary: Point certbot at the ACME directory of this instance, trust the root, get a first certificate with http-01 and check it.
audience: Admins who run certbot on a host
order: 30
site: /guides/certbot/
sources:
  - docs/OPERATIONS.md
  - internal/web/app_acme.go
  - internal/web/app_domains.go
  - internal/acme/finalize.go
  - internal/acme/admin.go
---

## What certbot needs

ACME is the protocol that lets a client ask a CA for a certificate and prove that it controls the name. Every ACME
client starts from one address, the **directory**: a document that lists where the server accepts accounts and orders.
The directory of this instance is the address in the next command.

```bash
curl --silent {acme_directory}
```

Before the first run, three things must be true:

- A [domain](/domains) covers the name you ask for and allows http-01. Without it certbot is refused with
  `rejectedIdentifier`.
- The PKI server can reach port 80 of the host under that name. With http-01 the server fetches a small file from
  `/.well-known/acme-challenge/` on that port and so proves that the host controls the name.
- certbot trusts your root, because it checks the server's certificate like any website.

## 1. Trust the root

The root is on the public listener as `/ca/<root name>/<generation>.crt`, in DER form. Fetch it, convert it and compare
the fingerprint with the one on the root's page under [Certificate authorities](/authorities) before you trust it.

```bash
curl --silent --output homelab-root.crt http://pki.homelab.lan/ca/root/1.crt
```

```bash
openssl x509 -inform DER -in homelab-root.crt -out homelab-root.pem
```

```bash
openssl x509 -in homelab-root.pem -noout -fingerprint -sha256
```

Then let certbot trust it. Either install the root system-wide (Debian and Ubuntu, the two commands below) or give it to
certbot alone with the environment variable `REQUESTS_CA_BUNDLE`, set to the path of the PEM file. A certbot that runs
from a systemd timer does not see your shell, so set the variable in the timer's unit too. If certbot still reports
`CERTIFICATE_VERIFY_FAILED`, use the variable.

```bash
sudo cp homelab-root.pem /usr/local/share/ca-certificates/homelab-root.crt
```

```bash
sudo update-ca-certificates
```

## 2. Ask for a certificate

With **standalone** certbot opens port 80 itself for the check, so nothing else may listen there:

```bash
sudo certbot certonly --server {acme_directory} --standalone -d nas.homelab.lan
```

With **webroot** your web server keeps port 80 and must serve `/.well-known/acme-challenge/` from that directory:

```bash
sudo certbot certonly --server {acme_directory} --webroot -w /var/www/acme -d nas.homelab.lan
```

certbot puts every `-d` name into its request as a *subject alternative name* (SAN). Modern clients match the host name against
the SANs, not the common name, and the server accepts a request only if it names exactly the names that were
ordered and validated. A name you did not order can never end up in a certificate.

## 3. A first account may have to wait

New domains default to the approval level *approved accounts*: the first account waits until an admin approves it under
[Accounts](/acme/accounts), and certbot says `waits for approval`. An **EAB key** skips the wait. Create one under
[EAB keys](/acme/eab); the key ID and the MAC key are shown once. It binds one account and expires after 7 days unless
you choose otherwise, so use it for the first run, in place of the plain command of step 2:

```bash
sudo certbot certonly --server {acme_directory} --eab-kid KEY_ID --eab-hmac-key MAC_KEY --standalone -d nas.homelab.lan
```

> **Warning:** The MAC key is a secret, and on a command line it is visible to every user of the host in the process
> list while certbot runs, it is saved in the shell history, and `sudo` writes the whole command into its log. Run
> `unset HISTFILE` in the shell first and close that shell afterwards, so the line is not saved, and treat the key as
> spent after the first run: it binds one account. An unused key cannot be withdrawn, it only expires, so choose few days.

## Check it worked

```bash
sudo certbot certificates
```

```bash
sudo openssl verify -CAfile homelab-root.pem -untrusted /etc/letsencrypt/live/nas.homelab.lan/fullchain.pem /etc/letsencrypt/live/nas.homelab.lan/fullchain.pem
```

```bash
sudo openssl x509 -in /etc/letsencrypt/live/nas.homelab.lan/fullchain.pem -noout -subject -issuer -dates -ext subjectAltName
```

[Orders](/acme/orders) shows the order as *valid*. certbot renews on its own 30 days before the end, and the package of
most distributions installs the timer; look for it with `systemctl list-timers`.

> **Warning:** `certbot renew --dry-run` is a real order for this server, which cannot tell it from a renewal. Depending
> on the predecessor setting of your tenant it can retire the certificate you use. On a production host watch the first
> real renewal instead.

## When it fails

| certbot says | Usually |
|---|---|
| `CERTIFICATE_VERIFY_FAILED`, unknown authority | certbot does not trust the root (step 1) |
| `rejectedIdentifier: no domain covers` | No domain covers the name: add one under [Domains](/domains) |
| `unauthorized: account waits for approval` | Approve the account or use an EAB key (step 3) |
| `connection: could not be reached` | Port 80 of the host is closed for the PKI server, or the name resolves elsewhere |
| `incorrectResponse: answered with status 404` | The web server does not serve the challenge directory: use standalone or fix the webroot |

The longer page adds a deploy hook that reloads nginx, split DNS and the other ACME clients.
