---
title: "Certbot with MyOwnPKI"
description: "Get and renew certificates from the MyOwnPKI ACME server with certbot: trust the root, standalone and webroot, an EAB key, the renewal timer and a deploy hook for nginx."
permalink: /guides/certbot/
sources:
  - docs/OPERATIONS.md
  - docs/NIGHTLOG.md
  - internal/web/app_acme.go
---

## When to use this

Use certbot when a Linux host already runs it, or when you want the best-known ACME client with the
least setup. certbot only asks for certificates and renews them; the **agent**
([Adding hosts]({{ '/hosts/' | relative_url }})) also deploys, tests, rolls back and reports to the server.
This page uses only what the operations guide documents
([§10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)); commands for options it does not
mention say so. Check `certbot --help all` for your version.

* TOC
{:toc}

## Before you start

- The ACME server is on and a **domain** covers the name you ask for
  ([Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }})).
- The client's DNS name resolves to the client **from the PKI server** and port 80 of the client is
  open for the PKI server: the server fetches the challenge file. See
  [Split DNS]({{ '/guides/split-dns/' | relative_url }}).
- certbot trusts your root (next section).
- The directory URL is `https://pki.homelab.lan/acme/directory`: the `acme.base_url` of the server plus
  `/directory`.

## Steps

1. Download the root from the public listener and compare its fingerprint with the one in
   *Certificate authorities* in the UI
   ([operations guide §10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients)):

   ```bash
   curl -o homelab-root.crt http://pki.homelab.lan/ca/root/1.crt
   ```

   ```bash
   openssl x509 -inform DER -in homelab-root.crt -out homelab-root.pem
   ```

   ```bash
   openssl x509 -in homelab-root.pem -noout -fingerprint -sha256
   ```

2. Let certbot trust it. Either install the root system-wide (Debian and Ubuntu: copy the PEM as
   `.crt` into `/usr/local/share/ca-certificates/` and run `update-ca-certificates`), or give it to
   certbot alone with the variable `REQUESTS_CA_BUNDLE`:

   ```bash
   export REQUESTS_CA_BUNDLE=/root/homelab-root.pem
   ```

   A certbot that runs from a systemd timer or cron does not see your shell: set the variable there too
   (for the timer, in a drop-in with `Environment=`), or use the system store. Whether certbot reads the
   system store depends on how it was installed; if it still reports `CERTIFICATE_VERIFY_FAILED`, use the
   variable.

3. **Standalone**, when no web server uses port 80. certbot opens port 80 itself during the check:

   ```bash
   certbot certonly --server https://pki.homelab.lan/acme/directory --standalone -d nas.homelab.lan
   ```

   **Webroot**, when a web server answers on port 80. The server must serve
   `/.well-known/acme-challenge/` from that directory:

   ```bash
   certbot certonly --server https://pki.homelab.lan/acme/directory --webroot -w /var/www/acme -d nas.homelab.lan
   ```

   Both ask for an e-mail address and the terms once. In a script add `--agree-tos -m admin@homelab.lan`.
   The operations guide documents `--server`, `--standalone`, `-d` and the EAB options. `--webroot`, `-w`,
   `--deploy-hook` (step 6), `renew` and `certificates` are general certbot behavior, so check
   `certbot --help all` for your version.

4. **With an EAB key.** If the domain's approval level is *approved accounts*, a new account waits for an
   admin. An EAB key skips the wait. Create it in *ACME → EAB keys*, copy the key ID and the MAC key (shown
   once), and add both to the first command, **instead of** the plain first command of step 3: an account
   that exists already was registered without the key:

   ```bash
   certbot certonly --server https://pki.homelab.lan/acme/directory --eab-kid KEY_ID --eab-hmac-key MAC_KEY -d nas.homelab.lan --standalone
   ```

   The key binds one account and expires (7 days by default), so use it once, for the first run.
   Without a key, the first run is refused with "waits for approval": approve the account in *ACME →
   Accounts* and run it again.

5. **Renewal.** certbot renews a certificate 30 days before it expires. Look for the timer:

   ```bash
   systemctl list-timers
   ```

   Be careful with a dry run (`certbot renew --dry-run`). The server cannot tell it from a real renewal:
   it issues a certificate that certbot throws away, and the tenant's predecessor rule then retires the
   certificate you use, because the account and the names are the same. By default that revocation
   comes after seven days ([Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }})). On a
   production host skip the dry run and watch the first real renewal, or ask an admin to set the
   predecessor policy of this account to *never* first.

   The packages of most distributions install a timer or a cron job that runs `certbot renew`; check
   that yours does. The server's default lifetime is 90 days.

6. **Reload nginx after a renewal.** A deploy hook runs only when a certificate was renewed. As a
   one-off option of the first issue (certbot stores it for later renewals):

   ```bash
   certbot certonly --server https://pki.homelab.lan/acme/directory --webroot -w /var/www/acme -d nas.homelab.lan --deploy-hook "systemctl reload nginx"
   ```

   Point nginx at the files certbot keeps under `/etc/letsencrypt/live/nas.homelab.lan/`:

   ```nginx
   ssl_certificate     /etc/letsencrypt/live/nas.homelab.lan/fullchain.pem;
   ssl_certificate_key /etc/letsencrypt/live/nas.homelab.lan/privkey.pem;
   ```

   `fullchain.pem` is the certificate plus the intermediates, without the root; the root is the client's
   anchor.

## Check it worked

```bash
certbot certificates
```

```bash
openssl verify -CAfile homelab-root.pem -untrusted /etc/letsencrypt/live/nas.homelab.lan/fullchain.pem /etc/letsencrypt/live/nas.homelab.lan/fullchain.pem
```

In the UI, *ACME → Orders* shows the order as *valid* with a link to the certificate, and the
certificate page shows the issuing CA and the names. Renewal needs no setup on the server
([Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }})).

## When it fails

| certbot says | Usually | See |
|---|---|---|
| A TLS error, unknown authority, `CERTIFICATE_VERIFY_FAILED` | certbot does not trust your root | Step 2; [§10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients) |
| `rejectedIdentifier: no domain covers …` | No domain for that name | *ACME → Domains* |
| `unauthorized: account … waits for approval` | Approval level *approved accounts* | *ACME → Accounts*, or an EAB key |
| `connection: … could not be reached` | Port 80 of the client is closed for the PKI server, or the name resolves elsewhere | [Split DNS]({{ '/guides/split-dns/' | relative_url }}) |
| `incorrectResponse: … answered with status 404` | The web server does not serve the challenge directory | Use standalone, or fix the webroot |
| `rateLimited` | A limit of the tenant settings | Wait for `Retry-After` |

The complete table is
[§10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails); more in
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- Wildcard names need dns-01. The server supports it, and so does the **agent** since v0.3.7
  ([dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }})). With certbot you can use a DNS
  plug-in of certbot itself; see
  [§10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).
- Use **one account per host**: hosts that share an account and the same names retire each other's
  certificates ([§10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)).
- Revoke a certificate from the client with `certbot revoke --cert-path …`
  ([Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }})).
- Other clients: [acme.sh]({{ '/guides/acme-sh/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}).
