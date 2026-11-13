---
title: "lego with MyOwnPKI"
description: "Get and renew certificates from the MyOwnPKI ACME server with lego: trust the root with LEGO_CA_CERTIFICATES, the first run, an EAB key, ARI renewal and revocation."
permalink: /guides/lego/
sources:
  - docs/OPERATIONS.md
  - docs/NIGHTLOG.md
  - internal/web/app_acme.go
---

## When to use this

Use lego when you want a single static binary without Python, or when you already use a tool that
embeds lego (Traefik does; see [Traefik and Caddy]({{ '/guides/traefik-caddy/' | relative_url }})). lego
supports ARI: it asks the MyOwnPKI server when to renew, and renews at once when a certificate was
revoked ([§10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)). The commands below
are the ones of the operations guide and of the project's own test runs; lego changes its command line
between major versions, so check `lego run --help` for yours.

* TOC
{:toc}

## Before you start

- The ACME server is on and a **domain** covers the name
  ([Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }})).
- Port 80 of this host is open for the PKI server, and the name resolves to this host from the PKI
  server ([Split DNS]({{ '/guides/split-dns/' | relative_url }})).
- You have the root as a PEM file, `homelab-root.pem`; see step 1 of the
  [Certbot guide]({{ '/guides/certbot/' | relative_url }}) for how to fetch and check it.
- The directory URL is `https://pki.homelab.lan/acme/directory`.

## Steps

1. Tell lego which root to trust. lego reads the variable `LEGO_CA_CERTIFICATES`:

   ```bash
   export LEGO_CA_CERTIFICATES=/root/homelab-root.pem
   ```

2. **First run.** lego's built-in web server answers the challenge on port 80 (`--http`). `--path` says
   where lego keeps the account and the certificates; without it lego uses `.lego` in the current
   directory.

   ```bash
   lego run --server https://pki.homelab.lan/acme/directory --path /var/lib/lego --email admin@homelab.lan --accept-tos --domains nas.homelab.lan --http
   ```

   If a web server already uses port 80, give lego a webroot instead of `--http` (check
   `lego run --help` for the exact option name of your version): the web server must serve
   `/.well-known/acme-challenge/` from that directory.

3. **Approval.** With the approval level *approved accounts* the first run stops with "waits for
   approval". In the UI the dashboard says that one ACME account waits: open *ACME → Accounts*, choose
   the account, *Approve account* (this asks for your second factor), and run the **same command**
   again. It then gets the certificate.

4. **With an EAB key.** Create the key in *ACME → EAB keys* (the key ID and the MAC key are shown once,
   together with a ready-made lego command). Use a fresh `--path`, because the key binds a new account:

   ```bash
   lego run --server https://pki.homelab.lan/acme/directory --path /var/lib/lego-eab --email admin@homelab.lan --accept-tos --domains nas.homelab.lan --http --eab --eab.kid KEY_ID --eab.hmac MAC_KEY
   ```

5. **Where the files are.** Below the path lego writes the certificate, the issuer certificate and the
   key:

   ```bash
   ls /var/lib/lego/certificates
   ```

   You find `nas.homelab.lan.crt`, `nas.homelab.lan.issuer.crt` and `nas.homelab.lan.key`. The project's
   own check uses the `.crt` as the certificate and the `.issuer.crt` as the intermediates.

6. **Renewal.** With ARI the server tells lego when the window opens: about two thirds of the lifetime
   (day 60 to 63 of 90) and nine days long. In the project's test runs, repeating the same `lego run`
   command did **not** renew while the window was ahead, and renewed at once after a revocation. So
   the renewal job is that same command, on a schedule you set up yourself (a systemd timer or
   cron), followed by your reload command. In an older lego the renewal is a separate command:
   `lego renew --help` shows it.

## Check it worked

```bash
openssl verify -CAfile /root/homelab-root.pem -untrusted /var/lib/lego/certificates/nas.homelab.lan.issuer.crt /var/lib/lego/certificates/nas.homelab.lan.crt
```

*ACME → Orders* lists the order as *valid* with a link to the certificate. Run the command of step 2
again: while the renewal window is ahead the certificate, and so its serial, stays the same:

```bash
openssl x509 -in /var/lib/lego/certificates/nas.homelab.lan.crt -noout -serial -enddate
```

## Revoke

The project's test runs revoke with the same account directory and the certificate name:

```bash
lego certificates revoke --server https://pki.homelab.lan/acme/directory --path /var/lib/lego --email admin@homelab.lan --cert.name nas.homelab.lan --reason 4 --keep
```

`--reason 4` is the RFC 5280 reason *superseded*; `--keep` is lego's option for what happens to its
local files afterwards (see `lego certificates revoke --help`). The server signs the CRL at once ([Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }})).

## When it fails

| lego says | Usually | See |
|---|---|---|
| `x509: certificate signed by unknown authority` | `LEGO_CA_CERTIFICATES` is not set where lego runs (a timer does not see your shell) | Step 1 |
| `rejectedIdentifier: no domain covers …` | No domain covers the name | *ACME → Domains* |
| `unauthorized: account … waits for approval` | Approval level *approved accounts* | Step 3, or an EAB key |
| `connection: … could not be reached` | Port 80 closed for the PKI server, or the name resolves elsewhere | [Split DNS]({{ '/guides/split-dns/' | relative_url }}) |
| `incorrectResponse: … answered with status 404` | Another program answers port 80 and does not serve the challenge | Use the webroot mode, or free the port |
| `rateLimited` | A tenant limit | Wait for `Retry-After` |

The complete table is
[§10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails); more in
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- DNS validation (dns-01, for wildcard names) exists on the server; lego has many DNS providers of its
  own. The **agent** does dns-01 too since v0.3.7 for RFC 2136 and Cloudflare
  ([dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }})). See
  [§10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).
- Use one account (one `--path`) per host: hosts that share an account and the same names retire each
  other's certificates.
- Other clients: [certbot]({{ '/guides/certbot/' | relative_url }}), [acme.sh]({{ '/guides/acme-sh/' | relative_url }}).
