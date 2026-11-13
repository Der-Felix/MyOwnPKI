---
title: "acme.sh with MyOwnPKI"
description: "Get and renew certificates from the MyOwnPKI ACME server with acme.sh: the server option, the root as CA bundle, an EAB key, installing the files and the renewal job."
permalink: /guides/acme-sh/
sources:
  - docs/OPERATIONS.md
  - docs/NIGHTLOG.md
---

## When to use this

Use acme.sh on hosts where a small shell client is easier than Python or Go: appliances, containers,
old distributions. Like certbot it asks for certificates and renews them; it does not report to the
server. For that use the agent ([Adding hosts]({{ '/hosts/' | relative_url }})).
The operations guide documents three things for acme.sh: `--server`, the EAB registration and
`--ca-bundle`
([§10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients),
[§10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)). Everything else on this
page is general acme.sh behavior; check `acme.sh --help` of your version.

* TOC
{:toc}

## Before you start

- The ACME server is on and a **domain** covers the name
  ([Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }})).
- Port 80 of this host is open for the PKI server, and the name resolves to this host from the PKI
  server ([Split DNS]({{ '/guides/split-dns/' | relative_url }})).
- You have the root as a PEM file, `homelab-root.pem`. How to fetch it and compare its fingerprint is in
  step 1 of the [Certbot guide]({{ '/guides/certbot/' | relative_url }}).
- The directory URL is `https://pki.homelab.lan/acme/directory`.

## Steps

1. **Issue** in standalone mode, with the root as CA bundle:

   ```bash
   acme.sh --issue --server https://pki.homelab.lan/acme/directory --ca-bundle /root/homelab-root.pem --standalone -d nas.homelab.lan
   ```

   acme.sh listens on port 80 itself during the check; the standalone mode needs `socat` on most
   systems. If a web server already uses port 80, use the webroot mode instead, with the directory
   from which the web server serves `/.well-known/acme-challenge/`:

   ```bash
   acme.sh --issue --server https://pki.homelab.lan/acme/directory --ca-bundle /root/homelab-root.pem --webroot /var/www/acme -d nas.homelab.lan
   ```

2. **With an EAB key.** Create the key in *ACME → EAB keys* (the key ID and the MAC key are shown once)
   and register the account first, then issue as above:

   ```bash
   acme.sh --register-account --server https://pki.homelab.lan/acme/directory --ca-bundle /root/homelab-root.pem --eab-kid KEY_ID --eab-hmac-key MAC_KEY
   ```

   Without a key, a domain with the approval level *approved accounts* refuses the first run with
   "waits for approval": approve the account in *ACME → Accounts*, then run the command again.

3. **Install** the files where the service reads them, and reload the service. `--install-cert` copies
   the files and remembers the reload command for the renewals:

   ```bash
   acme.sh --install-cert -d nas.homelab.lan --key-file /etc/nginx/pki/nas.homelab.lan.key --fullchain-file /etc/nginx/pki/nas.homelab.lan.fullchain.pem --reloadcmd "systemctl reload nginx"
   ```

   Point the service at these files, not at acme.sh's own directory. The fullchain file holds the
   certificate and the intermediates, without the root.

4. **Renewal.** The acme.sh installer adds a cron entry that renews certificates that are due. Look for
   it, and list what acme.sh manages:

   ```bash
   crontab -l
   ```

   ```bash
   acme.sh --list
   ```

   Test the renewal once. `--force` issues a new certificate even if the old one is far from its end:

   ```bash
   acme.sh --renew -d nas.homelab.lan --force
   ```

   A forced renewal is a real order. The previous certificate of the same account and the same names is
   retired by the tenant's predecessor rule (after seven days by default; see
   [Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }})).

## Check it worked

```bash
openssl verify -CAfile /root/homelab-root.pem -untrusted /etc/nginx/pki/nas.homelab.lan.fullchain.pem /etc/nginx/pki/nas.homelab.lan.fullchain.pem
```

*ACME → Orders* in the UI lists the order as *valid* with a link to the certificate. After a renewal the
service must present the new file: compare the serial the service serves with the file:

```bash
openssl s_client -connect nas.homelab.lan:443 -servername nas.homelab.lan -CAfile /root/homelab-root.pem </dev/null 2>/dev/null | openssl x509 -noout -serial -enddate
```

## When it fails

| acme.sh says or does | Usually | See |
|---|---|---|
| A TLS or "certificate verify" error against the server | The root is not trusted | `--ca-bundle` as above; [§10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients) |
| `rejectedIdentifier: no domain covers …` | No domain covers the name | *ACME → Domains* |
| `unauthorized: account … waits for approval` | Approval level *approved accounts* | *ACME → Accounts*, or an EAB key |
| `connection: … could not be reached` | Port 80 closed for the PKI server, or the name resolves elsewhere | [Split DNS]({{ '/guides/split-dns/' | relative_url }}) |
| The standalone mode cannot start | `socat` is missing, or another program holds port 80 | Install `socat`, or use the webroot mode |
| `rateLimited` | A tenant limit | Wait for `Retry-After` |

Every message is explained in
[§10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails) and in
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- Does the renewal job find the CA bundle? Run `acme.sh --cron` by hand once and read its output. If
  it cannot reach the server, give `--ca-bundle` again or put the root into the system store.
- DNS validation for wildcard names (*dns-01*) works on the server. The MyOwnPKI **agent** can do it too since
  v0.3.7 ([dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }})); acme.sh has its own DNS modes;
  see its documentation and
  [§10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).
- Other clients: [certbot]({{ '/guides/certbot/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}).
- Revoke or replace a certificate: [Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }}).
