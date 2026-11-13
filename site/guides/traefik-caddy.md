---
title: "Traefik and Caddy as ACME clients"
description: "Let Traefik or Caddy get and renew their certificates from the MyOwnPKI ACME server: the CA address, trusting the root, the HTTP challenge and renewal."
permalink: /guides/traefik-caddy/
sources:
  - docs/OPERATIONS.md
  - docs/NIGHTLOG.md
---

## When to use this

Use this when Traefik or Caddy already terminates TLS for your internal services and should get those
certificates from your own CA instead of Let's Encrypt. Both are ACME clients: once they know the CA's
address and trust its root, they obtain and renew certificates by themselves.

This page separates two kinds of statements. **Documented** means the operations guide
([§10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)) gives exactly this setting.
**General behavior** means how Traefik or Caddy normally work, written here so that the example is complete;
check it against the documentation of your version. The project's tests (CI) run lego, certbot and acme.sh
against the server; Traefik and Caddy as ACME clients are documented but were not tested
([release notes]({{ '/reference/changelog/' | relative_url }})). To put Traefik or Caddy *in front of* MyOwnPKI, see
[Reverse proxies]({{ '/guides/reverse-proxies/' | relative_url }}).

* TOC
{:toc}

## Before you start

- The ACME server is on and a **domain** covers the names the proxy serves
  ([Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }})).
- Port 80 of the proxy host is open for the PKI server: the server connects there to check the HTTP
  challenge ([Split DNS]({{ '/guides/split-dns/' | relative_url }})).
- You have the root as a PEM file on the proxy host, for example `/etc/caddy/homelab-root.pem` or
  `/etc/traefik/homelab-root.pem`; step 1 of the [Certbot guide]({{ '/guides/certbot/' | relative_url }}) shows
  how to fetch and check it.
- The directory URL is `https://pki.homelab.lan/acme/directory`.

## Caddy

1. **Documented.** Set the CA and its root in the global options of the `Caddyfile`:

   ```
   {
       acme_ca https://pki.homelab.lan/acme/directory
       acme_ca_root /etc/caddy/homelab-root.pem
   }
   ```

2. **General behavior.** A site block with the host name is enough; Caddy asks for the certificate
   itself, serves port 80 for the challenge and redirects to HTTPS:

   ```
   nas.homelab.lan {
       reverse_proxy 192.0.2.20:8080
   }
   ```

3. Check the file and reload Caddy:

   ```bash
   caddy validate --config /etc/caddy/Caddyfile
   ```

   ```bash
   systemctl reload caddy
   ```

4. **Renewal.** Documented: Caddy supports ARI, so it asks the server when to renew. The window opens at
   about two thirds of the lifetime, and a revoked certificate gets a window in the past, so Caddy
   renews it at once. Nothing to set up.

## Traefik

1. **Documented.** The static configuration defines a resolver with the CA's address and the HTTP
   challenge on the entry point that listens on port 80:

   ```yaml
   certificatesResolvers:
     homelab:
       acme:
         caServer: https://pki.homelab.lan/acme/directory
         email: admin@homelab.lan
         storage: /etc/traefik/acme-homelab.json
         httpChallenge:
           entryPoint: web
   ```

2. **Documented.** Traefik reads the root from the variable
   `LEGO_CA_CERTIFICATES` in **its own environment** (Traefik uses the lego library for ACME). With
   systemd, put it into a drop-in
   (`systemctl edit traefik`):

   ```ini
   [Service]
   Environment=LEGO_CA_CERTIFICATES=/etc/traefik/homelab-root.pem
   ```

   In a container, pass it with `-e` or `environment:` and mount the PEM file into the container.

3. **General behavior.** A router asks for a certificate through the resolver. In the dynamic
   configuration:

   ```yaml
   http:
     routers:
       nas:
         rule: "Host(`nas.homelab.lan`)"
         entryPoints: [websecure]
         service: nas
         tls:
           certResolver: homelab
     services:
       nas:
         loadBalancer:
           servers:
             - url: "http://192.0.2.20:8080"
   ```

4. Restart Traefik so that it reads the environment, then watch its log for the first order:

   ```bash
   systemctl restart traefik
   ```

   ```bash
   journalctl -u traefik -n 50 --no-pager
   ```

5. **Renewal** is Traefik's own: it renews certificates before they expire and keeps them in the
   `storage` file. The operations guide does not document its timing or ARI for Traefik. Watch the
   expiry in the UI (*Expiring soon* on the dashboard) until you have seen one renewal.

Both tools can also use an EAB key when the domain asks for approval. Create it in *ACME → EAB keys*; the
option names are in the documentation of each tool and are not in the operations guide. Without a key the
first order waits until an admin approves the account in *ACME → Accounts*.

## Check it worked

```bash
curl --cacert homelab-root.pem -sS -o /dev/null -w '%{http_code}\n' https://nas.homelab.lan/
```

```bash
openssl s_client -connect nas.homelab.lan:443 -servername nas.homelab.lan -CAfile homelab-root.pem </dev/null 2>/dev/null | openssl x509 -noout -issuer -serial -enddate
```

The issuer is your CA. In the UI, *ACME → Orders* lists the order as *valid* with a link to the certificate.

## When it fails

| What you see | Usually | See |
|---|---|---|
| `x509: certificate signed by unknown authority` in the Traefik log | `LEGO_CA_CERTIFICATES` is not in Traefik's environment, or points to the wrong file | Step 2 of Traefik |
| The same kind of error in the Caddy log | `acme_ca_root` is missing or unreadable by the Caddy user | Step 1 of Caddy |
| `rejectedIdentifier: no domain covers …` | No domain covers the name | *ACME → Domains* |
| `unauthorized: account … waits for approval` | Approval level *approved accounts* | *ACME → Accounts*, or an EAB key |
| `connection: … could not be reached` | Port 80 of the proxy is closed for the PKI server, or the name resolves elsewhere | [Split DNS]({{ '/guides/split-dns/' | relative_url }}) |
| `incorrectResponse: … answered with status 404` | The challenge request did not reach Caddy or Traefik, for example a load balancer in front | Pass `/.well-known/acme-challenge/` through |

The complete table is
[§10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails); more in
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- Wildcard certificates need dns-01 and a DNS plug-in of the proxy; the server supports it. The MyOwnPKI
  **agent** can do dns-01 since v0.3.7 ([dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }})).
- The proxy that fronts MyOwnPKI itself needs a certificate before any client can talk ACME, so the first one
  comes by hand: [Reverse proxies]({{ '/guides/reverse-proxies/' | relative_url }}).
- Other clients: [certbot]({{ '/guides/certbot/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}).
