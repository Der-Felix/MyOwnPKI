---
title: "Put MyOwnPKI behind a reverse proxy"
description: "Publish the MyOwnPKI ACME server and the public listener through nginx, Caddy or Traefik: what the proxy must pass, the listener overview, the proxy's own certificate and a test."
permalink: /guides/reverse-proxies/
sources:
  - docs/OPERATIONS.md
  - site/install.md
  - internal/publish/publish.go
---

## When to use this

By default the ACME server speaks plain HTTP on `127.0.0.1:8081` and is meant for a reverse proxy that
ends TLS. Use this guide when ACME clients should reach it as `https://pki.homelab.lan/acme/` and
certificates should point to `http://pki.homelab.lan/` for CRLs and CA certificates. The full examples
for nginx, Caddy and Traefik are in
[operations guide §10.3]({{ '/reference/operations/' | relative_url }}#103-proxy-examples); this page is the
task view. If you would rather have no proxy at all, ACME can use its own TLS
([§10.10]({{ '/reference/operations/' | relative_url }}#1010-without-a-reverse-proxy-acme-with-its-own-tls)).

* TOC
{:toc}

## What goes where

| Listener | Default | Through the proxy? |
|---|---|---|
| Admin (UI and REST API), HTTPS | `127.0.0.1:9443` (`install.sh` writes `0.0.0.0:9443` with `admin.allowed_networks`) | No. The examples do not publish it; keep it for administrators ([Installation]({{ '/install/' | relative_url }}#what-runs-where)) |
| Public (CRLs, CA certificates, trust page), plain HTTP | `:8080` | Yes, as `http://pki.homelab.lan/` on port 80, **without** a redirect to HTTPS |
| ACME, plain HTTP | `127.0.0.1:8081` | Yes, as `https://pki.homelab.lan/acme/` on port 443 |
| Agents, mutual TLS | `:8444` | Not in the examples; the agent listener speaks mutual TLS itself ([Adding hosts]({{ '/hosts/' | relative_url }})) |

Certificates contain the plain `http://` address of their CRL and of their issuer, and clients fetch
those before they trust anything. A redirect to HTTPS on that port would break revocation checks on
some clients.

## Steps

1. **Set the ACME keys** in `/etc/myownpki/config.yaml`:

   ```yaml
   acme:
     base_url: https://pki.homelab.lan/acme
     listen: 127.0.0.1:8081
     trusted_proxies: "127.0.0.1, ::1"
     resolver: 192.0.2.53
   ```

   `base_url` is the address clients use, with the path; every URL the server hands out is built from it.
   The server never trusts `X-Forwarded-Host` or `X-Forwarded-Proto`. `trusted_proxies` lists who may
   connect to the ACME listener; everybody else gets 403. `resolver` is for split DNS
   ([Split DNS]({{ '/guides/split-dns/' | relative_url }})). Check, restart and unseal:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml
   ```

   ```bash
   systemctl restart myownpki
   ```

2. **Get the proxy's own certificate** ([§10.2]({{ '/reference/operations/' | relative_url }}#102-the-proxys-own-certificate)).
   On the proxy host make a key and a request; the key never leaves it:

   ```bash
   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout pki.homelab.lan.key -out pki.homelab.lan.csr -subj "/CN=pki.homelab.lan" -addext "subjectAltName=DNS:pki.homelab.lan"
   ```

   Issue it with the preset *server* ([first certificate in the UI]({{ '/guides/first-certificate-ui/' | relative_url }})),
   download the fullchain, and save it as `pki.homelab.lan.fullchain.pem` next to the key. This certificate
   renews **by hand** (a calendar entry, or *Expiring soon* on the dashboard), unless Caddy or Traefik
   fetch it themselves as ACME clients of your own CA
   ([Traefik and Caddy]({{ '/guides/traefik-caddy/' | relative_url }})).

3. **Configure the proxy.** Whatever the product, it must do these things:

   - serve `/acme/` over TLS with the proxy's certificate and forward it to `127.0.0.1:8081` **with the path
     unchanged** (`/acme/...` stays `/acme/...`);
   - serve port 80 as plain HTTP and forward it to `127.0.0.1:8080`;
   - send the client's address in `X-Forwarded-For`. The server believes that header only from an address
     in `trusted_proxies` and takes the last entry that is not a trusted proxy, so a client cannot fake
     its address for the rate limits and the audit log.

   nginx, as in the operations guide:

   ```nginx
   server {
       listen 443 ssl;
       server_name pki.homelab.lan;
       ssl_certificate     /etc/nginx/pki/pki.homelab.lan.fullchain.pem;
       ssl_certificate_key /etc/nginx/pki/pki.homelab.lan.key;

       location /acme/ {
           proxy_pass http://127.0.0.1:8081;   # no URI after the port: the path stays /acme/…
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }

   server {
       listen 80;
       server_name pki.homelab.lan;
       location / {
           proxy_pass http://127.0.0.1:8080;   # CRLs and CA certificates
       }
   }
   ```

   The two traps are in the comments. With nginx, write `proxy_pass` **without** a path after the port; with
   Caddy use `handle`, **not** `handle_path`. The Caddy and Traefik examples are in
   [§10.3]({{ '/reference/operations/' | relative_url }}#103-proxy-examples).

4. **A proxy in a container.** `127.0.0.1` is then the container itself. Let MyOwnPKI listen where the proxy
   can reach it (`acme.listen: 0.0.0.0:8081`, as in the Docker example), and put the container network into
   `acme.trusted_proxies` (the Docker example has `172.16.0.0/12`).

5. Test the proxy configuration, then reload it:

   ```bash
   nginx -t
   ```

   ```bash
   systemctl reload nginx
   ```

## Check it worked

From a machine that trusts your root ([§10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients)):

```bash
curl --cacert homelab-root.pem https://pki.homelab.lan/acme/directory
```

The answer lists `newAccount`, `newOrder`, `revokeCert` and `renewalInfo`, all under
`https://pki.homelab.lan/acme/`. The public listener answers on plain HTTP; 200 is the trust page, 404 means
the page is switched off, which is fine:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://pki.homelab.lan/
```

Fetch a CRL the way a client does. The URL is in every certificate (print it with
`openssl x509 -in certificate.pem -noout -ext crlDistributionPoints`):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://pki.homelab.lan/crl/issuing/1.crl
```

## When it fails

| What you see | Usually | What to do |
|---|---|---|
| 403 "reachable only through its reverse proxy" | The proxy's address is not in `acme.trusted_proxies` | Add it; with Docker the network, for example `172.16.0.0/12` |
| `/acme/directory` does not answer as in the check above | The proxy changed the path (`handle_path` in Caddy, a URI after the port in `proxy_pass`) | Pass the path unchanged |
| Clients report a TLS error, unknown authority | They do not trust your root | [§10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients) |
| URLs in the directory answer name the wrong host or port | `acme.base_url` does not match what clients use | Fix `base_url`; the proxy's headers are ignored on purpose |
| Clients start to warn on a setup that worked | The proxy's own certificate expired | Renew it ([§10.2]({{ '/reference/operations/' | relative_url }}#102-the-proxys-own-certificate)) |
| CRL checks fail on some clients | Port 80 redirects to HTTPS | Serve the public listener as plain HTTP |

More in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- Connect a first client: [Certbot]({{ '/guides/certbot/' | relative_url }}).
- Create the domain that allows names: [Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }}).
- Open only what is needed: the port table in [Installation]({{ '/install/' | relative_url }}#ports-and-firewall).
