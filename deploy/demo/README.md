# MyOwnPKI demo

A throwaway instance for trying MyOwnPKI out with Docker. Not for production: the instance is a
*demo instance* (it says so in the UI banner and in the log at every start), and every one of its
secrets is in one file.

**First act (about two minutes):** a server with a test CA, a domain, and `certbot` getting a
certificate for `www.demo.test` by http-01. **Second act (optional, one click):** nginx whose
certificate is deployed by `myownpki-agent`.

## What you need

- Docker with the compose plugin (`docker compose version`), on Linux or macOS
- `curl`, `openssl` (1.1.1 or newer; on macOS `brew install openssl`), `sed` and bash 3.2 or newer
- Ports: `127.0.0.1:9443` on this host. Nothing else is published, and nothing listens on a
  network address of the host.

The image tag in `docker-compose.yml` (`ghcr.io/der-felix/myownpki:0.3.11`) exists after the
release is published. Before that, or for a snapshot or local build, name your image:

```bash
cp .env.example .env
```

then set `MYOWNPKI_IMAGE` in `.env` (or in the environment).

## First act

```bash
./demo.sh run
```

`run` does these steps in order; each one can also be run alone:

| Command | What it does | What to look at afterwards |
|---|---|---|
| `./demo.sh up` | `myownpki init --demo --with-ca` once (a demo admin, a test root and an issuing CA, every secret into `init-demo-secrets.txt` in the data volume), then starts the server **sealed** and waits until it is healthy | `https://127.0.0.1:9443/` (a self-signed certificate; the banner says *DEMO instance*) |
| `./demo.sh unseal` | signs in with the password and the TOTP code from the secrets file and unseals through the API | *Dashboard*: the server is unsealed. The ACME listener now serves a certificate that the demo CA issued |
| `./demo.sh domain` | creates the domain `demo.test` (http-01 only, open approval, address policy `internal`). It needs a fresh second factor, which is why the script does it, not the compose file | *Domains* |
| `./demo.sh certbot` | starts a `certbot` container that answers to `www.demo.test`, fetches the root from the public listener, prints its SHA-256 and compares it with the root the authenticated API reports, then runs `certbot certonly --standalone` | *Certificates*: a certificate for `www.demo.test` |
| `./demo.sh verify` | checks the chain with `openssl verify` against the demo root, that the only name in the certificate is `www.demo.test`, and that the audit log has the issuance | *Audit log*: `certificate.issue` |

Sign in to the UI yourself with the admin user, the password and the TOTP secret from the secrets
file (add the secret to an authenticator app; its first code confirms it). The script never prints
them, so read the file on purpose:

```bash
docker compose -f docker-compose.yml cp myownpki:/var/lib/myownpki/init-demo-secrets.txt "$HOME/init-demo-secrets.txt"
```

Keep that copy outside the repository and delete it when you are done. Why does a script read the passphrase from a file? The server
itself never does: a production instance is unsealed by a person. A demo instance is marked as one
for good, so the demo script may do what you would do at the keyboard. Do not copy the pattern to a
real instance.

## Second act: nginx and the agent

Needs the first act (the agent trusts the root that `certbot` fetched).

```bash
./demo.sh agent
```

It creates the agent CA (an intermediate with the key usage `clientAuth` only), restarts the server
with the agent listener (it starts sealed again, and the script unseals it), and builds and starts
`web`: nginx with `myownpki-agent` from the exact release's own verified package (taken from the
server image and checked against its `checksums.txt`). The agent enrolls as `web.demo.test`. Then one
click is left: *Agents -> Enrollment requests*, **Approve** `web.demo.test`. The agent gets its
certificate, orders one for `web.demo.test` by http-01 and deploys it to nginx, which reloads
(`nginx -t` and `nginx -s reload` are its hooks). Watch it in *Agents* and with `./demo.sh logs`.

This act is not part of the CI check; it is a live test.

## Clean up

```bash
./demo.sh down
```

removes the containers, the network and **all demo volumes** (the CA keys, the secrets file and the
certificates). Nothing is left on the host; `docker volume ls` should show no `myownpki-demo_*`.

## What is in here

| File | What |
|---|---|
| `docker-compose.yml` | project `myownpki-demo` with its own network and volumes; nothing is shared with `deploy/docker-compose.yml`. The server runs `read_only` with `cap_drop: [ALL]` and `no-new-privileges`; only the UI is published, on `127.0.0.1`. Third-party images are pinned by digest |
| `config.yaml` | the server configuration of the demo: ACME with its own TLS (`acme.tls_issuer: issuing`) at `https://acme.demo.test:8443/acme` on the demo network |
| `demo.sh` | the commands above |
| `certbot/run.sh` | what runs inside the certbot container |
| `web/` | the build of the second act |
| `.env.example` | `MYOWNPKI_IMAGE` |

Names such as `www.demo.test` exist only inside the demo network (Docker's DNS answers them). The
admin certificate is self-signed; `demo.sh` connects to `127.0.0.1` without checking it, which is
fine on one host and nothing to copy elsewhere.

## If something fails

- `./demo.sh logs` shows the server, certbot and web logs. They hold no secrets.
- `unseal` or `domain` ask for a second factor; a TOTP code works once, so the script may wait up to
  30 seconds for the next one. That is normal.
- The tag does not exist yet: set `MYOWNPKI_IMAGE` (see above).
- A start from scratch: `./demo.sh down`, then `./demo.sh run`.
