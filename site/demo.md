---
title: "Try the demo"
description: "A throwaway MyOwnPKI instance in Docker: a test CA, a domain and a certbot certificate in about two minutes, then optionally an nginx host that gets its certificate from the agent. What it needs, how to run it and how to remove it."
permalink: /demo/
sources:
  - deploy/demo/README.md
  - deploy/demo/demo.sh
  - deploy/demo/docker-compose.yml
---

The demo is a complete, disposable instance that you can start with Docker to see MyOwnPKI work before
you install anything. It is **not for production**: the instance is marked as a demo (the web UI says
so in a banner and the log says so at every start), and every one of its secrets is in one file.
When you are done, one command removes everything.

* TOC
{:toc}

## What it does

- **First act, about two minutes:** a server with a test root and an issuing CA, a domain named
  `demo.test`, and `certbot` in a container that gets a certificate for `www.demo.test` by http-01.
  A last step checks the chain with `openssl verify` and finds the issuance in the audit log.
- **Second act, optional, one click:** an nginx container whose certificate is deployed by
  `myownpki-agent`. The agent enrolls, you approve it in the web UI, and it orders its certificate,
  writes it for nginx and reloads.

The names `www.demo.test` and `web.demo.test` exist only inside the network that Docker creates for
the demo. Only the web UI is published, on `127.0.0.1:9443` of the host, with a self-signed certificate.

## What you need

- Docker with the compose plugin, version 2.20 or newer (`docker compose version`), on Linux or macOS.
- `curl`, `openssl` (1.1.1 or newer; on macOS `brew install openssl`), `sed` and bash 3.2 or newer.
- Port `127.0.0.1:9443` free on the host. Nothing else is published.

## Run it

The demo lives in `deploy/demo` of the repository. Take the files of the release you want to try:

```bash
git clone --depth 1 --branch "v{{ site.data.release.version }}" https://github.com/Der-Felix/MyOwnPKI.git
```

```bash
cd MyOwnPKI/deploy/demo
```

```bash
./demo.sh run
```

`run` starts the server, unseals it, creates the domain, runs certbot and checks the result. Each of
these steps (`up`, `unseal`, `domain`, `certbot`, `verify`) can also be run alone; the table in
[deploy/demo/README.md](https://github.com/Der-Felix/MyOwnPKI/blob/main/deploy/demo/README.md) says what
each does and what to look at in the web UI afterwards.

The image tag in `docker-compose.yml` is the release the files belong to. To try a snapshot or an
image you built yourself, copy `.env.example` to `.env` and set `MYOWNPKI_IMAGE` in it.

### Look at it in the browser

Open `https://127.0.0.1:9443/`. The browser warns about the certificate, which is self-signed; for a
demo on your own machine you can accept it. Sign in with the demo admin, whose password and TOTP
secret are in the secrets file. The scripts never print them, so copy the file out on purpose:

```bash
docker compose -f docker-compose.yml cp myownpki:/var/lib/myownpki/init-demo-secrets.txt "$HOME/init-demo-secrets.txt"
```

Add the TOTP secret to an authenticator app; its first code confirms it. Keep the copy outside the
repository, **never post it anywhere**, and delete it when you are done.

> **Note:** A script reads the unseal passphrase from a file only because this is a demo instance. The
> server itself never does that: a real instance is unsealed by a person. Do not copy the pattern.
{: .note}

## The second act

It needs the first act: the agent trusts the root that certbot fetched.

```bash
./demo.sh agent
```

The script creates an agent CA (an intermediate that may sign client certificates only), restarts the
server with the agent listener, unseals it again and starts `web`: nginx with `myownpki-agent`, taken
from the release's own package and checked against its `checksums.txt`. The agent enrolls as
`web.demo.test`. One click is left: *Agents → Enrollment requests*, **Approve** `web.demo.test`. The
agent then gets its certificate, orders one for `web.demo.test` by http-01, deploys it and reloads
nginx. Watch it in *Agents* and with `./demo.sh logs`. The second act is not checked by CI.

## Clean up

```bash
./demo.sh down
```

removes the containers, the network and **all demo volumes**: the CA keys, the secrets file and the
certificates. `docker volume ls` should then show no `myownpki-demo_*` volume.

## If something fails

- `./demo.sh logs` shows the server, certbot and web logs. They hold no secrets.
- `unseal` and `domain` ask for a second factor. A TOTP code works only once, so the script may wait up
  to 30 seconds for the next one. That is normal.
- The image tag does not exist (a release that is not published yet): set `MYOWNPKI_IMAGE` as above.
- To start from scratch, run `./demo.sh down`, then `./demo.sh run`.

When you have seen enough, [install it for real]({{ '/install/' | relative_url }}), or read how the
[first certificate in the web UI]({{ '/guides/first-certificate-ui/' | relative_url }}) goes.
