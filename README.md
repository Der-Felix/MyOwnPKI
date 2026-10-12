# MyOwnPKI

**Your own PKI – self-hosted, automated, from homelab to enterprise.**

> **Status: planning.** There is no runnable server yet. See [docs/PLAN.md](docs/PLAN.md) for
> the architecture, decisions and roadmap.

MyOwnPKI is a self-hosted certificate authority platform:

- **Secure web UI** with dashboards, upload/download and role-based access
- **ACME server** for your internal CA – use certbot, acme.sh, Traefik, Caddy or win-acme
- **ACME client** for public certificates from Let's Encrypt / ZeroSSL (http-01, dns-01)
- **Optional agent** that deploys certificates to Linux, Windows and FreeBSD hosts, reloads
  services safely and monitors what is actually being served
- **Multiple domains and tenants**, policies per domain, audit log
- **Runs anywhere** as a single binary or container: Docker, Podman, LXC, Linux, macOS, Windows, FreeBSD

## Repository layout

| Path | Content |
|---|---|
| `docs/PLAN.md` | Project plan, architecture decisions (ADRs), roadmap |
| `legacy/` | The original Bash PKI suite (`pki.sh`) – still usable as an offline/air-gapped root CA tool |

## Legacy Bash suite

The predecessor of this project lives in [`legacy/`](legacy/README.md). It remains supported as an
offline tool for root CA ceremonies. Its full history is in the original
[pki_script](https://github.com/Der-Felix/pki_script) repository.

## License

[Apache License 2.0](LICENSE)
