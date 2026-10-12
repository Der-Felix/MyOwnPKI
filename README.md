# MyOwnPKI

**Your own PKI – self-hosted, automated, from homelab to enterprise.**

> **Status: phase 0 (foundation) complete.** The binaries build and the design system is
> visible, but there is no CA functionality yet – that is phase 1. See [docs/PLAN.md](docs/PLAN.md)
> for the architecture, decisions and roadmap.

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
| `cmd/` | The three binaries: `myownpki` (server), `myownpki-agent`, `myownpki-ctl` |
| `internal/ca/preset` | Loader and validation for certificate presets |
| `internal/web` | templ components, layouts and pages of the admin UI |
| `presets/` | Built-in certificate presets (YAML, ported from `legacy/lib/presets.sh`) |
| `api/openapi.yaml` | REST API specification (draft for phase 1) |
| `web/styles/` | Design tokens and the global CSS classes |
| `legacy/` | The original Bash PKI suite (`pki.sh`) – still usable as an offline/air-gapped root CA tool |

## Development

Requirements: Go (the exact toolchain is pinned in `go.mod` and downloaded automatically),
[Task](https://taskfile.dev) and [golangci-lint](https://golangci-lint.run) – versions in `Taskfile.yml`.
templ and govulncheck are pinned in `go.mod` and run via `go tool`. Works in PowerShell and Git Bash.

```sh
task              # list all tasks
task check        # everything that must pass before a commit
task dev          # component gallery at http://127.0.0.1:9443/design (no TLS, no login, loopback only)
task vuln         # known vulnerabilities in dependencies and the Go standard library
task cross        # build for linux/amd64, linux/arm64, darwin/arm64, windows/amd64, freebsd/amd64
```

## Legacy Bash suite

The predecessor of this project lives in [`legacy/`](legacy/README.md). It remains supported as an
offline tool for root CA ceremonies. Its full history is in the original
[pki_script](https://github.com/Der-Felix/pki_script) repository.

## License

[Apache License 2.0](LICENSE)
