# OpenSSL Homelab PKI Generator

[![Documentation](https://img.shields.io/badge/Docs-GitHub%20Pages-blue?style=flat&logo=github)](https://der-felix.github.io/pki_script/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenSSL 3.x](https://img.shields.io/badge/OpenSSL-3.x-green.svg)](https://www.openssl.org/)
[![Bash 4+](https://img.shields.io/badge/Bash-4.x%20%7C%205.x-blue.svg)](https://www.gnu.org/software/bash/)

> 📖 **Online Documentation & Interactive Guides**: [https://der-felix.github.io/pki_script/](https://der-felix.github.io/pki_script/)

A modular, production-hardened, and user-friendly Bash suite for creating and operating a complete, file-based Public Key Infrastructure (PKI) powered by **OpenSSL 3.x**.

```
             ┌─────────────────────────┐
             │         Root CA         │  (RSA 4096 / offline capable)
             └────────────┬────────────┘
                          │ signs
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌───────────────┐                   ┌───────────────┐
│   Server-CA   │                   │   Client-CA   │  (Intermediate CAs)
└───────┬───────┘                   └───────┬───────┘
        │                                   │
  ┌─────┴───────────────┐             ┌─────┴───────────────┐
  ▼                     ▼             ▼                     ▼
Web Server / Proxy   Proxmox / NAS     mTLS / 802.1X      VPN Clients
```

---

## 🌟 Highlights & Architecture

- **Clean Modular Design (`lib/`)**: Deconstructed from a monolithic 3,100-line script into 17 focused, testable modules (`ca.sh`, `issue.sh`, `crypto.sh`, `network.sh`, etc.).
- **Enhanced Usability**:
  - **Intuitive TUI Menu**: Structured into 4 operational categories (CA Management, Issuance, Operations, Maintenance) with quick hotkeys.
  - **1-Click Quick Mode (`quick`)**: Supply only a hostname or IP – FQDN, short aliases, and IP SANs are automatically discovered via DNS.
  - **Certificate Search (`search`)**: Lightning-fast lookup by name, domain, IP, status, or serial number.
  - **System Health Checks (`doctor`)**: Validates OpenSSL 3.x compatibility, filesystem permissions, network tools, and CA database integrity.
  - **Integrated Backup & Restore (`backup` / `restore`)**: Secure, permission-preserving tarball backups of the entire PKI repository.
  - **Comprehensive Tab Completion**: Full Bash completion for all subcommands, presets, certificate names, and CLI flags.
- **Automated Deployment Guides (`GUIDE.txt`)**: Every issued certificate includes auto-generated, copy-paste configurations tailored for **Nginx, Apache, Traefik, Caddy, HAProxy, Proxmox VE, TrueNAS, UniFi, Docker, OpenVPN, strongSwan, and Windows IIS**.
- **Real-World Templates (`examples/`)**: Pre-configured templates for 802.1X EAP-TLS, RADIUS, LDAPS / Active Directory, Hypervisors, Cluster Peers, mTLS, and VPNs.
- **Full Backward Compatibility**: The original `./gen-ca.sh` remains available as an automated wrapper for legacy pipelines.

---

## 📁 Repository Structure

```text
pki_script/
├── pki.sh                   # Main executable entrypoint
├── gen-ca.sh                # Backward-compatibility wrapper for legacy workflows
├── build.sh                 # Compiles lib/* into a standalone bundle
│
├── lib/                     # Modular functional libraries
│   ├── core.sh              # Terminal colors, logging, validation helpers
│   ├── config.sh            # Configuration parser and persistent settings
│   ├── crypto.sh            # OpenSSL abstraction and crypto primitives
│   ├── passwords.sh         # Passphrase handling, caching, encryption
│   ├── presets.sh           # 12 Certificate profiles (KU, EKU, SANs, days)
│   ├── ca.sh                # Root and Intermediate CA lifecycle management
│   ├── issue.sh             # End-entity certificate issuance and bundling
│   ├── csr.sh               # External CSR parsing and signing
│   ├── network.sh           # Hostname/IP auto-discovery and quick issuance
│   ├── operations.sh        # List, search, show, verify, renew, revoke & CRL
│   ├── export.sh            # PKCS#12 (.p12), legacy 3DES, DER & GUIDE.txt
│   ├── ocsp.sh              # OpenSSL OCSP responder daemon and checks
│   ├── batch.sh             # Configuration templates and batch issuance
│   ├── backup.sh            # Full archive backup and restore utilities
│   ├── doctor.sh            # Pre-flight environment diagnostics
│   ├── ui.sh                # Interactive TUI wizards and menu system
│   └── cli.sh               # CLI argument parser and command dispatcher
│
├── completions/
│   └── pki.bash             # Bash auto-completion script
├── examples/                # Ready-to-use configuration templates
│   ├── network-auth-8021x.conf # 802.1X EAP-TLS client WiFi / wired switch auth
│   ├── radius-server.conf      # RADIUS server authentication (FreeRADIUS/UniFi)
│   ├── webserver.conf          # TLS web server / reverse proxy
│   ├── hypervisor-nas.conf     # Proxmox VE / TrueNAS Web UI
│   ├── wildcard.conf           # Wildcard certificate (*.domain + domain)
│   ├── mtls-client.conf        # Mutual TLS client authentication
│   ├── openvpn-server.conf     # OpenVPN server gateway
│   ├── openvpn-client.conf     # OpenVPN client certificate (.ovpn inline)
│   ├── ipsec-ikev2.conf        # strongSwan / IPsec IKEv2 VPN server
│   ├── ldaps-active-directory.conf # LDAPS / Active Directory Domain Controller
│   ├── cluster-node.conf       # Dual Server+Client (etcd, SaltStack, K8s)
│   ├── smime-email.conf        # S/MIME email signing and encryption
│   └── code-signing.conf       # PowerShell and binary code signing
└── dist/
    └── pki-standalone.sh    # Single-file standalone build for air-gapped nodes
```

---

## 🚀 Quickstart

### 1. Interactive Menu
Launch without arguments:
```bash
./pki.sh
```

### 2. Initialize PKI via CLI (30 Seconds)
Creates a Root CA and two dedicated Intermediate CAs for servers and clients:
```bash
./pki.sh init --org "MyHomelab" --intermediate server-ca --intermediate client-ca
```

### 3. Issue a Server Certificate in 1 Click (`quick`)
Automatically resolves FQDN, short hostname, and all local IP addresses via DNS:
```bash
./pki.sh quick proxmox.homelab.lan
```

### 4. Verify Certificate Chain & Key Match
Validates full chain, CRL revocation status, purpose, and private key matching:
```bash
./pki.sh verify proxmox.homelab.lan --host proxmox.homelab.lan
```

---

## ⌨️ Command Line Reference

### 1. Infrastructure & Diagnostics
| Command | Description |
|---|---|
| `./pki.sh init [options]` | Initializes Root CA and optional Intermediate CAs |
| `./pki.sh ca-new <name> [options]` | Creates a new Intermediate CA (with Name Constraints, EKU limits) |
| `./pki.sh doctor` | Runs system diagnostics and pre-flight checks |

### 2. Certificate Issuance
| Command | Description |
|---|---|
| `./pki.sh quick <host>` | 1-Click server certificate with DNS auto-discovery |
| `./pki.sh issue <preset> --cn <name>` | Issues a certificate matching a defined profile |
| `./pki.sh selfsigned [preset] --cn <name>` | Generates a standalone self-signed certificate (no CA) |
| `./pki.sh sign-csr <file.csr> --preset server` | Signs an external CSR |

### 3. Inspection & Management
| Command | Description |
|---|---|
| `./pki.sh list` (or `ls`) | Overview of all CAs and issued certificates with expiry |
| `./pki.sh search <query>` | Filters certificates by name, CN, IP, SAN, or serial number |
| `./pki.sh show <name> [--full]` | Displays certificate details and extensions |
| `./pki.sh verify <name> [--host h]` | Comprehensive verification (Chain, CRL, host, key match) |
| `./pki.sh check [--days N]` | Expiry monitoring (Exit 0=ok, 2=objects expiring soon) |
| `./pki.sh guide <name>\|--all` | Regenerates deployment guides (`GUIDE.txt`) |

### 4. Lifecycle & Maintenance
| Command | Description |
|---|---|
| `./pki.sh renew <name> [--revoke-old]` | Renews a certificate reusing stored metadata |
| `./pki.sh renew-ca <ca>` | Renews a CA certificate retaining original private key |
| `./pki.sh revoke <name> [--reason r]` | Revokes certificate and updates CRL immediately |
| `./pki.sh crl [--ca name]` | Generates new Certificate Revocation Lists |
| `./pki.sh export <name> [--p12] [--der]` | Exports certificate as `.p12` (PKCS#12) or `.der` |
| `./pki.sh backup [file.tar.gz]` | Creates a secure, compressed backup archive of the PKI |
| `./pki.sh restore <file.tar.gz>` | Restores a PKI repository from a backup archive |

---

## 📋 Certificate Profiles (Presets)

Inspect profile details at any time with `./pki.sh presets`:

| Preset | Purpose | Primary Use Cases |
|---|---|---|
| `server` | TLS Web Server | Nginx, Apache, Traefik, Caddy, Proxmox, TrueNAS, UniFi |
| `wildcard` | TLS Wildcard | `*.domain.lan` + `domain.lan` in a single certificate |
| `client` | TLS Client Auth | mTLS, 802.1X EAP-TLS (WiFi/LAN switch port), browser login |
| `server-client` | Dual Purpose | Cluster nodes, etcd, Syslog TLS, MQTT, SaltStack |
| `user` | User Identity | Client authentication + S/MIME email signature combined |
| `vpn-server` | VPN Server | OpenVPN Server, strongSwan (IPsec/IKEv2) |
| `vpn-client` | VPN Client | OpenVPN Clients (`.ovpn`), native Windows/macOS IKEv2 |
| `smime` | Email Security | S/MIME email signing and encryption |
| `codesign` | Code Signing | PowerShell scripts, Windows binaries, Linux packages |
| `ocsp` | OCSP Signer | Signs responses for the built-in OCSP responder |
| `timestamp` | Time Stamping (TSA) | RFC 3161 digital timestamping authority |
| `custom` | Customizable | Custom keyUsage & extendedKeyUsage flags |

---

## 🛠️ Deployment in Homelab & Enterprise

Every issued certificate directory (`pki/issued/<name>/`) contains all necessary bundles:
- `key.pem`: Private key (permissions: `600`)
- `cert.pem`: Leaf certificate only
- `chain.pem`: Intermediate CA chain (without Root)
- `fullchain.pem`: Leaf + Intermediate CA (**standard for 95% of web servers**)
- `ca-bundle.pem`: Intermediate + Root CA (for client authentication / trust validation)
- `combined.pem`: Private key + fullchain in a single file (for HAProxy)
- `cert.p12`: PKCS#12 bundle with complete chain for Windows, macOS, Android, iOS
- `GUIDE.txt`: Ready-to-use copy-paste deployment guide

### Trusting the Root CA on Clients (Once per device)
Public CA certificates are published in `pki/publish/`:

- **Debian / Ubuntu / Proxmox**:
  ```bash
  sudo cp pki/publish/root.pem /usr/local/share/ca-certificates/homelab-root.crt
  sudo update-ca-certificates
  ```
- **RHEL / Rocky Linux / Fedora**:
  ```bash
  sudo cp pki/publish/root.pem /etc/pki/ca-trust/source/anchors/homelab-root.pem
  sudo update-ca-trust
  ```
- **Windows (PowerShell as Administrator)**:
  ```powershell
  Import-Certificate -FilePath .\pki\publish\root.crt -CertStoreLocation Cert:\LocalMachine\Root
  ```
- **macOS**:
  ```bash
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain pki/publish/root.pem
  ```

---

## 💡 Setting up Bash Completion

Enable tab completion in your shell:

```bash
# Temporary (current session):
source completions/pki.bash

# Permanent (system-wide on Linux):
sudo cp completions/pki.bash /etc/bash_completion.d/pki
```

---

## 🤖 Headless Automation (Cron, SaltStack, Ansible)

All interactive prompts and passphrases can be provided via environment variables:

```bash
# Nightly Cronjob checking expiry and renewing:
0 3 * * * PKI_CA_PASS="secret" /path/to/pki.sh check --days 30 || /path/to/pki.sh renew <name> --revoke-old -y
```

Supported environment variables:
- `PKI_DIR`: PKI repository directory (default: `./pki`)
- `PKI_CA_PASS`: Universal CA passphrase
- `PKI_CA_PASS_<NAME>`: CA-specific passphrase (e.g. `PKI_CA_PASS_SERVER_CA`)
- `PKI_KEY_PASS`: Passphrase for encrypted leaf keys
- `PKI_P12_PASS`: Passphrase for PKCS#12 exports
- `NO_COLOR=1`: Disables ANSI colors in logs

---

## 📦 Standalone Build (Single-File Distribution)

To distribute the entire suite as a single self-contained script to remote or air-gapped machines:

```bash
./build.sh
# Outputs: dist/pki-standalone.sh
```
