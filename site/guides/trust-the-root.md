---
title: "Make clients trust your root"
description: "Verify the root's fingerprint, then install the root on Windows, macOS, iPhone, Android, Linux, Firefox and Java, and give it to single programs such as curl."
permalink: /guides/trust-the-root/
sources:
  - docs/OPERATIONS.md (10.4, 11, 11.1)
  - internal/web/pages/trust/trust.templ
  - internal/web/app_pki.go
---

A client trusts your certificates only after it trusts the **root CA** above them. You install the
root once per device or program; intermediates need no installation because servers send them along.
This guide verifies the root first, then goes through the platforms.

* TOC
{:toc}

## When to use this

- A browser, phone or tool warns about a certificate your PKI issued ("unknown authority").
- You set up a new device, server or program that should talk to hosts with your certificates.
- An ACME client or the agent must trust the server's own certificate (see
  [operations guide §10.4]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients)).

## 1. Compare the fingerprint first

A root is the anchor every check ends at. Whoever slips you a false root can impersonate every
website for you. The public trust page comes over plain HTTP, because it must work before anything
trusts your PKI, so someone in the network path could replace the file. The **SHA-256 fingerprint** is
the check: compare it with a value you got another way.

1. Sign in to the admin UI and open *Certificate authorities*, then the root. The page shows the
   SHA-256 fingerprint (authoritative) and, for a Windows dialog only, the SHA-1 fingerprint.
2. Download the root. The base URL is the public listener (`:8080` by default, `:80` behind a proxy
   or with `--public-port-80`):

   ```bash
   curl -o homelab-root.crt http://pki.homelab.lan/ca/root/1.crt
   ```

   The file is DER. The URL is `/ca/<root name>/<generation>.crt`; the PEM copy ends in `.pem`.
3. Print its fingerprint and compare it with the UI, character by character:

   ```bash
   openssl x509 -inform DER -in homelab-root.crt -noout -fingerprint -sha256
   ```

4. If a platform below needs PEM, convert once:

   ```bash
   openssl x509 -inform DER -in homelab-root.crt -out homelab-root.pem
   ```

## 2. The trust page of this server

The public listener serves a page at `/` (for example `http://pki.homelab.lan/`) that anyone may open
without signing in. Send people there instead of mailing root files. It shows:

- every active CA, roots first, with name, common name, validity and the SHA-256 fingerprint;
- downloads as DER and PEM;
- for each root two Windows helpers (`.cmd`): *this computer* and *my user only*;
- short guides for Windows, macOS, iPhone and iPad, Android, Linux and Firefox, with the file names
  filled in.

It contains only public data and no JavaScript. An administrator can switch it off in
*Administration → Tenant settings* (*Public trust page*); the CA certificates and CRLs stay served
([operations guide §11]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page)).

## 3. Install the root

### Windows

The helper on the trust page imports the root into *Trusted Root Certification Authorities*. It shows
the SHA-256 and requires either `-ExpectedSha256 <64 hex digits>` that you took from the admin UI, or
an interactive `YES` after your own comparison. *This computer* asks for administrator rights; *my user
only* does not. `/check` only displays and never imports. Windows may warn about a downloaded `.cmd`;
that is normal ([operations guide §11.1]({{ '/reference/operations/' | relative_url }}#111-the-windows-helpers)).
By hand, in a command prompt as administrator:

```bat
certutil -addstore -f Root homelab-root.crt
```

For your own user only, add `-user` after `certutil`. Distributing the root to many Windows machines
with Group Policy is common practice, but this documentation does not describe it, so it is not
covered here.

### macOS

Double-click the `.crt` and add it to the *System* keychain. Then open the certificate in Keychain
Access, expand *Trust*, set *When using this certificate* to *Always Trust* and confirm with your
password (Safari, Chrome and Edge use this keychain). Or in Terminal:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain homelab-root.crt
```

### iPhone and iPad

1. Open the trust page in **Safari**, tap the root's download and allow the configuration profile.
2. In *Settings* tap *Profile Downloaded* (or *General → VPN & Device Management*), choose the profile
   and tap *Install*.
3. Open *Settings → General → About → Certificate Trust Settings* and switch on full trust for the
   root. **Without this step** iOS installs the root but does not trust it for websites.

Menu names change between iOS versions.

### Android

Download the `.crt`, then open *Settings → Security and privacy → More security settings → Encryption
and credentials → Install a certificate → CA certificate* and choose the file. The path differs
between vendors and Android versions. Chrome trusts a CA installed this way; **many apps do not**,
because apps may ignore the user store. A device management (MDM) system can install the root for all
apps.

### Debian and Ubuntu

The file must be PEM and end in `.crt`:

```bash
sudo cp homelab-root.pem /usr/local/share/ca-certificates/homelab-root.crt
```

```bash
sudo update-ca-certificates
```

### Fedora, RHEL, Rocky, Alma

```bash
sudo cp homelab-root.pem /etc/pki/ca-trust/source/anchors/
```

```bash
sudo update-ca-trust
```

curl, wget and many other programs use this system store. Some programs ship their own list (Python
`requests` is one, see the table at the end), and Firefox and Chrome on Linux may keep their own; see the
next section.

### Firefox

Firefox has its own store. Open *Settings → Privacy & Security → Certificates → View Certificates →
Authorities*, choose *Import*, select the `.crt` and tick *Trust this CA to identify websites*. On
Windows and macOS Firefox can use the system store instead: set `security.enterprise_roots.enabled` to
`true` in `about:config`. Managed machines can use Firefox enterprise policies; see Mozilla's documentation.

### Java

Java uses its own keystore, not the system store. Import the PEM into the `cacerts` file of the Java
installation that runs your program. The path and the default password (`changeit`) belong to the
Java distribution and may vary by version:

```bash
sudo keytool -importcert -trustcacerts -alias homelab-root -file homelab-root.pem -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit
```

### One program only

If you do not want to change a system store, point the program at the root:

| Program | How |
|---|---|
| curl | `curl --cacert homelab-root.pem https://…` |
| OpenSSL | `openssl s_client -CAfile homelab-root.pem -connect host:443` |
| Python requests, certbot | `REQUESTS_CA_BUNDLE=/path/homelab-root.pem` |
| lego | `LEGO_CA_CERTIFICATES=/path/homelab-root.pem` |
| acme.sh | `--ca-bundle /path/homelab-root.pem` |
| Caddy | `acme_ca_root` |
| Traefik | `LEGO_CA_CERTIFICATES` in its environment |

## Check it worked

From a client that should now trust the root, without `--cacert`:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://www.homelab.lan/
```

A status code means the TLS handshake passed. `curl: (60)` means the client still does not trust the
chain. In a browser, the padlock appears without a warning.

## When it fails

- **Browser still warns on iOS:** the *Certificate Trust Settings* switch is off.
- **Chrome or an app on Android warns:** the app may ignore user-installed roots; use MDM or a
  program-specific setting.
- **Firefox warns while Chrome does not:** Firefox reads its own store; import there or enable
  `security.enterprise_roots.enabled`.
- **Java program fails, curl works:** the root is not in that Java's `cacerts`.
- **`update-ca-certificates` ignores the file:** it must end in `.crt` and be PEM.
- **The fingerprints differ:** do not install. Get the root from the admin UI or your administrator.
- More symptoms: [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in) and
  [operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails).

## Next steps

- Issue a certificate and test it: [Installation]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).
- Learn how CAs are created and replaced, and what clients must do then: [CA lifecycle]({{ '/guides/ca-lifecycle/' | relative_url }}).
