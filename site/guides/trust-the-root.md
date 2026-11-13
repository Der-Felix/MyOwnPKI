---
title: "Make clients trust your root"
description: "Hand the root to your devices with the trust portal, or by hand: verify the root's fingerprint, then install it on Windows, macOS, iPhone, Android, Linux, Firefox and Java, and give it to single programs such as curl."
permalink: /guides/trust-the-root/
sources:
  - docs/OPERATIONS.md (10.4, 11, 11.1, 12.12)
  - internal/web/pages/trust/trust.templ
  - internal/trustkit/guide.go
  - internal/web/app_pki.go
---

A client trusts your certificates only after it trusts the **root CA** above them. You install the
root once per device or program; intermediates need no installation because servers send them along.
Since v0.3.9 the [trust portal]({{ '/trust-portal/' | relative_url }}) of your server does most of it: send people to
its address, [section 2](#2-the-trust-portal-of-this-server). The steps by hand follow in section 3.
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
website for you. The public trust portal comes over plain HTTP, because it must work before anything
trusts your PKI, so someone in the network path could replace the file. The **SHA-256 fingerprint** is
the check: compare it with a value you got another way.

1. Sign in to the admin UI and open *Certificate authorities*, then the root. The page shows the
   SHA-256 fingerprint (authoritative) and, for a Windows dialog only, the SHA-1 fingerprint. On the
   server, `myownpki ca show NAME` prints the SHA-256 of every generation.
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

## 2. The trust portal of this server

The quickest way to hand the root to people and devices is the **trust portal** (since v0.3.9; before that
it was a simpler trust page). The public listener serves it at `/` (for example `http://pki.homelab.lan/`)
and anyone may open it without signing in. Send people there instead of mailing root files. It shows:

- every active CA, roots first, with name, common name, validity and the SHA-256 fingerprint, and downloads
  as DER and PEM;
- **your system**: the page guesses it from the browser and lets the visitor choose another one
  (`/?os=windows`, `macos`, `ios`, `android`, `debian`, `fedora`, `firefox`, `java` or `all`);
- for that system the steps and, where there are any, commands that download the root, **check its
  SHA-256 against the value in the command** and only then install it: PowerShell for Windows, a Terminal
  block for macOS, Debian and Ubuntu, Fedora, RHEL, Rocky and Alma, and `keytool` for Java;
- a **configuration profile** (`.mobileconfig`) for iPhone, iPad and Mac, and two Windows helpers (`.cmd`)
  for each root.

**The page cannot prove itself.** It comes over plain HTTP, so a change on the way would change the page,
the downloads and the digits in the commands together. The hash in a command only shows that the download is
the file the page described. Compare the fingerprint with the value from step 1 (or a message from your
admin) before you install: the admin UI writes that message for you (*Authorities*, the root, *Message for
your users*). Details, the limits of the commands and the switch for admins:
[The trust portal]({{ '/trust-portal/' | relative_url }}).

The sections below keep the steps **by hand**, for when you cannot reach the portal or want to see every
step.

## 3. Install the root

### Windows

The helper on the trust portal imports the root into *Trusted Root Certification Authorities*. It shows
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

The portal offers a configuration profile for a Mac too: open it, then *System Settings → Privacy &
Security → Profiles*, choose it and click *Install*. macOS shows it as **Not Signed**; that is expected,
and it is why you compare the fingerprint first. By hand: double-click the `.crt` and add it to the *System* keychain. Then open the certificate in Keychain
Access, expand *Trust*, set *When using this certificate* to *Always Trust* and confirm with your
password (Safari, Chrome and Edge use this keychain). Or in Terminal:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain homelab-root.crt
```

### iPhone and iPad

1. Open the trust portal in **Safari**, tap the root's profile and allow the configuration profile.
2. In *Settings* tap *Profile Downloaded* (or *General → VPN & Device Management*), choose the profile
   and tap *Install*. iOS shows the profile as **Not Signed**: it holds only the public root and cannot
   be signed with a certificate the device does not trust yet.
3. Open *Settings → General → About → Certificate Trust Settings* and switch on full trust for the
   root. **Without this step** iOS installs the root but does not trust it for websites.

Menu names change between iOS versions.

### Android

Download the `.crt`, then open *Settings → Security and privacy → More security settings → Encryption
and credentials → Install a certificate → CA certificate* and choose the file. The path differs
between vendors and Android versions. Chrome trusts a CA installed this way; **many apps do not**:
apps that target Android 7 (API 24) or higher ignore the user store unless their network security
configuration opts in. A device management (MDM) system can install the root for all apps.

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
- **A command of the portal stops at the hash check:** the download is not the file the page described.
  Do not install; compare with the admin UI.
- **The portal shows the wrong system:** the guess comes from the browser. Choose the system from the
  list; an iPad that asks for the desktop version of web sites looks like a Mac.
- **An agent host should trust the root too:** the agent can add it to the system store on request, see
  [the trust portal page]({{ '/trust-portal/' | relative_url }}#the-root-in-the-system-trust-store-of-an-agent-host).
- More symptoms: [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in) and
  [operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails).

## Next steps

- Issue a certificate and test it: [Installation]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).
- Learn how CAs are created and replaced, and what clients must do then: [CA lifecycle]({{ '/guides/ca-lifecycle/' | relative_url }}).
