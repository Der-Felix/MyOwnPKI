package trustkit

import "strings"

// Block is one titled part of a guide: steps for a person, commands to paste,
// or both, and a note. It is plain data; the page escapes every field.
type Block struct {
	Title string
	Steps []string // sentences to follow, in order
	Lines []string // the commands, one text line each; empty when no command is offered
	Note  string   // the limit of the block or a caveat, one or two sentences
}

// Fixed notes.
const (
	// limitNote: the embedded value proves only that the download is the file
	// this page describes. It says nothing about the page.
	limitNote = "The value in this command only checks the download against this page. " +
		"It does not show that the page is genuine: compare the SHA-256 with the admin UI or your administrator first."

	// refusedNote replaces the commands when the CA's public base URL does not
	// pass the pattern check.
	refusedNote = "No command is shown for this root because its public base URL is unusual. " +
		"Download the file above and compare its SHA-256 by hand."
)

// Guide returns the blocks of steps and commands that install root r on
// platform p, or nil for an unknown platform. Commands appear only when the
// root's name and base URL pass the pattern checks; otherwise the block says
// to compare by hand. The text depends on nothing but r: the commands carry
// the root's SHA-256, its download URL and its CA name, and nothing else
// variable.
func Guide(p Platform, r Root) []Block {
	url, ok := r.CertURL()
	hexSum := r.SHA256()
	file := fileText(r)
	switch p {
	case Linux:
		// A detection result only: the page expands it to Debian and Fedora.
		return nil
	case Windows:
		blocks := []Block{{
			Title: "By hand with the certificate dialog",
			Steps: []string{
				"Download the DER file and save it as " + file + ".cer (the download link is above).",
				"Double-click it, choose Install Certificate, pick Current User or Local Machine and place the certificate in the store Trusted Root Certification Authorities.",
				"On the Details tab of the certificate dialog compare the thumbprint with the SHA-1 shown here and the fingerprint with the SHA-256 from the admin UI before you confirm.",
			},
		}}
		if !ok {
			return append(blocks, Block{Title: "PowerShell", Note: refusedNote})
		}
		return append(blocks,
			Block{
				Title: "PowerShell, for your user only",
				Lines: powershell(url, hexSum, file, `Cert:\CurrentUser\Root`),
				Note:  "Windows asks you to confirm the import. " + limitNote,
			},
			Block{
				Title: "PowerShell started as administrator, for all users of this computer",
				Lines: powershell(url, hexSum, file, `Cert:\LocalMachine\Root`),
				Note:  limitNote,
			})
	case MacOS:
		blocks := []Block{{
			Title: "Configuration profile",
			Steps: []string{
				"Download the profile (the link above). macOS saves it and does not install it yet.",
				"Open System Settings, Privacy & Security, Profiles (older macOS: System Preferences, Profiles), choose the profile and click Install.",
				"macOS shows the profile as Not Signed. That is expected: it holds only the public root certificate and cannot be signed with a certificate your Mac does not trust yet. Compare the SHA-256 of the certificate with your trusted value before you install.",
				"If Keychain Access still shows the certificate as not trusted, double-click it, open Trust and set When using this certificate to Always Trust.",
			},
			Note: "An iPad that asks for the desktop version of web sites looks like a Mac to this page: use the iPhone and iPad steps on it.",
		}}
		if !ok {
			return append(blocks, Block{Title: "Terminal", Note: refusedNote})
		}
		return append(blocks, Block{
			Title: "Terminal",
			Lines: chain(
				"curl -fsS -o root.crt '"+url+"'",
				"echo '"+hexSum+"  root.crt' | shasum -a 256 -c -",
				"sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt",
			),
			Note: limitNote + " Safari, Chrome and Edge use the keychain.",
		})
	case IOS:
		return []Block{{
			Title: "Configuration profile",
			Steps: []string{
				"Open this page in Safari and tap the profile link above. Allow the download of the configuration profile.",
				"Open Settings. Profile Downloaded appears at the top (or General, VPN & Device Management). Choose the profile, tap Install and enter your passcode.",
				"iOS shows the profile as Not Signed. That is expected: it holds only the public root certificate and cannot be signed with a certificate your device does not trust yet. Compare the SHA-256 of the certificate with your trusted value before you install.",
				"Open Settings, General, About, Certificate Trust Settings and switch on full trust for the root. Without this step the root is installed but not trusted for web sites.",
			},
			Note: "Menu names differ between iOS versions.",
		}}
	case Android:
		return []Block{{
			Title: "User certificate",
			Steps: []string{
				"Download the certificate file (the link above).",
				"Open Settings, Security and privacy, More security settings, Encryption and credentials, Install a certificate, CA certificate. Menu names differ between vendors and Android versions. Confirm the warning and choose the file.",
				"Android may ask you to set a screen lock first.",
			},
			Note: "Chrome and most browsers accept such a user CA. Apps that target Android 7 (API 24) or higher ignore user CAs unless their network security configuration opts in. A device management (MDM) can install the root for all apps.",
		}}
	case Debian:
		if !ok {
			return []Block{{Title: "Command line", Note: refusedNote}}
		}
		return []Block{{
			Title: "Command line",
			Lines: chain(
				"curl -fsS -o root.crt '"+url+"'",
				"echo '"+hexSum+"  root.crt' | sha256sum -c -",
				"openssl x509 -inform DER -in root.crt -out myownpki-"+file+".crt",
				"sudo install -m 0644 myownpki-"+file+".crt /usr/local/share/ca-certificates/myownpki-"+file+".crt",
				"sudo update-ca-certificates",
			),
			Note: limitNote + " curl, wget, Python and most programs use this store; Firefox and Chrome on Linux keep their own.",
		}}
	case Fedora:
		if !ok {
			return []Block{{Title: "Command line", Note: refusedNote}}
		}
		return []Block{{
			Title: "Command line",
			Lines: chain(
				"curl -fsS -o root.crt '"+url+"'",
				"echo '"+hexSum+"  root.crt' | sha256sum -c -",
				"openssl x509 -inform DER -in root.crt -out myownpki-"+file+".pem",
				"sudo install -m 0644 myownpki-"+file+".pem /etc/pki/ca-trust/source/anchors/myownpki-"+file+".pem",
				"sudo update-ca-trust",
			),
			Note: limitNote + " curl, wget, Python and most programs use this store; Firefox and Chrome on Linux keep their own.",
		}}
	case Firefox:
		return []Block{{
			Title: "Import dialog",
			Steps: []string{
				"Download the certificate file (the link above).",
				"Open Settings, Privacy & Security, Certificates, View Certificates, Authorities.",
				"Import the file and tick Trust this CA to identify websites.",
			},
			Note: "On Windows and macOS Firefox can use the system store instead: open about:config and set security.enterprise_roots.enabled to true. This does not apply to Linux.",
		}}
	case Java:
		if !ok {
			return []Block{{Title: "keytool", Note: refusedNote}}
		}
		return []Block{{
			Title: "keytool",
			Lines: chain(
				"curl -fsS -o root.crt '"+url+"'",
				"echo '"+hexSum+"  root.crt' | sha256sum -c -",
				"sudo keytool -importcert -trustcacerts -alias myownpki-"+file+` -file root.crt -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit`,
			),
			Note: limitNote + " keytool prints the certificate's fingerprint and asks before it trusts it: compare it too. " +
				"changeit is the public default password of the Java keystore; older Java keeps the file under jre/lib/security. On macOS use shasum -a 256 -c - instead of sha256sum -c -.",
		}}
	}
	return nil
}

// fileText is the base name for download names inside steps and commands. A
// name that fails the check never reaches a command (CertURL refuses it), and
// text only gets a neutral phrase.
func fileText(r Root) string {
	if !ValidName(r.Name) || r.Generation < 1 {
		return "the-root"
	}
	return r.File()
}

// chain joins commands with && so that a failed check stops the rest, one
// command per line.
func chain(cmds ...string) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c
		if i > 0 {
			out[i] = "  && " + c
		}
		if i < len(cmds)-1 {
			out[i] += " \\"
		}
	}
	return out
}

// powershell is the Windows block: one if/else statement, so pasting it line
// by line cannot import after a failed check. PowerShell compares the hash
// without regard to case.
func powershell(url, hexSum, file, store string) []string {
	return []string{
		"$f = Join-Path $env:TEMP 'myownpki-" + file + ".cer'",
		"Invoke-WebRequest -UseBasicParsing -Uri '" + url + "' -OutFile $f",
		"if ((Get-FileHash -Algorithm SHA256 -Path $f).Hash -eq '" + strings.ToUpper(hexSum) + "') { Import-Certificate -FilePath $f -CertStoreLocation " + store +
			" } else { Remove-Item $f; Write-Error 'SHA-256 mismatch: nothing was installed' }",
	}
}
