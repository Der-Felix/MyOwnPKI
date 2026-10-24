package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"strings"
)

// Windows helpers of the trust page (v0.2.2, owner 2026-10-24): one .cmd
// per root generation and store – LocalMachine (asks for administrator
// rights itself) or CurrentUser (no administrator needed). Double-click it,
// or run it in cmd.exe.
//
// The file is a Batch/PowerShell polyglot: cmd.exe reads the first line
// "<# :" as a label and runs the batch lines up to "exit /b"; PowerShell
// reads everything from "<#" to "#>" as a comment and runs the rest. The
// batch part starts PowerShell on the file itself. The root is embedded as
// PEM; before anything is imported, its SHA-256 is computed and compared
// with the fingerprint written into the file – a changed certificate stops
// the import. "/check" only checks (the CI runs it so) and imports nothing.
//
// The file is ASCII only (CA names are ASCII; the common name, which may
// not be, stays out) and has CRLF line ends – cmd.exe misreads labels and
// goto targets in a file with LF only.

// Scopes of a Windows helper.
const (
	ScopeMachine = "machine" // Cert:\LocalMachine\Root, needs administrator rights
	ScopeUser    = "user"    // Cert:\CurrentUser\Root, for this user only
)

// windowsHelper returns the .cmd for one root certificate.
func windowsHelper(caName string, generation int64, der []byte, scope string) []byte {
	store, what := "LocalMachine", "this computer (all users; asks for administrator rights)"
	if scope == ScopeUser {
		store, what = "CurrentUser", "your Windows user only (no administrator rights needed)"
	}
	certPEM := strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "\n")
	lines := []string{
		fmt.Sprintf("<# : MyOwnPKI trust helper - root CA %s, generation %d, for %s", caName, generation, what),
		"@echo off",
		"setlocal",
		"rem Imports the root certificate below into Trusted Root Certification",
		"rem Authorities after it checked its SHA-256. \"/check\" only checks.",
		"set \"MYOWNPKI_SELF=%~f0\"",
		"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:MYOWNPKI_SELF))) %*\"",
		"exit /b %errorlevel%",
		"#>",
		"$ErrorActionPreference = 'Stop'",
		"$name = '" + caName + "'",
		fmt.Sprintf("$generation = %d", generation),
		"$store = '" + store + "'",
		"$expected = '" + colonHex(der) + "'",
		"$pem = @'",
	}
	lines = append(lines, strings.Split(certPEM, "\n")...)
	lines = append(lines, []string{
		"'@",
		"foreach ($a in $args) {",
		"    if ($a -ne '/check' -and $a -ne '/quiet') {",
		"        Write-Host \"Unknown argument '$a' - nothing was imported. Use /check (check only) or /quiet (no prompt at the end).\"",
		"        exit 64",
		"    }",
		"}",
		"$check = $args -contains '/check'",
		"$quiet = $check -or ($args -contains '/quiet')",
		"function Done([int]$code) {",
		"    if (-not $quiet) { try { [void](Read-Host 'Press Enter to close') } catch { } }",
		"    exit $code",
		"}",
		"$b64 = (($pem -split \"`n\") | Where-Object { $_ -notmatch '-----' }) -join ''",
		"$der = [Convert]::FromBase64String(($b64 -replace '\\s', ''))",
		"$sha = [Security.Cryptography.SHA256]::Create()",
		"$got = (($sha.ComputeHash($der) | ForEach-Object { $_.ToString('X2') }) -join ':')",
		"Write-Host \"Root CA $name (generation $generation), SHA-256 of the certificate in this file:\"",
		"Write-Host \"  $got\"",
		"if ($got -ne $expected) {",
		"    Write-Host 'STOP: the certificate in this file does not match its fingerprint - the file was changed. Nothing was imported.'",
		"    Done 2",
		"}",
		"Write-Host 'Fingerprint ok. Compare it with the fingerprint on the trust page, or one you got from your administrator.'",
		"if ($check) { exit 0 }",
		"if ($store -eq 'LocalMachine') {",
		"    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()",
		"    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
		"        Write-Host 'Asking for administrator rights ...'",
		"        $p = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', ('\"' + $env:MYOWNPKI_SELF + '\"') -Verb RunAs -Wait -PassThru",
		"        exit $p.ExitCode",
		"    }",
		"}",
		"$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, $der)",
		"$root = New-Object Security.Cryptography.X509Certificates.X509Store ('Root', $store)",
		"$root.Open('ReadWrite')",
		"try { $root.Add($cert) } finally { $root.Close() }",
		"Write-Host \"Done: imported into Trusted Root Certification Authorities ($store).\"",
		"Done 0",
	}...)
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// colonHex is the SHA-256 of der as upper-case hex with colons – what
// Windows, browsers and `openssl x509 -fingerprint -sha256` show.
func colonHex(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
