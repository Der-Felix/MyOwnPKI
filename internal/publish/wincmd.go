package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"strings"
)

// Windows helpers of the trust page: one .cmd per root generation and store –
// LocalMachine (asks for administrator rights itself) or CurrentUser (no
// administrator needed). Double-click it, or run it in cmd.exe.
//
// The file is a Batch/PowerShell polyglot: cmd.exe reads the first line
// "<# :" as a label and runs the batch lines up to "exit /b"; PowerShell
// reads everything from "<#" to "#>" as a comment and runs the rest. The
// batch part starts PowerShell on the file itself. The root is embedded as
// PEM. The helper computes its SHA-256 and SHA-1, but contains no expected
// fingerprint: only an independent SHA-256 argument or an explicit user
// confirmation authorizes an import. "/check" imports nothing.
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
		"rem Imports the root certificate below only after independent SHA-256 authorization.",
		"rem \"/check\" computes and displays fingerprints without importing.",
		"set \"MYOWNPKI_SELF=%~f0\"",
		"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:MYOWNPKI_SELF))) %*\"",
		"exit /b %errorlevel%",
		"#>",
		"$ErrorActionPreference = 'Stop'",
		"$name = '" + caName + "'",
		fmt.Sprintf("$generation = %d", generation),
		"$store = '" + store + "'",
		"$pem = @'",
	}
	lines = append(lines, strings.Split(certPEM, "\n")...)
	lines = append(lines, []string{
		"'@",
		"$check = $false",
		"$quiet = $false",
		"$expected = ''",
		"for ($i = 0; $i -lt $args.Count; $i++) {",
		"    $a = [string]$args[$i]",
		"    if ($a -eq '/check') {",
		"        $check = $true",
		"    } elseif ($a -eq '/quiet') {",
		"        $quiet = $true",
		"    } elseif ($a -eq '-ExpectedSha256') {",
		"        if ($expected -ne '' -or $i + 1 -ge $args.Count) {",
		"            Write-Host 'Missing or duplicate -ExpectedSha256 value - nothing was imported.'",
		"            exit 64",
		"        }",
		"        $i++",
		"        $expected = [string]$args[$i]",
		"        if ($expected -notmatch '^[0-9A-Fa-f]{64}$') {",
		"            Write-Host 'STOP: -ExpectedSha256 must be exactly 64 hexadecimal characters with no colons or whitespace. Nothing was imported.'",
		"            exit 64",
		"        }",
		"        $expected = $expected.ToUpperInvariant()",
		"    } else {",
		"        Write-Host \"Unknown argument '$a' - nothing was imported. Use /check, /quiet, or -ExpectedSha256 <64-hex-value>.\"",
		"        exit 64",
		"    }",
		"}",
		"$quiet = $check -or $quiet",
		"function Done([int]$code) {",
		"    if (-not $quiet -and $expected -eq '') { try { [void](Read-Host 'Press Enter to close') } catch { } }",
		"    exit $code",
		"}",
		"$b64 = (($pem -split \"`n\") | Where-Object { $_ -notmatch '-----' }) -join ''",
		"$der = [Convert]::FromBase64String(($b64 -replace '\\s', ''))",
		"$sha256 = [Security.Cryptography.SHA256]::Create()",
		"$sha1 = [Security.Cryptography.SHA1]::Create()",
		"$sha256Bytes = $sha256.ComputeHash($der)",
		"$sha1Bytes = $sha1.ComputeHash($der)",
		"$gotHex = (($sha256Bytes | ForEach-Object { $_.ToString('X2') }) -join '')",
		"$got = (($sha256Bytes | ForEach-Object { $_.ToString('X2') }) -join ':')",
		"$gotSHA1 = (($sha1Bytes | ForEach-Object { $_.ToString('X2') }) -join ':')",
		"Write-Host \"Root CA $name (generation $generation), certificate SHA-256 (authoritative):\"",
		"Write-Host \"  $got\"",
		"Write-Host 'Certificate SHA-1 (display only, for the Windows certificate dialog):'",
		"Write-Host \"  $gotSHA1\"",
		"if ($expected -ne '') {",
		"    if ($gotHex -cne $expected) {",
		"        Write-Host 'STOP: the certificate SHA-256 does not match -ExpectedSha256. The certificate may have changed. Nothing was imported.'",
		"        Done 2",
		"    }",
		"    Write-Host 'SHA-256 matches the independently supplied expected value.'",
		"}",
		"if ($check) { exit 0 }",
		"if ($store -eq 'LocalMachine') {",
		"    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()",
		"    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
		"        Write-Host 'Asking for administrator rights ...'",
		"        $child = '\"' + $env:MYOWNPKI_SELF + '\"'",
		"        if ($expected -ne '') { $child += ' -ExpectedSha256 ' + $expected }",
		"        if ($quiet) { $child += ' /quiet' }",
		"        $p = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', $child -Verb RunAs -Wait -PassThru",
		"        exit $p.ExitCode",
		"    }",
		"}",
		"if ($expected -eq '') {",
		"    if ($quiet) {",
		"        Write-Host 'STOP: /quiet cannot replace independent SHA-256 authorization. Supply -ExpectedSha256 or run interactively. Nothing was imported.'",
		"        Done 3",
		"    }",
		"    $answer = Read-Host 'Type YES only after independently comparing the authoritative SHA-256 above'",
		"    if ($answer -cne 'YES') {",
		"        Write-Host 'STOP: independent SHA-256 comparison was not confirmed. Nothing was imported.'",
		"        Done 3",
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
