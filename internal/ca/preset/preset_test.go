package preset

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestBuiltin(t *testing.T) {
	t.Parallel()
	set, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}

	want := []string{
		"client", "codesign", "custom", "ocsp", "server", "server-client",
		"smime", "timestamp", "user", "vpn-client", "vpn-server", "wildcard",
	}
	if got := set.Names(); !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}

	server, _ := set.Get("server")
	tests := []struct {
		alg  x509.PublicKeyAlgorithm
		want x509.KeyUsage
	}{
		{x509.RSA, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		{x509.ECDSA, x509.KeyUsageDigitalSignature},
		{x509.Ed25519, x509.KeyUsageDigitalSignature},
	}
	for _, tt := range tests {
		if got := server.KeyUsageFor(tt.alg); got != tt.want {
			t.Errorf("server.KeyUsageFor(%v) = %b, want %b", tt.alg, got, tt.want)
		}
	}

	vpn, _ := set.Get("vpn-server")
	std, rest := vpn.ExtKeyUsages()
	if !slices.Equal(std, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("vpn-server std EKUs = %v", std)
	}
	wantRest := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 17}, {1, 3, 6, 1, 5, 5, 8, 2, 2}}
	if len(rest) != len(wantRest) || !rest[0].Equal(wantRest[0]) || !rest[1].Equal(wantRest[1]) {
		t.Errorf("vpn-server OID EKUs = %v, want %v", rest, wantRest)
	}
	if all := vpn.ExtKeyUsageOIDs(); len(all) != 3 || !all[0].Equal(extKeyUsageOID["serverAuth"]) {
		t.Errorf("vpn-server ExtKeyUsageOIDs() = %v", all)
	}

	// Accessors return copies: callers can't change the shared preset.
	std[0] = x509.ExtKeyUsageAny
	rest[0][0] = 9
	if again, againRest := vpn.ExtKeyUsages(); again[0] != x509.ExtKeyUsageServerAuth || againRest[0][0] != 1 {
		t.Error("ExtKeyUsages() exposes internal slices")
	}

	if _, ok := set.Get("nonexistent"); ok {
		t.Error(`Get("nonexistent") found a preset`)
	}
}

// validPreset is a correct preset; each rejection case changes one detail.
const validPreset = `name: test
description: "Test preset"
usage: "Testing"
family: server
validity_days: 397
key_usage:
  rsa: [digitalSignature, keyEncipherment]
  other: [digitalSignature]
ext_key_usage:
  usages: [serverAuth]
  critical: false
subject_alt_names:
  required_any_of: [dns, ip]
  offered: [dns, ip]
common_name_from: dns
openssl_purpose: sslserver
ocsp_no_check: false
customizable: false
`

func TestParseValid(t *testing.T) {
	t.Parallel()
	p, err := Parse("test.yaml", []byte(validPreset))
	if err != nil {
		t.Fatalf("Parse(validPreset): %v", err)
	}
	if p.Name != "test" || p.ValidityDays != 397 {
		t.Errorf("unexpected preset: %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		old, new string // replacement applied to validPreset
		wantErr  string
	}{
		{"unknown field (typo)", "validity_days:", "validity_day:", "field validity_day not found"},
		{"bad name", "name: test", "name: Test_1", "name:"},
		{"empty description", `description: "Test preset"`, `description: ""`, "description: must not be empty"},
		{"unknown family", "family: server", "family: web", `family: "web" is not one of`},
		{"validity zero", "validity_days: 397", "validity_days: 0", "validity_days: must be between"},
		{"validity too long", "validity_days: 397", "validity_days: 4000", "validity_days: must be between"},
		{"CA key usage", "rsa: [digitalSignature, keyEncipherment]", "rsa: [digitalSignature, keyCertSign]", "reserved for CA certificates"},
		{"cRLSign", "other: [digitalSignature]", "other: [cRLSign]", "reserved for CA certificates"},
		{"encryption with ECDSA", "other: [digitalSignature]", "other: [digitalSignature, keyEncipherment]", "needs an RSA key"},
		{"key agreement", "other: [digitalSignature]", "other: [keyAgreement]", "keyAgreement"},
		{"unknown key usage", "other: [digitalSignature]", "other: [digitalSignatur]", `unknown key usage "digitalSignatur"`},
		{"duplicate key usage", "other: [digitalSignature]", "other: [digitalSignature, digitalSignature]", "listed twice"},
		{"empty key usage", "other: [digitalSignature]", "other: []", "at least one key usage"},
		{"unknown EKU", "usages: [serverAuth]", "usages: [webServer]", `unknown extended key usage "webServer"`},
		{"EKU as OID instead of name", "usages: [serverAuth]", "usages: [serverAuth, 1.3.6.1.5.5.7.3.2]", `write "clientAuth" instead of the OID`},
		{"anyExtendedKeyUsage", "usages: [serverAuth]", "usages: [serverAuth, 2.5.29.37.0]", "anyExtendedKeyUsage"},
		{"invalid OID", "usages: [serverAuth]", "usages: [serverAuth, 1.03.4]", "unknown extended key usage"},
		{"duplicate EKU", "usages: [serverAuth]", "usages: [serverAuth, serverAuth]", "listed twice"},
		{"empty EKU", "usages: [serverAuth]", "usages: []", "at least one extended key usage"},
		{"server without SAN", "required_any_of: [dns, ip]", "required_any_of: []", "need a DNS or IP SAN"},
		{"required not offered", "offered: [dns, ip]", "offered: [dns]", `"ip" is required but not in offered`},
		{"unknown SAN type", "offered: [dns, ip]", "offered: [dns, ip, upn]", `unknown SAN type "upn"`},
		{"CN from IP", "common_name_from: dns", "common_name_from: ip", "common_name_from: must be"},
		{"OCSP no-check without OCSPSigning", "ocsp_no_check: false", "ocsp_no_check: true", "only allowed together with the OCSPSigning"},
		{"purpose mismatch", "openssl_purpose: sslserver", "openssl_purpose: sslclient", "needs the clientAuth extended key usage"},
		{"unknown purpose", "openssl_purpose: sslserver", "openssl_purpose: webserver", `unknown purpose "webserver"`},
		{"customizable outside custom", "customizable: false", "customizable: true", `only allowed for family "custom"`},
		{"second YAML document", "customizable: false\n", "customizable: false\n---\nname: other\n", "only one YAML document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(validPreset, tt.old) {
				t.Fatalf("test setup: %q not found in validPreset", tt.old)
			}
			data := strings.Replace(validPreset, tt.old, tt.new, 1)
			_, err := Parse("test.yaml", []byte(data))
			if err == nil {
				t.Fatalf("Parse() accepted invalid preset, want error containing %q", tt.wantErr)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q\nwant it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseTimestampRules(t *testing.T) {
	t.Parallel()
	base := strings.NewReplacer(
		"family: server", "family: timestamp",
		"usages: [serverAuth]", "usages: [timeStamping]",
		"required_any_of: [dns, ip]", "required_any_of: []",
		"openssl_purpose: sslserver", "openssl_purpose: timestampsign",
	).Replace(validPreset)

	if _, err := Parse("ts.yaml", []byte(strings.Replace(base, "critical: false", "critical: true", 1))); err != nil {
		t.Fatalf("valid timestamp preset rejected: %v", err)
	}
	if _, err := Parse("ts.yaml", []byte(base)); err == nil || !strings.Contains(err.Error(), "RFC 3161") {
		t.Errorf("non-critical timeStamping EKU: err = %v, want RFC 3161 error", err)
	}
}

func TestParseReportsAllProblems(t *testing.T) {
	t.Parallel()
	data := strings.NewReplacer("validity_days: 397", "validity_days: 0", "family: server", "family: web").Replace(validPreset)
	_, err := Parse("test.yaml", []byte(data))
	if err == nil || !strings.Contains(err.Error(), "validity_days") || !strings.Contains(err.Error(), "family") {
		t.Errorf("want both problems in one error, got %v", err)
	}
}

func TestParseLimits(t *testing.T) {
	t.Parallel()
	if _, err := Parse("empty.yaml", nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty file: err = %v", err)
	}
	big := []byte(validPreset + "#" + strings.Repeat("x", MaxFileSize))
	if _, err := Parse("big.yaml", big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: err = %v", err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	t.Run("name must match file name", func(t *testing.T) {
		t.Parallel()
		fsys := fstest.MapFS{"other.yaml": {Data: []byte(validPreset)}}
		if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "must match the file name") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no files", func(t *testing.T) {
		t.Parallel()
		if _, err := Load(fstest.MapFS{"README.md": {}}); !errors.Is(err, ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("all broken files are reported", func(t *testing.T) {
		t.Parallel()
		fsys := fstest.MapFS{
			"a.yaml":    {Data: []byte("name: a\n")},
			"b.yaml":    {Data: []byte("name: b\n")},
			"test.yaml": {Data: []byte(validPreset)},
		}
		_, err := Load(fsys)
		if err == nil || !strings.Contains(err.Error(), "a.yaml") || !strings.Contains(err.Error(), "b.yaml") {
			t.Errorf("err = %v, want both a.yaml and b.yaml", err)
		}
	})
	t.Run("loads valid files", func(t *testing.T) {
		t.Parallel()
		set, err := Load(fstest.MapFS{"test.yaml": {Data: []byte(validPreset)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := set.Get("test"); !ok {
			t.Error(`Get("test") not found`)
		}
	})
}

func TestParseOID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in string
		ok bool
	}{
		{"1.3.6.1.5.5.8.2.2", true},
		{"2.5.29.37.0", true},
		{"2.999.1", true},
		{"1", false},
		{"1..2", false},
		{"1.02", false},
		{"3.1", false},
		{"1.40", false},
		{"1.2.x", false},
		{"1.2.-3", false},
		{"1.2.99999999999", false},
	}
	for _, tt := range tests {
		if _, ok := parseOID(tt.in); ok != tt.ok {
			t.Errorf("parseOID(%q) ok = %v, want %v", tt.in, ok, tt.ok)
		}
	}
}
