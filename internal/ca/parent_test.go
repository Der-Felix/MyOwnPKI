package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestParentMustBeUsable: a new CA is signed only below a parent that is
// active, has a certificate that works now and a key this build can use.
func TestParentMustBeUsable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(t *testing.T, v *env)
		want  string
	}{
		{"unknown parent", func(*testing.T, *env) {}, `there is no parent CA named "parent"`},
		{"retired parent", func(t *testing.T, v *env) {
			v.root(t, "parent", nil)
			if err := v.e.RetireCA(t.Context(), "parent", tester); err != nil {
				t.Fatal(err)
			}
		}, `parent CA "parent" is retired, not active`},
		{"parent that waits for its signature", func(t *testing.T, v *env) {
			v.importRoot(t, "offline-root", newOfflineRoot(t, "Offline Root", t0.Add(-day)))
			v.intermediate(t, "parent", "offline-root", nil)
		}, `parent CA "parent" is pending_signature, not active`},
		{"parent with an HSM key", func(t *testing.T, v *env) {
			v.root(t, "parent", nil)
			if _, err := v.pki.ExecContext(t.Context(), `UPDATE cas SET key_mode = 'hsm' WHERE name = 'parent'`); err != nil {
				t.Fatal(err)
			}
		}, `parent CA "parent" uses an HSM key, which this build can't use`},
		{"parent without a signed certificate", func(t *testing.T, v *env) {
			v.root(t, "parent", nil)
			if _, err := v.pki.ExecContext(t.Context(), `UPDATE cas SET current_generation = NULL WHERE name = 'parent'`); err != nil {
				t.Fatal(err)
			}
		}, `parent CA "parent" has no signed certificate yet`},
		{"parent whose certificate has expired", func(t *testing.T, v *env) {
			v.root(t, "parent", func(r *RootRequest) { r.ValidityDays = 30 })
			v.clk.Advance(31 * day)
		}, `the chain of parent CA "parent" is not valid now (Homelab parent valid from 2026-10-13 to 2026-11-12)`},
		{"the last second of the parent's certificate", func(t *testing.T, v *env) {
			v.root(t, "parent", func(r *RootRequest) { r.ValidityDays = 30 })
			v.clk.Set(t0.AddDate(0, 0, 30).Add(time.Second))
		}, "is not valid now"},
		{"a root above the parent that has expired", func(t *testing.T, v *env) {
			top := v.addCA(t, "top", caOpts{notAfter: t0.AddDate(0, 0, 30)})
			v.addCA(t, "parent", caOpts{parent: top, key: mustKey(t, elliptic.P256())})
			v.clk.Advance(31 * day)
		}, `the chain of parent CA "parent" is not valid now (Test top valid from 2026-10-12 to 2026-11-12)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t)
			tt.setup(t, v)
			_, err := v.e.CreateIntermediate(t.Context(), IntermediateRequest{
				CASettings: CASettings{Name: "child", BaseURL: baseURL}, Parent: "parent", Subject: Subject{CommonName: "Child CA"}, Who: tester,
			})
			if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
				t.Errorf("reasons %q, want %q", got, tt.want)
			}
			var n int
			if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM cas WHERE name = 'child'`).Scan(&n); err != nil || n != 0 {
				t.Errorf("%d CAs named child after the refusal (%v)", n, err)
			}
		})
	}
}

// TestRenewingAnOfflineRoot: only a new key under the same name and subject.
func TestRenewingAnOfflineRoot(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	first := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", first)
	v.root(t, "online", nil)
	retired := newOfflineRoot(t, "Retired Root", t0.Add(-day))
	v.importRoot(t, "retired", retired)
	if err := v.e.RetireCA(t.Context(), "retired", tester); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, ca string
		root     *offlineRoot
		want     string
	}{
		{"the same certificate again", "offline-root", first, "the key is the one of generation 1 – renewing with the same key is not supported"},
		{"a new certificate with the old key", "offline-root", &offlineRoot{cert: first.cert, key: first.key}, "renewing with the same key is not supported"},
		{"another subject", "offline-root", newOfflineRoot(t, "Other Name", t0.Add(-day)), "the subject differs from generation 1"},
		{"the name of an online root", "online", newOfflineRoot(t, "Homelab online", t0.Add(-day)), `a CA named "online" exists already and is not an offline root`},
		{"a retired root", "retired", newOfflineRoot(t, "Retired Root", t0.Add(-day)), `CA "retired" is retired`},
	}
	for _, tt := range tests {
		_, err := v.e.ImportRoot(t.Context(), ImportRootRequest{CASettings: CASettings{Name: tt.ca, BaseURL: baseURL}, CertPEM: tt.root.pem(), Who: tester})
		if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
	var gens int
	if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM ca_generations g JOIN cas c ON c.id = g.ca_id WHERE c.name = 'offline-root'`).Scan(&gens); err != nil || gens != 1 {
		t.Errorf("%d generations of offline-root after the refusals (%v)", gens, err)
	}
}

// TestDigestAndSignatureFollowTheKey: the OpenSSL digest the bundle names and
// the signature algorithm the engine uses (pki-rules.md §4).
func TestDigestAndSignatureFollowTheKey(t *testing.T) {
	t.Parallel()
	p521 := mustKey(t, elliptic.P521())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		pub    any
		digest string
		sig    x509.SignatureAlgorithm
	}{
		{"P-256", mustKey(t, elliptic.P256()).Public(), "sha256", x509.ECDSAWithSHA256},
		{"P-384", mustKey(t, elliptic.P384()).Public(), "sha384", x509.ECDSAWithSHA384},
		{"P-521", p521.Public(), "sha512", x509.ECDSAWithSHA512},
		{"RSA", rsaKey.Public(), "sha256", x509.SHA256WithRSA},
		{"Ed25519", edPub, "", x509.PureEd25519},
		{"P-224 (not a CA curve)", p224.Public(), "sha256", 0},
	}
	for _, tt := range tests {
		if got := digestFor(tt.pub); got != tt.digest {
			t.Errorf("%s: digest %q, want %q", tt.name, got, tt.digest)
		}
		got, err := signatureAlgorithm(tt.pub)
		if tt.sig == 0 {
			if err == nil {
				t.Errorf("%s: a signature algorithm %v for a key that can't be a CA key", tt.name, got)
			}
			continue
		}
		if err != nil || got != tt.sig {
			t.Errorf("%s: signature %v (%v), want %v", tt.name, got, err, tt.sig)
		}
	}
	if _, err := signatureAlgorithm(struct{}{}); err == nil || !strings.Contains(err.Error(), "is not supported") {
		t.Errorf("an unknown key type: %v", err)
	}
}

// TestMatchIPFailsClosedOnBadInput: a name or a constraint that doesn't parse
// matches nothing – so it never counts as permitted.
func TestMatchIPFailsClosedOnBadInput(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, value string
		want        bool
	}{
		{"10.0.0.1", "10.0.0.0/8", true},
		{"not an ip", "10.0.0.0/8", false},
		{"10.0.0.1", "10.0.0.0", false},
		{"10.0.0.1", "", false},
		{"", "10.0.0.0/8", false},
		{"10.0.0.1", "10.0.0.0/33", false},
		{"fd00::1", "fd00::/129", false},
		{"0.0.0.0", "0.0.0.0/0", true},
		{"::1", "0.0.0.0/0", false},
	} {
		if got := matchIP(tt.name, tt.value); got != tt.want {
			t.Errorf("matchIP(%q, %q) = %v, want %v", tt.name, tt.value, got, tt.want)
		}
	}
	// The names reach it through netip, in canonical form.
	if a, err := netip.ParseAddr("10.0.0.1"); err != nil || !matchIP(a.String(), "10.0.0.0/8") {
		t.Error("canonical form")
	}
}
