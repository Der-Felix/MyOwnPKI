package tlsscan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestTrustAnchors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	anchors, err := e.inst.Engine.TrustAnchors(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors.Roots) != 1 || len(anchors.Intermediates) != 1 {
		t.Fatalf("roots %d, intermediates %d", len(anchors.Roots), len(anchors.Intermediates))
	}
	root, issuing := anchors.Roots[0], anchors.Intermediates[0]
	if !root.IsCA || root.Subject.String() != root.Issuer.String() || issuing.Issuer.String() != root.Subject.String() {
		t.Errorf("root %s, intermediate %s issued by %s", root.Subject, issuing.Subject, issuing.Issuer)
	}
	// Read-only and public: the same while the server is sealed.
	if err := e.inst.Ring.Seal(t.Context(), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if again, err := e.inst.Engine.TrustAnchors(t.Context(), testinstance.Console); err != nil || len(again.Roots) != 1 || len(again.Intermediates) != 1 {
		t.Errorf("sealed: %v", err)
	}
	// A tenant-wide viewer reads; a role limited to one CA does not (404).
	if _, err := e.inst.Engine.TrustAnchors(t.Context(), who(authz.Viewer, "")); err != nil {
		t.Errorf("viewer: %v", err)
	}
	for _, w := range []string{"issuing", "root"} {
		if _, err := e.inst.Engine.TrustAnchors(t.Context(), who(authz.Viewer, w)); !errors.Is(err, ca.ErrNotFound) {
			t.Errorf("viewer of %s only: %v", w, err)
		}
	}
	if _, err := e.inst.Engine.TrustAnchors(t.Context(), who(authz.Viewer, "")); err != nil {
		t.Fatal(err)
	}
}

// TestTrustAnchorsKeepOlderGenerationsAndDropRevokedOnes: a chain may still
// end in an older generation of a renewed CA; a revoked CA is no anchor.
func TestTrustAnchorsKeepOlderGenerationsAndDropRevokedOnes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.inst.Engine.RenewCA(t.Context(), ca.RenewRequest{Name: "issuing", Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	anchors, err := e.inst.Engine.TrustAnchors(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors.Intermediates) != 2 || len(anchors.Roots) != 1 {
		t.Fatalf("after the renewal: roots %d, intermediates %d", len(anchors.Roots), len(anchors.Intermediates))
	}
	if _, rerr := e.inst.Engine.RevokeCA(t.Context(), ca.RevokeCARequest{Name: "issuing", Generation: 1, Reason: "superseded", Who: testinstance.Console}); rerr != nil {
		t.Fatal(rerr)
	}
	anchors, err = e.inst.Engine.TrustAnchors(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors.Intermediates) != 1 {
		t.Errorf("after revoking generation 1: %d intermediates", len(anchors.Intermediates))
	}
}

func TestCertificateByFingerprint(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	issued, err := e.inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"www.homelab.lan"}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(issued.CertDER)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	if fp != issued.Fingerprint {
		t.Fatalf("test setup: %s != %s", fp, issued.Fingerprint)
	}
	for _, in := range []string{fp, strings.ToLower(fp), " " + fp + " "} {
		got, err := e.inst.Engine.CertificateByFingerprint(t.Context(), testinstance.Console, in)
		if err != nil || got.ID != issued.ID || got.Status != ca.CertValid || got.DNSNames[0] != "www.homelab.lan" {
			t.Errorf("%q: %v, %+v", in, err, got)
		}
	}
	for name, tc := range map[string]struct {
		who keys.Who
		fp  string
	}{
		"unknown":                 {testinstance.Console, strings.Repeat("AB", 32)},
		"not hex":                 {testinstance.Console, strings.Repeat("ZZ", 32)},
		"too short":               {testinstance.Console, fp[:62]},
		"empty":                   {testinstance.Console, ""},
		"a role for another CA":   {who(authz.Viewer, "root"), fp},
		"no principal":            {keys.Who{}, fp},
		"SQL-looking input":       {testinstance.Console, "' OR 1=1 --"},
		"the fingerprint of x509": {testinstance.Console, hex.EncodeToString(make([]byte, 32))},
	} {
		if _, err := e.inst.Engine.CertificateByFingerprint(t.Context(), tc.who, tc.fp); !errors.Is(err, ca.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The viewer of the issuing CA, and a tenant-wide one, read it.
	for _, w := range []keys.Who{who(authz.Viewer, "issuing"), who(authz.Viewer, "")} {
		if _, err := e.inst.Engine.CertificateByFingerprint(t.Context(), w, fp); err != nil {
			t.Errorf("viewer: %v", err)
		}
	}
	// A revoked certificate is still found, with its status.
	if _, err := e.inst.Engine.Revoke(t.Context(), ca.RevokeRequest{CertificateID: issued.ID, Reason: "superseded", Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	if got, err := e.inst.Engine.CertificateByFingerprint(t.Context(), testinstance.Console, fp); err != nil || got.Status != ca.CertRevoked {
		t.Errorf("revoked: %v, %+v", err, got)
	}
}

func TestValidPunycode(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"bcher-kva":             true,  // buecher with u-umlaut
		"mnchen-3ya":            true,  // muenchen with u-umlaut
		"80ak6aa92e":            true,  // a Cyrillic label
		"n3h":                   true,  // an emoji label
		"":                      false, // nothing after xn--
		"9":                     false, // runs out of digits
		"a-":                    false, // no encoded part
		"zzzzzzzzzzzzzz":        false, // overflows
		strings.Repeat("a", 60): false,
		"bcher-KVA":             false, // upper case never gets here, but is no digit of ours
		"bcher-k.a":             false,
	} {
		if got := validPunycode(in); got != want {
			t.Errorf("validPunycode(%q) = %v, want %v", in, got, want)
		}
	}
}
