package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// ari fetches renewalInfo (GET, unsigned).
func (v *env) ari(t *testing.T, id string) (int, http.Header, map[string]map[string]string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, v.ts.URL+"/acme/renewal-info/"+id, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]map[string]string
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, resp.Header, out
}

func ariWindow(t *testing.T, w map[string]map[string]string) (time.Time, time.Time) {
	t.Helper()
	start, err1 := time.Parse(time.RFC3339, w["suggestedWindow"]["start"])
	end, err2 := time.Parse(time.RFC3339, w["suggestedWindow"]["end"])
	if err1 != nil || err2 != nil {
		t.Fatalf("window: %v", w)
	}
	return start, end
}

// TestRenewalInfo (PHASE2 step 12): the window lies at 2/3 of the
// lifetime inside the certificate's validity; a revoked certificate gets a
// window in the past; bad identifiers are refused.
func TestRenewalInfo(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	der, _ := c.issue("nas.homelab.lan")
	cert, _ := x509.ParseCertificate(der)
	id := ariID(cert)

	code, hdr, w := v.ari(t, id)
	if code != http.StatusOK || hdr.Get("Retry-After") != "21600" {
		t.Fatalf("renewalInfo: %d %v %v", code, hdr, w)
	}
	start, end := ariWindow(t, w)
	life := cert.NotAfter.Sub(cert.NotBefore)
	earliest := cert.NotBefore.Add(life * 2 / 3).Add(-time.Second)
	latest := cert.NotBefore.Add(life*2/3 + life/30 + life/10)
	if start.Before(earliest) || !end.After(start) || end.After(latest) || !end.Before(cert.NotAfter) {
		t.Errorf("window %s – %s for a certificate %s – %s", start, end, cert.NotBefore, cert.NotAfter)
	}
	if _, _, again := v.ari(t, id); again["suggestedWindow"]["start"] != w["suggestedWindow"]["start"] {
		t.Error("the window changes between two questions")
	}

	// Unknown and malformed identifiers.
	if code, _, _ := v.ari(t, strings.Split(id, ".")[0]+".AQ"); code != http.StatusNotFound {
		t.Errorf("unknown serial: %d", code)
	}
	for _, bad := range []string{"nodot", "a.b.c", strings.Split(id, ".")[0] + ".gA", strings.Split(id, ".")[0] + ".AAE", id + "==", ".AQ"} {
		if code, _, _ := v.ari(t, bad); code != http.StatusBadRequest {
			t.Errorf("%q: %d", bad, code)
		}
	}

	// Revoked: renew now.
	if a := c.post(testBase+"/revoke-cert", revokePayload(der, 4)); a.code != http.StatusOK {
		t.Fatalf("revoke: %d %s", a.code, a.body)
	}
	_, _, w = v.ari(t, id)
	if _, end := ariWindow(t, w); !end.Before(v.Clock.Now()) {
		t.Errorf("revoked, window ends %s – not in the past", end)
	}
}

func TestRenewalWindow(t *testing.T) {
	t.Parallel()
	nb := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	na := nb.Add(90 * 24 * time.Hour)
	starts := map[time.Time]bool{}
	for i := range 50 {
		start, end := renewalWindow(nb, na, big.NewInt(int64(1000+i)))
		day := func(x time.Time) float64 { return x.Sub(nb).Hours() / 24 }
		if day(start) < 60 || day(start) >= 63 || end.Sub(start) != 9*24*time.Hour {
			t.Errorf("serial %d: day %.2f to %.2f", 1000+i, day(start), day(end))
		}
		starts[start] = true
	}
	if len(starts) < 40 {
		t.Errorf("only %d different starts for 50 certificates – no jitter", len(starts))
	}
	// A lifetime too short for a shift still gets a window.
	if s, e := renewalWindow(nb, nb.Add(10*time.Second), big.NewInt(1)); !e.After(s) && e != s {
		t.Errorf("short lifetime: %s %s", s, e)
	}
}

// TestReplaces (RFC 9773 §5): a renewal names the certificate it replaces;
// only the own certificate, with a shared name, once.
func TestReplaces(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	der, _ := c.issue("nas.homelab.lan")
	cert, _ := x509.ParseCertificate(der)
	id := ariID(cert)
	newOrder := func(cl *client, name, replaces string) *answer {
		t.Helper()
		return cl.post(testBase+"/new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": name}}, "replaces": replaces})
	}

	other := v.client(t)
	other.register()
	if a := newOrder(other, "nas.homelab.lan", id); a.code != http.StatusBadRequest || a.problem() != "malformed" {
		t.Errorf("foreign account: %d %s", a.code, a.body)
	}
	if a := newOrder(c, "web.homelab.lan", id); a.code != http.StatusBadRequest {
		t.Errorf("no shared name: %d %s", a.code, a.body)
	}
	if a := newOrder(c, "nas.homelab.lan", "garbage"); a.code != http.StatusBadRequest {
		t.Errorf("garbage: %d %s", a.code, a.body)
	}
	order := newOrder(c, "nas.homelab.lan", id)
	if order.code != http.StatusCreated || order.json["replaces"] != id {
		t.Fatalf("renewal order: %d %s", order.code, order.body)
	}
	if a := newOrder(c, "nas.homelab.lan", id); a.code != http.StatusConflict || a.problem() != "alreadyReplaced" {
		t.Errorf("second renewal: %d %s", a.code, a.body)
	}
	// The renewal's certificate records what it replaces.
	c.solve(order, "http-01")
	fin := c.finalize(order, csrFor(t, mustKey(t), "nas.homelab.lan", []string{"nas.homelab.lan"}, nil))
	if fin.json["status"] != "valid" {
		t.Fatalf("finalize: %d %s", fin.code, fin.body)
	}
	certURL, _ := fin.json["certificate"].(string)
	newID := certURL[strings.LastIndex(certURL, "/")+1:]
	q := pkidb.New(v.Engine.PKI)
	row, err := q.GetCertificate(t.Context(), newID)
	sum := sha256.Sum256(der)
	old, err2 := q.GetCertificateByFingerprint(t.Context(), strings.ToUpper(hex.EncodeToString(sum[:])))
	if err != nil || err2 != nil || row.RenewalOf.String != old.ID {
		t.Errorf("renewal_of %q, want %q (%v %v)", row.RenewalOf.String, old.ID, err, err2)
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
