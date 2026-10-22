package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// issue orders, validates and finalizes a certificate for name; it returns
// the certificate's DER and its key.
func (c *client) issue(name string) ([]byte, *ecdsa.PrivateKey) {
	c.t.Helper()
	order := c.order(name)
	c.solve(order, "http-01")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fin := c.finalize(order, csrFor(c.t, key, name, []string{name}, nil))
	if fin.json["status"] != "valid" {
		c.t.Fatalf("finalize: %d %s", fin.code, fin.body)
	}
	certURL, _ := fin.json["certificate"].(string)
	got := c.post(certURL, nil)
	b, _ := pem.Decode(got.body)
	if b == nil {
		c.t.Fatalf("certificate: %d %s", got.code, got.body)
	}
	return b.Bytes, key
}

// keyClient signs with key and sends it as jwk (no account).
func (v *env) keyClient(t *testing.T, key *ecdsa.PrivateKey) *client {
	t.Helper()
	jk, err := jose.KeyFor(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, v: v, key: key, jwk: string(jk.Canonical())}
}

func revokePayload(der []byte, reason int) map[string]any {
	p := map[string]any{"certificate": b64(der)}
	if reason >= 0 {
		p["reason"] = reason
	}
	return p
}

func (v *env) revocation(t *testing.T, der []byte) (string, bool) {
	t.Helper()
	q := pkidb.New(v.Engine.PKI)
	sum := sha256.Sum256(der)
	row, err := q.GetCertificateByFingerprint(t.Context(), strings.ToUpper(hex.EncodeToString(sum[:])))
	if err != nil {
		t.Fatalf("certificate not stored: %v", err)
	}
	rev, err := q.GetRevocation(t.Context(), row.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return rev.Reason, true
}

func TestRevokeCert(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	owner := v.client(t)
	owner.register()
	url := testBase + "/revoke-cert"

	// 1. Another account without authorizations may not; with them it may,
	// but not with keyCompromise.
	cert1, _ := owner.issue("nas.homelab.lan")
	other := v.client(t)
	other.register()
	if a := other.post(url, revokePayload(cert1, -1)); a.code != http.StatusForbidden || a.problem() != "unauthorized" {
		t.Errorf("foreign account: %d %s", a.code, a.body)
	}
	o := other.order("nas.homelab.lan")
	other.solve(o, "http-01")
	if a := other.post(url, revokePayload(cert1, 1)); a.code != http.StatusForbidden || a.problem() != "unauthorized" {
		t.Errorf("keyCompromise by a name holder: %d %s", a.code, a.body)
	}
	if a := other.post(url, revokePayload(cert1, 4)); a.code != http.StatusOK {
		t.Fatalf("revoke by a name holder: %d %s", a.code, a.body)
	}
	if r, ok := v.revocation(t, cert1); !ok || r != ca.ReasonSuperseded {
		t.Errorf("cert1 revocation: %q %v", r, ok)
	}
	if a := owner.post(url, revokePayload(cert1, -1)); a.code != http.StatusBadRequest || a.problem() != "alreadyRevoked" {
		t.Errorf("again: %d %s", a.code, a.body)
	}

	// 2. The ordering account, with keyCompromise; reasons outside the list.
	cert2, _ := owner.issue("nas.homelab.lan")
	for _, bad := range []int{2, 6, 7, 8, 10, 11, -5} {
		p := revokePayload(cert2, 0)
		p["reason"] = bad
		if a := owner.post(url, p); a.code != http.StatusBadRequest || a.problem() != "badRevocationReason" {
			t.Errorf("reason %d: %d %s", bad, a.code, a.body)
		}
	}
	if a := owner.post(url, revokePayload(cert2, 1)); a.code != http.StatusOK {
		t.Fatalf("revoke by the owner: %d %s", a.code, a.body)
	}
	if r, ok := v.revocation(t, cert2); !ok || r != ca.ReasonKeyCompromise {
		t.Errorf("cert2 revocation: %q %v", r, ok)
	}

	// 3. Signed with the certificate's key (jwk); a different jwk fails.
	cert3, key3 := owner.issue("nas.homelab.lan")
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := v.keyClient(t, stranger)
	if a := sc.post(url, revokePayload(cert3, 1)); a.code != http.StatusForbidden || a.problem() != "unauthorized" {
		t.Errorf("foreign jwk: %d %s", a.code, a.body)
	}
	kc := v.keyClient(t, key3)
	if a := kc.post(url, revokePayload(cert3, 1)); a.code != http.StatusOK {
		t.Fatalf("revoke with the certificate key: %d %s", a.code, a.body)
	}
	if _, ok := v.revocation(t, cert3); !ok {
		t.Error("cert3 not revoked")
	}

	// 4. Malformed requests and unknown certificates.
	selfKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	self, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "nas.homelab.lan"}, DNSNames: []string{"nas.homelab.lan"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "nas.homelab.lan"}}, &selfKey.PublicKey, selfKey)
	if a := owner.post(url, revokePayload(self, -1)); a.code != http.StatusNotFound {
		t.Errorf("unknown certificate: %d %s", a.code, a.body)
	}
	for _, p := range []map[string]any{
		{"certificate": b64(cert2) + "=="},
		{"certificate": "%%%"},
		{"certificate": b64([]byte("not a certificate"))},
		{},
	} {
		if a := owner.post(url, p); a.code != http.StatusBadRequest || a.problem() != "malformed" {
			t.Errorf("payload %v: %d %s", p, a.code, a.body)
		}
	}

	v.Deliver(t)
	log := strings.Join(testinstance.Audit(t, v.TenantAudit), " ")
	for _, want := range []string{"certificate.revoke/success", "certificate.revoke/denied", "crl.sign/success"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit lacks %s: %s", want, log)
		}
	}
}

// TestRevokeWhileSealed: the revocation is stored at once; the CRL follows
// at the unseal.
func TestRevokeWhileSealed(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	der, _ := c.issue("nas.homelab.lan")
	if err := v.Ring.Seal(t.Context(), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if a := c.post(testBase+"/revoke-cert", revokePayload(der, 5)); a.code != http.StatusOK {
		t.Fatalf("revoke while sealed: %d %s", a.code, a.body)
	}
	if r, ok := v.revocation(t, der); !ok || r != ca.ReasonCessationOfOperation {
		t.Errorf("revocation: %q %v", r, ok)
	}
}

// postSigned sends a jwk request signed by any allowed key type.
func (c *client) postSigned(signer crypto.Signer, url string, payload any) *answer {
	c.t.Helper()
	jk, err := jose.KeyFor(signer.Public())
	if err != nil {
		c.t.Fatal(err)
	}
	h, _ := json.Marshal(map[string]any{"alg": jk.Algorithm(), "nonce": c.getNonce(), "url": url, "jwk": json.RawMessage(jk.Canonical())})
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	var sig []byte
	switch k := signer.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	case *rsa.PrivateKey:
		sum := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		var digest []byte
		if size == 48 {
			s := sha512.Sum384([]byte(input))
			digest = s[:]
		} else {
			s := sha256.Sum256([]byte(input))
			digest = s[:]
		}
		r, s, serr := ecdsa.Sign(rand.Reader, k, digest)
		err = serr
		sig = make([]byte, 2*size)
		if serr == nil {
			r.FillBytes(sig[:size])
			s.FillBytes(sig[size:])
		}
	}
	if err != nil {
		c.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"protected": b64(h), "payload": b64(p), "signature": b64(sig)})
	return c.postRaw(url, body)
}

// TestRevokeWithEachKeyType: a certificate's own key revokes it for every
// key type the JWS allowlist knows; a P-521 certificate (allowed for
// certificates, not for JWS) is revoked by its account instead.
func TestRevokeWithEachKeyType(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	owner := v.client(t)
	owner.register()
	url := testBase + "/revoke-cert"
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	issueWith := func(key crypto.Signer) []byte {
		t.Helper()
		order := owner.order("nas.homelab.lan")
		owner.solve(order, "http-01")
		fin := owner.finalize(order, csrFor(t, key, "nas.homelab.lan", []string{"nas.homelab.lan"}, nil))
		if fin.json["status"] != "valid" {
			t.Fatalf("finalize %T: %d %s", key, fin.code, fin.body)
		}
		certURL, _ := fin.json["certificate"].(string)
		b, _ := pem.Decode(owner.post(certURL, nil).body)
		return b.Bytes
	}
	for _, key := range []crypto.Signer{p384, rsaKey, edKey} {
		der := issueWith(key)
		if a := owner.postSigned(key, url, revokePayload(der, 1)); a.code != http.StatusOK {
			t.Errorf("revoke with a %T certificate key: %d %s", key, a.code, a.body)
		}
		if r, ok := v.revocation(t, der); !ok || r != ca.ReasonKeyCompromise {
			t.Errorf("%T: revocation %q %v", key, r, ok)
		}
	}
	der := issueWith(p521)
	if a := owner.post(url, revokePayload(der, 1)); a.code != http.StatusOK {
		t.Errorf("revoke a P-521 certificate by its account: %d %s", a.code, a.body)
	}
}
