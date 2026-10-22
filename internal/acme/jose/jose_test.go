package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// Vectors from RFC 7515 appendix A, RFC 7638 §3.1 and RFC 8037 appendix A.
const (
	rfcPayload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	// A.2 RS256
	rfcRSAn   = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
	rfcRSAsig = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
	// A.3 ES256
	rfcECx   = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	rfcECy   = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	rfcECsig = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	// RFC 7638 §3.1
	rfc7638n     = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	rfc7638Thumb = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	// RFC 8037 A.2–A.4 Ed25519
	rfcEdX     = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfcEdThumb = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	rfcEdInput = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfcEdSig   = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func vectorJWS(t *testing.T, alg, input, sig string) *JWS {
	t.Helper()
	s, err := b64.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	return &JWS{Alg: alg, signingInput: []byte(input), signature: s}
}

func TestRFCVectors(t *testing.T) {
	t.Parallel()
	rsaKey, err := ParseJWK([]byte(`{"kty":"RSA","n":"` + rfcRSAn + `","e":"AQAB"}`))
	if err != nil {
		t.Fatal(err)
	}
	if verr := vectorJWS(t, RS256, "eyJhbGciOiJSUzI1NiJ9."+rfcPayload, rfcRSAsig).Verify(rsaKey); verr != nil {
		t.Errorf("RFC 7515 A.2 (RS256): %v", verr)
	}
	ecKey, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","y":"` + rfcECy + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if verr := vectorJWS(t, ES256, "eyJhbGciOiJFUzI1NiJ9."+rfcPayload, rfcECsig).Verify(ecKey); verr != nil {
		t.Errorf("RFC 7515 A.3 (ES256): %v", verr)
	}
	// A changed payload must fail.
	if verr := vectorJWS(t, ES256, "eyJhbGciOiJFUzI1NiJ9."+rfcPayload+"A", rfcECsig).Verify(ecKey); !errors.Is(verr, ErrBadSignature) {
		t.Errorf("tampered A.3: %v", verr)
	}
	edKey, err := ParseJWK([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + rfcEdX + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if verr := vectorJWS(t, EdDSA, rfcEdInput, rfcEdSig).Verify(edKey); verr != nil {
		t.Errorf("RFC 8037 A.4 (EdDSA): %v", verr)
	}
	if edKey.Thumbprint() != rfcEdThumb {
		t.Errorf("RFC 8037 A.3 thumbprint %s", edKey.Thumbprint())
	}
	tk, err := ParseJWK([]byte(`{"kty":"RSA","n":"` + rfc7638n + `","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tk.Thumbprint() != rfc7638Thumb {
		t.Errorf("RFC 7638 §3.1 thumbprint %s", tk.Thumbprint())
	}
	// A.1 (HS256), A.4 (ES512 on P-521) and A.5 (none): not accepted.
	for _, alg := range []string{"HS256", "ES512", "none"} {
		if err := checkAlg(alg); !errors.Is(err, ErrBadAlgorithm) {
			t.Errorf("%s: %v", alg, err)
		}
	}
	if _, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"}`)); !errors.Is(err, ErrBadKey) {
		t.Errorf("RFC 7515 A.4 key (P-521): %v", err)
	}
}

// signer makes ACME-shaped requests for the tests.
type signer struct {
	priv crypto.Signer
	alg  string
	jwk  string
}

func newSigner(tb testing.TB, kind string) *signer {
	tb.Helper()
	var priv crypto.Signer
	var err error
	switch kind {
	case ES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ES384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RS256:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case EdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		tb.Fatal(err)
	}
	k, err := KeyFor(priv.Public())
	if err != nil {
		tb.Fatal(err)
	}
	return &signer{priv: priv, alg: kind, jwk: string(k.Canonical())}
}

func (s *signer) sign(tb testing.TB, input []byte) []byte {
	tb.Helper()
	switch p := s.priv.(type) {
	case *ecdsa.PrivateKey:
		var d []byte
		if s.alg == ES256 {
			h := sha256.Sum256(input)
			d = h[:]
		} else {
			h := sha512.Sum384(input)
			d = h[:]
		}
		r, ss, err := ecdsa.Sign(rand.Reader, p, d)
		if err != nil {
			tb.Fatal(err)
		}
		size := (p.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		ss.FillBytes(out[size:])
		return out
	case *rsa.PrivateKey:
		h := sha256.Sum256(input)
		sig, err := rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA256, h[:])
		if err != nil {
			tb.Fatal(err)
		}
		return sig
	case ed25519.PrivateKey:
		return ed25519.Sign(p, input)
	}
	return nil
}

// body builds a flattened JWS from a raw protected header and payload.
func (s *signer) body(tb testing.TB, header, payload string) []byte {
	tb.Helper()
	ph, pl := b64.EncodeToString([]byte(header)), b64.EncodeToString([]byte(payload))
	sig := s.sign(tb, []byte(ph+"."+pl))
	return []byte(`{"protected":"` + ph + `","payload":"` + pl + `","signature":"` + b64.EncodeToString(sig) + `"}`)
}

func (s *signer) header() string {
	return `{"alg":"` + s.alg + `","nonce":"n1","url":"https://acme.example/new-account","jwk":` + s.jwk + `}`
}

func TestEveryAllowedAlgorithm(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{ES256, ES384, RS256, EdDSA} {
		s := newSigner(t, alg)
		j, err := Parse(s.body(t, s.header(), `{"contact":[]}`))
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if verr := j.Verify(j.JWK); verr != nil {
			t.Errorf("%s: %v", alg, verr)
		}
		if j.Nonce != "n1" || j.URL != "https://acme.example/new-account" || string(j.Payload) != `{"contact":[]}` {
			t.Errorf("%s: %+v", alg, j)
		}
		// The same request with a kid and the payload empty (POST-as-GET).
		kidHeader := `{"alg":"` + alg + `","nonce":"n2","url":"https://acme.example/order/1","kid":"https://acme.example/acct/1"}`
		j, err = Parse(s.body(t, kidHeader, ""))
		if err != nil || j.KID == "" || len(j.Payload) != 0 || j.JWK != nil {
			t.Fatalf("%s kid: %+v %v", alg, j, err)
		}
		k, _ := ParseJWK([]byte(s.jwk))
		if err := j.Verify(k); err != nil {
			t.Errorf("%s kid: %v", alg, err)
		}
	}
}

// TestRules: one refusal per rule.
func TestRules(t *testing.T) {
	t.Parallel()
	es := newSigner(t, ES256)
	es384 := newSigner(t, ES384)
	good := es.body(t, es.header(), `{}`)
	var top map[string]string
	if err := json.Unmarshal(good, &top); err != nil {
		t.Fatal(err)
	}
	withHeader := func(h string) []byte { return es.body(t, h, `{}`) }
	hdr := func(extra string) string {
		return `{"alg":"ES256","nonce":"n1","url":"https://acme.example/x","jwk":` + es.jwk + extra + `}`
	}
	jwkHeader := func(jwk string) string {
		return `{"alg":"ES256","nonce":"n1","url":"https://acme.example/x","jwk":` + jwk + `}`
	}
	ecPoint := strings.TrimSuffix(es.jwk, "}")
	cases := map[string]struct {
		body []byte
		want error
	}{
		"not an object":         {[]byte(`[1]`), ErrMalformed},
		"data after the object": {append(append([]byte{}, good...), []byte(` {}`)...), ErrMalformed},
		"unprotected header":    {[]byte(`{"protected":"` + top["protected"] + `","header":{},"payload":"","signature":"` + top["signature"] + `"}`), ErrMalformed},
		"general serialization": {[]byte(`{"payload":"","signatures":[]}`), ErrMalformed},
		"unknown member":        {[]byte(`{"protected":"` + top["protected"] + `","payload":"","signature":"` + top["signature"] + `","x":1}`), ErrMalformed},
		"payload missing":       {[]byte(`{"protected":"` + top["protected"] + `","signature":"` + top["signature"] + `"}`), ErrMalformed},
		"duplicate member":      {[]byte(`{"protected":"` + top["protected"] + `","payload":"","payload":"e30","signature":"` + top["signature"] + `"}`), ErrMalformed},
		"payload not a string":  {[]byte(`{"protected":"` + top["protected"] + `","payload":{},"signature":"` + top["signature"] + `"}`), ErrMalformed},
		"padding":               {[]byte(`{"protected":"` + top["protected"] + `","payload":"e30=","signature":"` + top["signature"] + `"}`), ErrMalformed},
		"non-strict bits":       {[]byte(`{"protected":"` + top["protected"] + `","payload":"e31","signature":"` + top["signature"] + `"}`), ErrMalformed},
		"duplicate header":      {withHeader(hdr(`,"nonce":"n2"`)), ErrMalformed},
		"duplicate by escape":   {withHeader(hdr(`,"nonce":"n2"`)), ErrMalformed},
		"crit":                  {withHeader(hdr(`,"crit":["b64"]`)), ErrMalformed},
		"b64 false":             {withHeader(hdr(`,"b64":false`)), ErrMalformed},
		"alg none":              {withHeader(strings.Replace(hdr(""), `"ES256"`, `"none"`, 1)), ErrBadAlgorithm},
		"alg HS256":             {withHeader(strings.Replace(hdr(""), `"ES256"`, `"HS256"`, 1)), ErrBadAlgorithm},
		"alg ES512":             {withHeader(strings.Replace(hdr(""), `"ES256"`, `"ES512"`, 1)), ErrBadAlgorithm},
		"alg RS384":             {withHeader(strings.Replace(hdr(""), `"ES256"`, `"RS384"`, 1)), ErrBadAlgorithm},
		"alg lower case":        {withHeader(strings.Replace(hdr(""), `"ES256"`, `"es256"`, 1)), ErrBadAlgorithm},
		"nonce missing":         {withHeader(strings.Replace(hdr(""), `"nonce":"n1",`, ``, 1)), ErrMalformed},
		"url missing":           {withHeader(strings.Replace(hdr(""), `"url":"https://acme.example/x",`, ``, 1)), ErrMalformed},
		"jwk and kid":           {withHeader(hdr(`,"kid":"https://acme.example/acct/1"`)), ErrMalformed},
		"neither jwk nor kid":   {withHeader(`{"alg":"ES256","nonce":"n1","url":"https://acme.example/x"}`), ErrMalformed},
		"private member":        {withHeader(jwkHeader(ecPoint + `,"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`)), ErrBadKey},
		"short coordinate":      {withHeader(jwkHeader(`{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}`)), ErrBadKey},
		"not on the curve":      {withHeader(jwkHeader(`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","y":"` + rfcECx + `"}`)), ErrBadKey},
		"jwk alg mismatch":      {withHeader(jwkHeader(ecPoint + `,"alg":"ES384"}`)), ErrBadAlgorithm},
		"RSA 1024":              {withHeader(jwkHeader(`{"kty":"RSA","n":"` + b64.EncodeToString(big.NewInt(0).Lsh(big.NewInt(1), 1023).Bytes()) + `","e":"AQAB"}`)), ErrBadKey},
		"RSA even exponent":     {withHeader(jwkHeader(`{"kty":"RSA","n":"` + rfcRSAn + `","e":"AQAA"}`)), ErrBadKey},
		"RSA leading zero":      {withHeader(jwkHeader(`{"kty":"RSA","n":"AA` + rfcRSAn[2:] + `","e":"AQAB"}`)), ErrBadKey},
		"key type oct":          {withHeader(jwkHeader(`{"kty":"oct","k":"c2VjcmV0"}`)), ErrBadKey},
	}
	for name, tc := range cases {
		if _, err := Parse(tc.body); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// Rules checked by Verify.
	j, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ParseJWK([]byte(es384.jwk))
	if verr := j.Verify(other); !errors.Is(verr, ErrBadAlgorithm) {
		t.Errorf("header alg vs. another key's alg: %v", verr)
	}
	otherES256, _ := ParseJWK([]byte(newSigner(t, ES256).jwk))
	if verr := j.Verify(otherES256); !errors.Is(verr, ErrBadSignature) {
		t.Errorf("another key: %v", verr)
	}
	// A DER-encoded ECDSA signature is refused.
	ph, pl := b64.EncodeToString([]byte(es.header())), b64.EncodeToString([]byte(`{}`))
	h := sha256.Sum256([]byte(ph + "." + pl))
	ecPriv, ok := es.priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	der, err := ecdsa.SignASN1(rand.Reader, ecPriv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	jd, err := Parse([]byte(`{"protected":"` + ph + `","payload":"` + pl + `","signature":"` + b64.EncodeToString(der) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if verr := jd.Verify(jd.JWK); !errors.Is(verr, ErrBadSignature) || !strings.Contains(verr.Error(), "DER") {
		t.Errorf("DER signature: %v", verr)
	}
	// A changed payload under the original signature.
	tampered := []byte(`{"protected":"` + top["protected"] + `","payload":"eyJ4IjoxfQ","signature":"` + top["signature"] + `"}`)
	jt, err := Parse(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := jt.Verify(jt.JWK); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered payload: %v", err)
	}
}

func TestEAB(t *testing.T) {
	t.Parallel()
	acct := newSigner(t, ES256)
	acctKey, _ := ParseJWK([]byte(acct.jwk))
	macKey := []byte("a mac key the admin created, 32b")
	const url = "https://acme.example/new-account"
	eab := func(header, payload string, key []byte) json.RawMessage {
		ph, pl := b64.EncodeToString([]byte(header)), b64.EncodeToString([]byte(payload))
		m := hmac.New(sha256.New, key)
		m.Write([]byte(ph + "." + pl))
		return json.RawMessage(`{"protected":"` + ph + `","payload":"` + pl + `","signature":"` + b64.EncodeToString(m.Sum(nil)) + `"}`)
	}
	lookup := func(kid string) ([]byte, error) {
		if kid != "eab-1" {
			return nil, errors.New("unknown EAB key")
		}
		return macKey, nil
	}
	hdr := `{"alg":"HS256","kid":"eab-1","url":"` + url + `"}`
	if kid, err := VerifyEAB(eab(hdr, acct.jwk, macKey), acctKey, url, lookup); err != nil || kid != "eab-1" {
		t.Fatalf("valid EAB: %q %v", kid, err)
	}
	other := newSigner(t, ES256)
	for name, raw := range map[string]json.RawMessage{
		"wrong MAC key": eab(hdr, acct.jwk, []byte("another key of thirty-two bytes!")),
		"another key":   eab(hdr, other.jwk, macKey),
		"nonce present": eab(`{"alg":"HS256","kid":"eab-1","url":"`+url+`","nonce":"x"}`, acct.jwk, macKey),
		"HS512":         eab(`{"alg":"HS512","kid":"eab-1","url":"`+url+`"}`, acct.jwk, macKey),
		"other URL":     eab(`{"alg":"HS256","kid":"eab-1","url":"https://acme.example/elsewhere"}`, acct.jwk, macKey),
		"unknown kid":   eab(`{"alg":"HS256","kid":"eab-2","url":"`+url+`"}`, acct.jwk, macKey),
		"duplicate kid": eab(`{"alg":"HS256","kid":"eab-1","kid":"eab-2","url":"`+url+`"}`, acct.jwk, macKey),
		"extra member":  json.RawMessage(`{"protected":"e30","payload":"e30","signature":"","header":{}}`),
	} {
		if _, err := VerifyEAB(raw, acctKey, url, lookup); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzParse: no input makes the parser panic, and what it accepts keeps
// its promises.
func FuzzParse(f *testing.F) {
	s := newSigner(f, ES256)
	f.Add(s.body(f, s.header(), `{"x":1}`))
	f.Add([]byte(`{"protected":"","payload":"","signature":""}`))
	f.Add([]byte(`{"protected":"eyJhbGciOiJub25lIn0","payload":"","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		j, err := Parse(data)
		if err != nil {
			return
		}
		if !allowed[j.Alg] || j.Nonce == "" || j.URL == "" || (j.JWK == nil) == (j.KID == "") {
			t.Fatalf("accepted a JWS that breaks a rule: %+v", j)
		}
		if j.JWK != nil {
			_ = j.Verify(j.JWK)
		}
	})
}
