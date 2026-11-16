package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fuzz targets of the ACME envelope (PHASE3 section 18.2). Every target calls
// the production function unchanged and re-checks what it accepted with the
// standard library only: nothing here calls object(), str(), decodeB64 or
// any other helper of the parser. Seeds are written in code; the files
// under testdata/fuzz are what the fuzzer stored after a failure.

const (
	// fuzzMaxTime is the wall time one input may take (section 18.2, rule 2).
	fuzzMaxTime = 2 * time.Second
	// fuzzMaxError bounds the text of a refusal: the parser may name the rule
	// and a short piece of the input, never the input (rule 5).
	fuzzMaxError = 400
)

const fuzzURL = "https://acme.example/acme/new-account"

// fuzzSeeds holds the signers and bodies every Parse target starts from. RSA
// key generation is slow, so it happens once per process.
var fuzzSeeds = sync.OnceValue(func() *seedSet {
	set := &seedSet{signers: map[string]*signer{}}
	for _, alg := range []string{ES256, ES384, RS256, EdDSA} {
		set.signers[alg] = newSigner(panicTB{}, alg)
	}
	return set
})

type seedSet struct {
	signers map[string]*signer
}

// panicTB lets the once-per-process setup use newSigner outside a test: key
// generation does not fail on a healthy machine, and if it does the fuzz run
// is useless anyway.
type panicTB struct{ testing.TB }

func (panicTB) Helper() {}
func (panicTB) Fatal(args ...any) {
	panic(fmt.Sprint(args...))
}

// bodies returns one signed request per shape the plan lists.
func (set *seedSet) bodies(tb testing.TB) (valid, invalid [][]byte) {
	tb.Helper()
	es, es384, rs, ed := set.signers[ES256], set.signers[ES384], set.signers[RS256], set.signers[EdDSA]
	hdr := func(s *signer, extra string) string {
		return `{"alg":"` + s.alg + `","nonce":"n1","url":"` + fuzzURL + `","jwk":` + s.jwk + extra + `}`
	}
	kid := func(s *signer) string {
		return `{"alg":"` + s.alg + `","nonce":"n2","url":"https://acme.example/acme/order/1","kid":"https://acme.example/acme/account/1"}`
	}
	valid = [][]byte{
		es.body(tb, hdr(es, ""), `{"termsOfServiceAgreed":true}`),
		es384.body(tb, hdr(es384, ""), `{}`),
		rs.body(tb, hdr(rs, ""), `{}`),
		ed.body(tb, hdr(ed, ""), `{"contact":["mailto:a@example.com"]}`),
		es.body(tb, kid(es), ``), // POST-as-GET with a kid
		rs.body(tb, kid(rs), ``),
		// A key change: the inner JWS has the new key in "jwk", no nonce, no kid.
		es.body(tb, `{"alg":"ES256","url":"https://acme.example/acme/key-change","jwk":`+es.jwk+`}`, `{"account":"https://acme.example/acme/account/1","oldKey":`+ed.jwk+`}`),
		ed.body(tb, `{"alg":"EdDSA","url":"https://acme.example/acme/key-change","jwk":`+ed.jwk+`}`, `{}`),
	}
	good := string(valid[0])
	var top map[string]string
	if err := json.Unmarshal(valid[0], &top); err != nil {
		tb.Fatal(err)
	}
	protected, signature := top["protected"], top["signature"]
	invalid = [][]byte{
		// The three failure shapes of the plan: duplicate members, crit, b64.
		[]byte(`{"protected":"` + protected + `","payload":"","payload":"e30","signature":"` + signature + `"}`),
		es.body(tb, hdr(es, `,"nonce":"n2"`), `{}`),
		es.body(tb, hdr(es, `,"nonce":"n2"`), `{}`),
		es.body(tb, hdr(es, `,"crit":["b64"]`), `{}`),
		es.body(tb, hdr(es, `,"b64":false`), `{}`),
		es.body(tb, strings.Replace(hdr(es, ""), `"ES256"`, `"HS256"`, 1), `{}`),
		es.body(tb, strings.Replace(hdr(es, ""), `"ES256"`, `"none"`, 1), `{}`),
		es.body(tb, hdr(es, `,"kid":"https://acme.example/acme/account/1"`), `{}`),
		es.body(tb, `{"alg":"ES256","nonce":"n1","url":"`+fuzzURL+`"}`, `{}`),
		[]byte(`{"protected":"` + protected + `","header":{"alg":"ES256"},"payload":"","signature":"` + signature + `"}`),
		[]byte(`{"payload":"","signatures":[{"protected":"` + protected + `","signature":"` + signature + `"}]}`),
		[]byte(`{"protected":"` + protected + `","payload":"e30=","signature":"` + signature + `"}`),
		[]byte(good + ` {}`),
		[]byte(`{"protected":"","payload":"","signature":""}`),
		[]byte(`[]`),
		[]byte(``),
	}
	return valid, invalid
}

// refUnmarshalObject reads a JSON object with encoding/json only.
func refUnmarshalObject(t *testing.T, what string, data []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		t.Fatalf("accepted %s that encoding/json does not read as an object (%v): %q", what, err, clipBytes(data))
	}
	if refHasDuplicateMember(data) {
		t.Fatalf("accepted %s with a member name that appears twice: %q", what, clipBytes(data))
	}
	return m
}

func clipBytes(b []byte) []byte {
	if len(b) > 300 {
		return b[:300]
	}
	return b
}

// refHasDuplicateMember reports a member name used twice in the outermost
// object of data (names compared after JSON unescaping). It walks the tokens
// with a depth counter; the parser under test reads member by member.
func refHasDuplicateMember(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	seen := map[string]bool{}
	depth, expectKey := 0, false
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth == 1 {
					expectKey = true
				}
			} else {
				depth--
				if depth == 1 {
					expectKey = true // a nested value ended
				}
			}
		case string:
			if depth == 1 && expectKey {
				if seen[v] {
					return true
				}
				seen[v] = true
				expectKey = false
			} else if depth == 1 {
				expectKey = true // a string value ended
			}
		default:
			if depth == 1 {
				expectKey = true // a number, boolean or null value ended
			}
		}
	}
}

// refString reads a JSON string member.
func refString(t *testing.T, what string, raw json.RawMessage) string {
	t.Helper()
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		t.Fatalf("%s is not a JSON string: %q", what, clipBytes(raw))
	}
	return s
}

// refB64 decodes base64url without padding and demands the one canonical
// encoding (the decoded bytes encode back to the same text).
func refB64(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		t.Fatalf("accepted %s that is not canonical base64url without padding: %q (%v)", what, s[:min(len(s), 80)], err)
	}
	return b
}

// refAlg is the algorithm of a standard library public key.
func refAlg(pub crypto.PublicKey) string {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return "ES256"
		case elliptic.P384():
			return "ES384"
		}
	case *rsa.PublicKey:
		return "RS256"
	case ed25519.PublicKey:
		return "EdDSA"
	}
	return ""
}

// refVerify checks a signature with the standard library, for the algorithm
// that goes with the key.
func refVerify(pub crypto.PublicKey, input, sig []byte) bool {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		var digest []byte
		if size == 32 {
			d := sha256.Sum256(input)
			digest = d[:]
		} else {
			d := sha512.Sum384(input)
			digest = d[:]
		}
		return ecdsa.Verify(p, digest, new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:]))
	case *rsa.PublicKey:
		d := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(p, crypto.SHA256, d[:], sig) == nil
	case ed25519.PublicKey:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(p, input, sig)
	}
	return false
}

// refThumbprint is RFC 7638 for the key, written out independently.
func refThumbprint(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	var canonical string
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		px, py := refPoint(t, p)
		crv := "P-256"
		if size == 48 {
			crv = "P-384"
		}
		canonical = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, enc(px), enc(py))
	case *rsa.PublicKey:
		canonical = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, enc(big.NewInt(int64(p.E)).Bytes()), enc(p.N.Bytes()))
	case ed25519.PublicKey:
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, enc(p))
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
	sum := sha256.Sum256([]byte(canonical))
	return enc(sum[:])
}

// refOnCurve checks y^2 = x^3 - 3x + b (mod p) for the NIST curves.
func refOnCurve(t *testing.T, p *ecdsa.PublicKey) bool {
	t.Helper()
	params := p.Params()
	px, py := refPoint(t, p)
	x, y := new(big.Int).SetBytes(px), new(big.Int).SetBytes(py)
	if x.Cmp(params.P) >= 0 || y.Cmp(params.P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, params.P)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
	rhs.Add(rhs, params.B)
	rhs.Mod(rhs, params.P)
	return lhs.Cmp(rhs) == 0
}

// checkRefusal: a refusal is typed (a caller can map it to an ACME problem)
// and its text is short, whatever the input was.
func checkRefusal(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBadAlgorithm) && !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrBadKey) {
		t.Fatalf("a refusal that maps to no ACME problem type: %v", err)
	}
	if n := len(err.Error()); n > fuzzMaxError {
		t.Fatalf("a refusal of %d bytes (limit %d) – it echoes input: %.200q", n, fuzzMaxError, err.Error())
	}
}

// checkJWK re-checks an accepted key against its source text: allowed type
// and curve, RSA size, no private member, the thumbprint of RFC 7638 and the
// round trip through Canonical.
func checkJWK(t *testing.T, raw []byte, k *Key) {
	t.Helper()
	m := refUnmarshalObject(t, "JWK", raw)
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := m[name]; ok {
			t.Fatalf("accepted a JWK with the private member %q", name)
		}
	}
	kty := refString(t, "kty", m["kty"])
	pub := k.Public()
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		crv := refString(t, "crv", m["crv"])
		size := 0
		switch {
		case kty == "EC" && crv == "P-256" && p.Curve == elliptic.P256():
			size = 32
		case kty == "EC" && crv == "P-384" && p.Curve == elliptic.P384():
			size = 48
		default:
			t.Fatalf("accepted an EC key of type %q curve %q (key curve %v)", kty, crv, p.Curve.Params().Name)
		}
		x := refB64(t, "x", refString(t, "x", m["x"]))
		y := refB64(t, "y", refString(t, "y", m["y"]))
		px, py := refPoint(t, p)
		if len(x) != size || len(y) != size || !bytes.Equal(x, px) || !bytes.Equal(y, py) {
			t.Fatalf("the key's point is not the JWK's x and y")
		}
		if !refOnCurve(t, p) {
			t.Fatalf("accepted a point that is not on %s", crv)
		}
	case *rsa.PublicKey:
		if kty != "RSA" {
			t.Fatalf("an RSA key from kty %q", kty)
		}
		n := refB64(t, "n", refString(t, "n", m["n"]))
		e := refB64(t, "e", refString(t, "e", m["e"]))
		if bits := p.N.BitLen(); bits < 2048 || bits > 8192 {
			t.Fatalf("accepted an RSA key of %d bits", bits)
		}
		if len(n) == 0 || n[0] == 0 || len(e) == 0 || e[0] == 0 || !bytes.Equal(n, p.N.Bytes()) || new(big.Int).SetBytes(e).Int64() != int64(p.E) {
			t.Fatalf("the key's n and e are not the JWK's, or not minimal")
		}
		if p.E < 3 || p.E%2 == 0 || len(e) > 4 || new(big.Int).SetBytes(e).Cmp(big.NewInt(1<<31-1)) > 0 {
			t.Fatalf("accepted RSA exponent %d", p.E)
		}
	case ed25519.PublicKey:
		if kty != "OKP" || refString(t, "crv", m["crv"]) != "Ed25519" {
			t.Fatalf("an Ed25519 key from kty %q", kty)
		}
		if x := refB64(t, "x", refString(t, "x", m["x"])); len(x) != 32 || !bytes.Equal(x, p) {
			t.Fatalf("the key is not the JWK's x")
		}
	default:
		t.Fatalf("accepted a key of type %T", pub)
	}
	alg := refAlg(pub)
	if alg == "" || k.Algorithm() != alg {
		t.Fatalf("the key signs with %q, the parser says %q", alg, k.Algorithm())
	}
	if raw, ok := m["alg"]; ok && refString(t, "alg", raw) != alg {
		t.Fatalf("accepted a JWK whose alg %s does not fit its key (%s)", raw, alg)
	}
	if want := refThumbprint(t, pub); k.Thumbprint() != want {
		t.Fatalf("thumbprint %s, RFC 7638 says %s", k.Thumbprint(), want)
	}
	// The canonical form parses again, to the same key, and is a fixed point.
	canon := k.Canonical()
	again, err := ParseJWK(canon)
	if err != nil {
		t.Fatalf("Canonical() does not parse: %v: %s", err, canon)
	}
	if again.Thumbprint() != k.Thumbprint() || !bytes.Equal(again.Canonical(), canon) || !k.Equal(again) {
		t.Fatalf("Canonical() is not a fixed point: %s -> %s", canon, again.Canonical())
	}
	wrapped, err := KeyFor(pub)
	if err != nil || wrapped.Thumbprint() != k.Thumbprint() {
		t.Fatalf("KeyFor(Public()) = %v, %v", wrapped, err)
	}
	cm := refUnmarshalObject(t, "canonical JWK", canon)
	if _, ok := cm["alg"]; ok || len(cm) < 3 || len(cm) > 4 {
		t.Fatalf("Canonical() has members beyond the required ones: %s", canon)
	}
}

// checkParsed re-reads the request body with encoding/json and compares it
// with what Parse or ParseInner accepted.
func checkParsed(t *testing.T, body []byte, j *JWS, inner bool) {
	t.Helper()
	top := refUnmarshalObject(t, "request body", body)
	if len(top) != 3 {
		t.Fatalf("accepted a body with %d members, flattened JWS has exactly 3", len(top))
	}
	var pb64, pl64, sig64 string
	for name, dst := range map[string]*string{"protected": &pb64, "payload": &pl64, "signature": &sig64} {
		raw, ok := top[name]
		if !ok {
			t.Fatalf("accepted a body without %q", name)
		}
		*dst = refString(t, name, raw)
	}
	sig := refB64(t, "signature", sig64)
	if !bytes.Equal(refB64(t, "payload", pl64), j.Payload) {
		t.Fatalf("the payload is not the decoded payload member")
	}
	h := refUnmarshalObject(t, "protected header", refB64(t, "protected", pb64))
	for _, name := range []string{"crit", "b64"} {
		if _, ok := h[name]; ok {
			t.Fatalf("accepted a header with %q", name)
		}
	}
	alg := refString(t, "alg", h["alg"])
	if alg != j.Alg || (alg != "ES256" && alg != "ES384" && alg != "RS256" && alg != "EdDSA") {
		t.Fatalf("accepted algorithm %q (parser says %q)", alg, j.Alg)
	}
	if u := refString(t, "url", h["url"]); u == "" || u != j.URL {
		t.Fatalf("url %q, parser says %q", u, j.URL)
	}
	_, hasNonce := h["nonce"]
	_, hasKID := h["kid"]
	rawJWK, hasJWK := h["jwk"]
	switch {
	case inner:
		if hasNonce || hasKID || !hasJWK || j.Nonce != "" || j.KID != "" || j.JWK == nil {
			t.Fatalf("an inner JWS must have a jwk and no nonce and no kid: %v", h)
		}
	default:
		if n := refString(t, "nonce", h["nonce"]); n == "" || n != j.Nonce {
			t.Fatalf("nonce %q, parser says %q", n, j.Nonce)
		}
		if hasJWK == hasKID {
			t.Fatalf("accepted a header with jwk=%v and kid=%v: exactly one is allowed", hasJWK, hasKID)
		}
	}
	if hasKID && !inner {
		if k := refString(t, "kid", h["kid"]); k == "" || k != j.KID || j.JWK != nil {
			t.Fatalf("kid %q, parser says %q (jwk %v)", k, j.KID, j.JWK)
		}
	}
	if hasJWK {
		if j.JWK == nil || j.KID != "" {
			t.Fatalf("a jwk header without a key in the result")
		}
		checkJWK(t, rawJWK, j.JWK)
		// Verify: the answer is the standard library's answer.
		err := j.Verify(j.JWK)
		ok := refVerify(j.JWK.Public(), []byte(pb64+"."+pl64), sig)
		switch {
		case alg != refAlg(j.JWK.Public()):
			if !errors.Is(err, ErrBadAlgorithm) {
				t.Fatalf("header %s with a %s key verified or failed with %v", alg, refAlg(j.JWK.Public()), err)
			}
		case ok && err != nil:
			t.Fatalf("a valid signature is refused: %v", err)
		case !ok && err == nil:
			t.Fatalf("an invalid signature is accepted")
		case err != nil && !errors.Is(err, ErrBadSignature):
			t.Fatalf("a bad signature is reported as %v", err)
		}
	}
}

func addBodies(f *testing.F) {
	f.Helper()
	valid, invalid := fuzzSeeds().bodies(f)
	for _, b := range valid {
		f.Add(b)
	}
	for _, b := range invalid {
		f.Add(b)
	}
}

func fuzzParseTarget(f *testing.F, inner bool) {
	f.Helper()
	addBodies(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		parse := Parse
		if inner {
			parse = ParseInner
		}
		j, err := parse(data)
		if time.Since(start) > fuzzMaxTime {
			t.Fatalf("one input took %v", time.Since(start))
		}
		if err != nil {
			checkRefusal(t, err)
			return
		}
		checkParsed(t, data, j, inner)
	})
}

// FuzzParse: no input makes the parser panic or take long, a refusal is
// typed and short, and what it accepts keeps its promises: an allowed
// algorithm, a nonce, a URL and exactly one of jwk and kid, no crit and no
// b64, no unprotected header, no duplicate member, a signature that Verify
// judges like the standard library.
//
// testdata/fuzz/FuzzParse/9b96ca1cadb19878 is a regression input the fuzzer wrote: an
// object whose first member name is about 100 bytes of invalid UTF-8; the
// refusal repeated the whole name (fixed, see TestRefusalsDoNotEchoTheRequest).
func FuzzParse(f *testing.F) { fuzzParseTarget(f, false) }

// FuzzParseInner: the same for the inner JWS of a key change, which has the
// new key in "jwk" and neither a nonce nor a kid.
func FuzzParseInner(f *testing.F) { fuzzParseTarget(f, true) }

// FuzzParseJWK: an accepted key has an allowed type and curve, RSA of 2048
// to 8192 bits, no private member, the RFC 7638 thumbprint, and Canonical()
// parses again to the same key.
func FuzzParseJWK(f *testing.F) {
	set := fuzzSeeds()
	for _, alg := range []string{ES256, ES384, RS256, EdDSA} {
		f.Add([]byte(set.signers[alg].jwk))
	}
	for _, s := range []string{
		`{"kty":"RSA","n":"` + rfcRSAn + `","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`,
		`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","y":"` + rfcECy + `"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"` + rfcEdX + `"}`,
		`{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"}`,
		`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","y":"` + rfcECx + `"}`, // not on the curve
		`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","y":"` + rfcECy + `","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`,
		`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","y":"` + rfcECy + `","alg":"ES384"}`,
		`{"kty":"EC","crv":"P-256","x":"` + rfcECx + `","x":"` + rfcECx + `","y":"` + rfcECy + `"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"` + rfcEdX + `"}`,
		`{"kty":"RSA","n":"` + b64.EncodeToString(new(big.Int).Lsh(big.NewInt(1), 1023).Bytes()) + `","e":"AQAB"}`, // 1024 bits
		`{"kty":"RSA","n":"` + rfcRSAn + `","e":"AQAA"}`,                                                           // even exponent
		`{"kty":"RSA","n":"AA` + rfcRSAn[2:] + `","e":"AQAB"}`,                                                     // leading zero
		`{"kty":"RSA","n":"` + rfcRSAn + `","e":"AQAB","p":"AQ"}`,
		`{"kty":"oct","k":"c2VjcmV0"}`,
		`{"kty":"OKP","crv":"Ed448","x":"` + rfcEdX + `"}`,
		`{"kty":"EC"}`,
		`{}`, `[]`, `null`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		k, err := ParseJWK(data)
		if time.Since(start) > fuzzMaxTime {
			t.Fatalf("one input took %v", time.Since(start))
		}
		if err != nil {
			checkRefusal(t, err)
			return
		}
		checkJWK(t, data, k)
	})
}

// FuzzVerifyEAB: an accepted external account binding has the header
// {alg: HS256, kid, url} and nothing else, the URL of the request, the
// account's own key as payload and a MAC that HMAC-SHA-256 over the signing
// input reproduces; the returned ID is the header's.
func FuzzVerifyEAB(f *testing.F) {
	set := fuzzSeeds()
	acct := set.signers[ES256]
	acctKey, err := ParseJWK([]byte(acct.jwk))
	if err != nil {
		f.Fatal(err)
	}
	other := set.signers[EdDSA]
	macKey := []byte("a mac key the admin created, 32b")
	const url = "https://acme.example/acme/new-account"
	eab := func(header, payload string, key []byte) []byte {
		ph, pl := b64.EncodeToString([]byte(header)), b64.EncodeToString([]byte(payload))
		m := hmac.New(sha256.New, key)
		m.Write([]byte(ph + "." + pl))
		return []byte(`{"protected":"` + ph + `","payload":"` + pl + `","signature":"` + b64.EncodeToString(m.Sum(nil)) + `"}`)
	}
	hdr := `{"alg":"HS256","kid":"eab-1","url":"` + url + `"}`
	f.Add(eab(hdr, acct.jwk, macKey))
	f.Add(eab(hdr, " "+acct.jwk+"\n", macKey)) // white space around the payload JSON
	f.Add(eab(hdr, acct.jwk, []byte("another key of thirty-two bytes!")))
	f.Add(eab(hdr, other.jwk, macKey))
	f.Add(eab(`{"alg":"HS256","kid":"eab-1","url":"`+url+`","nonce":"x"}`, acct.jwk, macKey))
	f.Add(eab(`{"alg":"HS512","kid":"eab-1","url":"`+url+`"}`, acct.jwk, macKey))
	f.Add(eab(`{"alg":"none","kid":"eab-1","url":"`+url+`"}`, acct.jwk, macKey))
	f.Add(eab(`{"alg":"HS256","kid":"eab-1","url":"https://acme.example/acme/elsewhere"}`, acct.jwk, macKey))
	f.Add(eab(`{"alg":"HS256","kid":"eab-2","url":"`+url+`"}`, acct.jwk, macKey))
	f.Add(eab(`{"alg":"HS256","kid":"eab-1","kid":"eab-2","url":"`+url+`"}`, acct.jwk, macKey))
	f.Add(eab(`{"alg":"HS256","kid":"","url":"`+url+`"}`, acct.jwk, macKey))
	f.Add([]byte(`{"protected":"e30","payload":"e30","signature":"","header":{}}`))
	f.Add([]byte(`{"protected":"","payload":"","signature":""}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var lookups []string
		lookup := func(kid string) ([]byte, error) {
			lookups = append(lookups, kid)
			if kid != "eab-1" {
				return nil, errors.New("unknown EAB key")
			}
			return macKey, nil
		}
		start := time.Now()
		kid, err := VerifyEAB(data, acctKey, url, lookup)
		if time.Since(start) > fuzzMaxTime {
			t.Fatalf("one input took %v", time.Since(start))
		}
		if len(lookups) > 1 || (len(lookups) == 1 && lookups[0] == "") {
			t.Fatalf("the MAC key was looked up %q", lookups)
		}
		if err != nil {
			if len(err.Error()) > fuzzMaxError {
				t.Fatalf("a refusal of %d bytes echoes input: %.200q", len(err.Error()), err.Error())
			}
			return
		}
		top := refUnmarshalObject(t, "externalAccountBinding", data)
		if len(top) != 3 {
			t.Fatalf("accepted a binding with %d members", len(top))
		}
		pb64 := refString(t, "protected", top["protected"])
		pl64 := refString(t, "payload", top["payload"])
		sig64 := refString(t, "signature", top["signature"])
		h := refUnmarshalObject(t, "binding header", refB64(t, "protected", pb64))
		if len(h) != 3 {
			t.Fatalf("accepted a binding header with %d members: only alg, kid and url", len(h))
		}
		if refString(t, "alg", h["alg"]) != "HS256" {
			t.Fatalf("accepted a binding that is not HS256")
		}
		if refString(t, "url", h["url"]) != url {
			t.Fatalf("accepted a binding for another URL")
		}
		if hk := refString(t, "kid", h["kid"]); hk == "" || hk != kid || len(lookups) != 1 || lookups[0] != kid {
			t.Fatalf("returned ID %q, header kid %q, looked up %q", kid, hk, lookups)
		}
		// The payload is the account's own key, member by member.
		payload := refB64(t, "payload", pl64)
		pm := refUnmarshalObject(t, "binding payload", payload)
		wantPub, ok := acctKey.Public().(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("the test account key is not ECDSA")
		}
		if refString(t, "kty", pm["kty"]) != "EC" || refString(t, "crv", pm["crv"]) != "P-256" {
			t.Fatalf("accepted a binding for another key: %s", clipBytes(payload))
		}
		wx, wy := refPoint(t, wantPub)
		x := refB64(t, "x", refString(t, "x", pm["x"]))
		y := refB64(t, "y", refString(t, "y", pm["y"]))
		if !bytes.Equal(x, wx) || !bytes.Equal(y, wy) {
			t.Fatalf("accepted a binding for another key: %s", clipBytes(payload))
		}
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, present := pm[name]; present {
				t.Fatalf("accepted a binding whose key has the private member %q", name)
			}
		}
		mac := hmac.New(sha256.New, macKey)
		mac.Write([]byte(pb64 + "." + pl64))
		if !bytes.Equal(mac.Sum(nil), refB64(t, "signature", sig64)) {
			t.Fatalf("accepted a binding whose MAC is not HMAC-SHA-256 of the signing input")
		}
	})
}

// TestFuzzHelpersSeeAFailure keeps the independent checks honest: each one
// must refuse an input that breaks its rule, otherwise a fuzz target could
// pass because the check can never fail.
func TestFuzzHelpersSeeAFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		data string
		dup  bool
	}{
		{`{"a":1,"b":2}`, false},
		{`{"a":1,"a":2}`, true},
		{`{"a":{"b":1,"b":2}}`, false}, // nested names are not the outer object's
		{`{"a":[1,2],"b":"x","a":null}`, true},
		{`{"a":"x","a":"y"}`, true},
		{`{"a":"x","b":"x","c":{"d":1},"c":2}`, true},
	} {
		if got := refHasDuplicateMember([]byte(tc.data)); got != tc.dup {
			t.Errorf("%s: duplicate = %v", tc.data, got)
		}
	}
}

// refPoint is the affine point of an EC key as two fixed-length big-endian
// numbers, read from the uncompressed encoding (04 || x || y).
func refPoint(t *testing.T, p *ecdsa.PublicKey) (x, y []byte) {
	t.Helper()
	b, err := p.Bytes()
	if err != nil || len(b) < 3 || b[0] != 4 || len(b)%2 == 0 {
		t.Fatalf("an EC key without an uncompressed point: %v", err)
	}
	size := (len(b) - 1) / 2
	return b[1 : 1+size], b[1+size:]
}
