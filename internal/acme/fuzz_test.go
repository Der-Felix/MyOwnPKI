package acme

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Fuzz targets of the ACME payload helpers (PHASE3 section 18.2): the
// production functions are called unchanged; what they accept is re-checked
// with the standard library and code written here, never with the helpers
// of the function under test. No database, no network, no real clock.

const (
	// fuzzMaxTime is the wall time one input may take (section 18.2, rule 2).
	fuzzMaxTime = 2 * time.Second
	// fuzzMaxDetail bounds the text of a refusal. The names the ca package
	// quotes are at most 253 bytes (longer ones are cut by its short()) and a
	// message can quote one twice; what must not happen is a text that grows
	// with the input.
	fuzzMaxDetail = 700
)

// refDetail returns the problem of a refusal: it must be an *acmeError with
// one of the expected types and a text that is short.
func refDetail(t *testing.T, err error, status int, types ...string) {
	t.Helper()
	var ae *acmeError
	if !errors.As(err, &ae) {
		t.Fatalf("a refusal that is no ACME problem: %T %v", err, err)
	}
	if ae.status != status {
		t.Fatalf("status %d, want %d (%s: %s)", ae.status, status, ae.typ, ae.detail)
	}
	known := false
	for _, typ := range types {
		known = known || ae.typ == typ
	}
	if !known {
		t.Fatalf("problem type %q, want one of %v", ae.typ, types)
	}
	if len(ae.detail) > fuzzMaxDetail {
		t.Fatalf("a refusal text of %d bytes (limit %d) echoes input: %.200q", len(ae.detail), fuzzMaxDetail, ae.detail)
	}
}

var refLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// refCheckDNS says why a name is no lower-case LDH name of an order, or "".
// It follows RFC 1123 and CA/B Forum BR 3.2.2.6: ASCII, at most 253 bytes,
// labels of 1 to 63 characters, letters digits and hyphens, no hyphen at
// either end, "--" at positions 3 and 4 only for "xn--", no trailing dot, a
// wildcard only as the whole first label with two more labels behind it, a
// last label that is not all digits.
func refCheckDNS(name string) string {
	if name == "" || len(name) > 253 {
		return "length"
	}
	for i := range len(name) {
		if name[i] >= 0x80 {
			return "not ASCII"
		}
		if name[i] >= 'A' && name[i] <= 'Z' {
			return "upper case"
		}
	}
	labels := strings.Split(name, ".")
	if labels[0] == "*" {
		if len(labels) < 3 {
			return "wildcard too broad"
		}
		labels = labels[1:]
	}
	for _, l := range labels {
		switch {
		case l == "" || len(l) > 63:
			return "label length"
		case !refLabel.MatchString(l):
			return "label characters"
		case len(l) >= 4 && l[2] == '-' && l[3] == '-' && !strings.HasPrefix(l, "xn--"):
			return "reserved hyphens"
		}
	}
	allDigits := true
	for _, c := range labels[len(labels)-1] {
		allDigits = allDigits && c >= '0' && c <= '9'
	}
	if allDigits {
		return "last label is all digits"
	}
	if net.ParseIP(name) != nil {
		return "an IP address"
	}
	return ""
}

// FuzzNormalizeIdentifier: no input panics; an accepted dns name is lower
// case LDH of the input, an accepted ip is the canonical text of the same
// address without a zone, and normalizing twice gives the same result.
func FuzzNormalizeIdentifier(f *testing.F) {
	for _, s := range [][2]string{
		{"dns", "example.com"}, {"dns", "Example.COM"}, {"dns", "*.wild.example.com"}, {"dns", "*.example"},
		{"dns", "a.*.example.com"}, {"dns", "*"}, {"dns", ""}, {"dns", "."}, {"dns", "example.com."},
		{"dns", "-a.example.com"}, {"dns", "a-.example.com"}, {"dns", "ab--c.example.com"}, {"dns", "xn--nxasmq6b.example.com"},
		{"dns", "bücher.example"}, {"dns", "a..example.com"}, {"dns", "a b.example.com"}, {"dns", "1.2.3.4"},
		{"dns", "example.123"}, {"dns", "2001:db8::1"}, {"dns", strings.Repeat("a", 64) + ".example.com"},
		{"dns", strings.Repeat("a.", 130) + "com"}, {"dns", "fe80::1%" + strings.Repeat("z", 200)},
		{"dns", "example.com\x00"}, {"dns", "example.com\n"}, {"dns", strings.Repeat("\xff", 5000)},
		{"ip", "192.0.2.1"}, {"ip", "2001:DB8::1"}, {"ip", "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"ip", "::ffff:192.0.2.1"}, {"ip", "fe80::1%eth0"}, {"ip", "192.0.2.01"}, {"ip", "192.0.2.1/24"},
		{"ip", " 192.0.2.1"}, {"ip", "0.0.0.0"}, {"ip", "::"}, {"ip", "1.2.3"}, {"ip", "example.com"}, {"ip", strings.Repeat("1", 5000)},
		{"email", "a@example.com"}, {"", ""}, {"DNS", "example.com"}, {"dns ", "example.com"}, {strings.Repeat("x", 5000), "example.com"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, typ, value string) {
		start := time.Now()
		got, err := normalize(identifier{Type: typ, Value: value})
		if time.Since(start) > fuzzMaxTime {
			t.Fatalf("one input took %v", time.Since(start))
		}
		if err != nil {
			refDetail(t, err, 400, "rejectedIdentifier", "malformed", "unsupportedIdentifier")
			if typ != "dns" && typ != "ip" {
				refDetail(t, err, 400, "unsupportedIdentifier")
			}
			return
		}
		if got.Type != typ {
			t.Fatalf("type %q became %q", typ, got.Type)
		}
		switch typ {
		case "dns":
			if why := refCheckDNS(got.Value); why != "" {
				t.Fatalf("accepted %q as %q, which is no LDH name (%s)", value, got.Value, why)
			}
			if got.Value != strings.ToLower(value) {
				t.Fatalf("accepted %q but returned %q: only the case may change", value, got.Value)
			}
		case "ip":
			ip := net.ParseIP(value)
			if ip == nil || strings.ContainsAny(value, "%/ ") {
				t.Fatalf("accepted %q, which net.ParseIP does not read as an address", value)
			}
			back := net.ParseIP(got.Value)
			if back == nil || !back.Equal(ip) || back.String() != got.Value || strings.ContainsAny(got.Value, "%") {
				t.Fatalf("accepted %q as %q: not the canonical text of the same address", value, got.Value)
			}
			if len(got.Value) > 45 {
				t.Fatalf("an address of %d characters", len(got.Value))
			}
		default:
			t.Fatalf("accepted the identifier type %q", typ)
		}
		again, err := normalize(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %+v became %+v (%v)", got, again, err)
		}
	})
}

// FuzzParseARIID: an accepted identifier is two canonical base64url parts,
// a non-empty authority key ID and the minimal DER content of a positive
// INTEGER of at most 20 octets; ariID of such a certificate gives the
// identifier back. The other direction (a certificate's identifier always
// parses, unless the serial is too long or the authority key ID is empty)
// is checked with the two extra inputs.
func FuzzParseARIID(f *testing.F) {
	f.Add("", []byte(nil), []byte(nil))
	f.Add("AQID.AQ", []byte{1, 2, 3}, []byte{1})
	f.Add("AQID.AA", []byte{1, 2, 3}, []byte{})      // serial 0: one zero octet
	f.Add("AQID.AP8", []byte{1, 2, 3}, []byte{0xff}) // 255 needs a leading zero
	f.Add("AQID.__8", []byte{1, 2, 3}, []byte{0xff}) // a high bit without it: negative
	f.Add("AQID.AAE", []byte{1, 2, 3}, []byte{1})    // not minimal
	f.Add("AQID.AQ.", []byte{1}, []byte{1})          // a third part
	f.Add(".AQ", []byte(nil), []byte{1})             // no authority key ID
	f.Add("AQID.AQ=", []byte{1, 2, 3}, []byte{1})    // padding
	f.Add("AQID.AR", []byte{1, 2, 3}, []byte{1})     // stray bits
	f.Add("AQID", []byte{1, 2, 3}, []byte{1})        // no dot
	f.Add(strings.Repeat("A", 190)+".AQ", []byte{1}, []byte{1})
	f.Add("AQID."+strings.Repeat("_", 40), []byte{1}, bytes.Repeat([]byte{0xff}, 30))
	f.Add("AQID.AP"+strings.Repeat("_", 28), []byte{1}, append([]byte{0}, bytes.Repeat([]byte{0xff}, 20)...))
	f.Add("YWI.AQ", []byte("ab"), bytes.Repeat([]byte{1}, 20))
	f.Fuzz(func(t *testing.T, id string, aki, serialBytes []byte) {
		start := time.Now()
		gotAKI, gotSerial, err := parseARIID(id)
		if time.Since(start) > fuzzMaxTime {
			t.Fatalf("one input took %v", time.Since(start))
		}
		if err != nil {
			refDetail(t, err, 400, "malformed")
		} else {
			parts := strings.Split(id, ".")
			if len(parts) != 2 || len(id) > 200 {
				t.Fatalf("accepted %q", id)
			}
			wantAKI, errA := base64.RawURLEncoding.DecodeString(parts[0])
			sb, errS := base64.RawURLEncoding.DecodeString(parts[1])
			if errA != nil || errS != nil || base64.RawURLEncoding.EncodeToString(wantAKI) != parts[0] || base64.RawURLEncoding.EncodeToString(sb) != parts[1] {
				t.Fatalf("accepted %q, which is not canonical base64url", id)
			}
			if len(wantAKI) == 0 || len(sb) == 0 || !bytes.Equal(gotAKI, wantAKI) {
				t.Fatalf("accepted %q with the authority key ID %x, read %x", id, wantAKI, gotAKI)
			}
			// The serial is a positive INTEGER in minimal DER, at most 20 octets
			// plus the leading zero: encoding/asn1 writes the same content.
			value := new(big.Int).SetBytes(sb)
			der, merr := asn1.Marshal(value)
			if merr != nil || len(der) < 3 || !bytes.Equal(der[2:], sb) || len(sb) > 21 || sb[0]&0x80 != 0 {
				t.Fatalf("accepted %q whose serial %x is no minimal positive DER INTEGER of at most 21 octets", id, sb)
			}
			if gotSerial.Cmp(value) != 0 || gotSerial.Sign() < 0 {
				t.Fatalf("accepted %q with the serial %v, expected %v", id, gotSerial, value)
			}
			if again := ariID(&x509.Certificate{SerialNumber: gotSerial, AuthorityKeyId: gotAKI}); again != id {
				t.Fatalf("round trip: %q parsed and written as %q", id, again)
			}
		}

		// A certificate's own identifier parses back to it, unless it cannot.
		serial := new(big.Int).SetBytes(serialBytes)
		minimal, merr := asn1.Marshal(serial)
		if merr != nil {
			t.Fatal(merr)
		}
		own := ariID(&x509.Certificate{SerialNumber: serial, AuthorityKeyId: aki})
		a, s, perr := parseARIID(own)
		fits := len(aki) > 0 && len(minimal)-2 <= 21 && len(own) <= 200
		switch {
		case fits && perr != nil:
			t.Fatalf("the identifier %q of serial %v with %d key ID bytes is refused: %v", own, serial, len(aki), perr)
		case fits && (!bytes.Equal(a, aki) || s.Cmp(serial) != 0):
			t.Fatalf("the identifier %q parsed to %x and %v, expected %x and %v", own, a, s, aki, serial)
		case !fits && perr == nil:
			t.Fatalf("accepted %q for %d key ID bytes and the serial %v (too long or empty)", own, len(aki), serial)
		}
	})
}

// csrFuzz is the fixed world of FuzzCheckCSR: an order, an account key and a
// certificate key, made once per process.
type csrFuzz struct {
	order   pkidb.AcmeOrder
	wantDNS []string
	wantIP  []net.IP
	account ed25519.PrivateKey
	key     ed25519.PrivateKey
}

var csrWorld = sync.OnceValue(func() *csrFuzz {
	w := &csrFuzz{
		wantDNS: []string{"example.com", "www.example.com", "kdc.example.com", "*.wild.example.com"},
		wantIP:  []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
	}
	ids := []identifier{
		{"dns", "example.com"}, {"dns", "www.example.com"}, {"dns", "kdc.example.com"}, {"dns", "*.wild.example.com"},
		{"ip", "192.0.2.1"}, {"ip", "2001:db8::1"},
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		panic(err)
	}
	w.order = pkidb.AcmeOrder{ID: "order-1", AccountID: "acct-1", Status: "ready", Identifiers: string(raw)}
	_, w.account, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	_, w.key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return w
})

// refAsciiLower lower-cases ASCII letters only, which is what a DNS name
// compares by; unicode.ToLower would also fold U+212A (the Kelvin sign) onto
// "k".
func refAsciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// refVerdict is the verdict of the rules of checkCSR, written out from
// RFC 8555 section 7.4 and 11.1: the signature verifies, no e-mail address
// or URI, the DNS names and IP addresses and the common name (which must be
// one of the order's names) together are exactly the order's names, and the
// key is not the account's key.
func (w *csrFuzz) refVerdict(der []byte, accountKey crypto.PublicKey) (ok bool, why string) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return false, "does not parse"
	}
	if csr.CheckSignature() != nil {
		return false, "signature"
	}
	if len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return false, "e-mail or URI"
	}
	got := map[string]bool{}
	for _, d := range csr.DNSNames {
		got["dns:"+refAsciiLower(d)] = true
	}
	for _, ip := range csr.IPAddresses {
		got["ip:"+ip.String()] = true
	}
	if cn := csr.Subject.CommonName; cn != "" {
		key := "dns:" + refAsciiLower(cn)
		if ip := net.ParseIP(cn); ip != nil {
			key = "ip:" + ip.String()
		}
		if !w.wants(key) {
			return false, "common name"
		}
		got[key] = true
	}
	want := map[string]bool{}
	for _, d := range w.wantDNS {
		want["dns:"+d] = true
	}
	for _, ip := range w.wantIP {
		want["ip:"+ip.String()] = true
	}
	if len(got) != len(want) {
		return false, "names differ"
	}
	for k := range got {
		if !want[k] {
			return false, "names differ"
		}
	}
	if eq, isEq := csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); isEq && eq.Equal(accountKey) {
		return false, "account key"
	}
	return true, ""
}

func (w *csrFuzz) wants(key string) bool {
	for _, d := range w.wantDNS {
		if key == "dns:"+d {
			return true
		}
	}
	for _, ip := range w.wantIP {
		if key == "ip:"+ip.String() {
			return true
		}
	}
	return false
}

// build signs a request from the fuzzed fields; ok is false when the
// standard library refuses to encode them.
func (w *csrFuzz) build(key ed25519.PrivateKey, cn, dns, ips, email, uri string) ([]byte, bool) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	if dns != "" {
		tmpl.DNSNames = strings.Split(dns, ",")
	}
	if len(tmpl.DNSNames) > 16 {
		return nil, false
	}
	if ips != "" {
		for s := range strings.SplitSeq(ips, ",") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, false
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	if email != "" {
		tmpl.EmailAddresses = []string{email}
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, false
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, false
	}
	return der, true
}

// FuzzCheckCSR: the order and the account key are fixed. The target feeds
// checkCSR the fuzzed bytes as they are and a CSR it signs itself from the
// fuzzed names, and compares the answer with an independent verdict in both
// directions: what checkCSR accepts has a valid signature, exactly the
// order's DNS names and IPs, no e-mail address or URI, a common name that
// is one of the order's names and a key that is not the account's key; and
// what the verdict accepts is not refused.
func FuzzCheckCSR(f *testing.F) {
	w := csrWorld()
	good := "example.com,www.example.com,kdc.example.com,*.wild.example.com"
	ips := "192.0.2.1,2001:db8::1"
	seed := func(cn, dns, ip, email, uri string, byAccount bool) {
		key := w.key
		if byAccount {
			key = w.account
		}
		der, _ := w.build(key, cn, dns, ip, email, uri)
		f.Add(der, cn, dns, ip, email, uri, byAccount)
	}
	seed("example.com", good, ips, "", "", false)
	seed("", good, ips, "", "", false)
	seed("EXAMPLE.com", strings.ToUpper(good), ips, "", "", false)
	seed("192.0.2.1", good, ips, "", "", false)
	seed("::ffff:192.0.2.1", good, ips, "", "", false)
	seed("2001:DB8::1", good, "192.0.2.1,2001:db8:0:0:0:0:0:1", "", "", false)
	seed("example.com", good, "192.0.2.1,::ffff:192.0.2.1,2001:db8::1", "", "", false)
	seed("Kdc.example.com", good, ips, "", "", false) // Kelvin sign, folds onto "k" in unicode
	seed("other.example.org", good, ips, "", "", false)
	seed("example.com", good, ips, "admin@example.com", "", false)
	seed("example.com", good, ips, "", "https://example.com/", false)
	seed("example.com", good, ips, "", "", true)
	seed("example.com", "example.com", ips, "", "", false) // names missing
	seed("example.com", good+",extra.example.com", ips, "", "", false)
	seed("example.com", good, "192.0.2.1", "", "", false)
	seed("example.com", good, ips+",192.0.2.2", "", "", false)
	seed("", "", "", "", "", false)
	f.Add([]byte(nil), "", "", "", "", "", false)
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----"), "", "", "", "", "", false)
	f.Add(bytes.Repeat([]byte{0x30, 0x82}, 100), "", "", "", "", "", false)

	f.Fuzz(func(t *testing.T, raw []byte, cn, dns, ipList, email, uri string, byAccount bool) {
		s := &Server{}
		check := func(what string, der []byte) {
			t.Helper()
			start := time.Now()
			err := s.checkCSR(&w.order, der, w.account.Public())
			if time.Since(start) > fuzzMaxTime {
				t.Fatalf("%s: one input took %v", what, time.Since(start))
			}
			ok, why := w.refVerdict(der, w.account.Public())
			switch {
			case err == nil && !ok:
				t.Fatalf("%s: accepted a CSR that breaks a rule (%s): cn=%q dns=%q ips=%q email=%q uri=%q", what, why, cn, dns, ipList, email, uri)
			case err != nil && ok:
				t.Fatalf("%s: refused a CSR that follows every rule: %v", what, err)
			case err != nil:
				refDetail(t, err, 400, "badCSR")
			}
		}
		check("raw bytes", raw)
		key := w.key
		if byAccount {
			key = w.account
		}
		if der, ok := w.build(key, cn, dns, ipList, email, uri); ok {
			check("built", der)
		}
	})
}

// TestCheckCSRCommonNameIsAnIdentifier: found by FuzzCheckCSR – the common
// name was lower-cased with strings.ToLower, so "Kdc.example.com" (the
// Kelvin sign) passed as the order's "kdc.example.com" and went on into the
// issued certificate's subject. Only the case of ASCII letters may differ.
func TestCheckCSRCommonNameIsAnIdentifier(t *testing.T) {
	t.Parallel()
	w := csrWorld()
	s := &Server{}
	names := "example.com,www.example.com,kdc.example.com,*.wild.example.com"
	ips := "192.0.2.1,2001:db8::1"
	for cn, wantOK := range map[string]bool{
		"kdc.example.com":  true,
		"KDC.Example.COM":  true,
		"Kdc.example.com":  false, // Kelvin sign
		"kdc.example.coṁ": false,
		"kdc.examplе.com":  false, // Cyrillic e
	} {
		der, ok := w.build(w.key, cn, names, ips, "", "")
		if !ok {
			t.Fatalf("cannot build a CSR for %q", cn)
		}
		err := s.checkCSR(&w.order, der, w.account.Public())
		if (err == nil) != wantOK {
			t.Errorf("common name %q: error %v, accepted should be %v", cn, err, wantOK)
		}
	}
}
