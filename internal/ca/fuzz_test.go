package ca

import (
	"bytes"
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
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/Der-Felix/MyOwnPKI/internal/testutil/racemode"
)

// Fuzz targets of the parsers that read attacker input in this package (docs/PHASE3.md §18.2): the CSR and
// certificate uploads, the names of a request and the CRL upload. Every target calls the production function
// unchanged and re-checks what it promises with code of its own. Seeds are built here; files under
// testdata/fuzz are only what the fuzzer wrote after a failure.

// fuzzDeadline is the longest one input may take.
var fuzzDeadline = racemode.Scale(2 * time.Second)

// fuzzTimer fails the target when one input needed longer than fuzzDeadline: a slow input is a denial of
// service on the server, whatever it returns.
func fuzzTimer(t *testing.T) func() {
	t.Helper()
	start := time.Now()
	return func() {
		if d := time.Since(start); d > fuzzDeadline {
			t.Errorf("one input took %v (limit %v)", d, fuzzDeadline)
		}
	}
}

type fuzzKeySet struct {
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
	rsa *rsa.PrivateKey
}

// fuzzKeys generates the test keys once per process, not once per input.
var fuzzKeys = sync.OnceValue(func() fuzzKeySet {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return fuzzKeySet{ec, ed, rk}
})

func fuzzCSRDER(tmpl *x509.CertificateRequest, key crypto.Signer) []byte {
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		panic(err)
	}
	return der
}

func fuzzPEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// pemCount is how many PEM blocks the text announces, whether they decode or not.
func pemCount(data []byte) int { return bytes.Count(data, []byte("-----BEGIN ")) }

// onlySpace: nothing but white space (Unicode, as a person pastes it).
func onlySpace(b []byte) bool {
	return strings.TrimFunc(string(b), unicode.IsSpace) == ""
}

// onePEMBlock re-reads data as the upload rules promise it: one PEM block of an allowed type, no headers,
// nothing but white space after it. It returns the DER or the rule that is broken.
func onePEMBlock(data []byte, types ...string) ([]byte, string) {
	if n := pemCount(data); n != 1 {
		return nil, fmt.Sprintf("%d PEM blocks announced, want exactly one", n)
	}
	block, rest := pem.Decode(data)
	switch {
	case block == nil:
		return nil, "no PEM block decodes"
	case !slices.Contains(types, block.Type):
		return nil, fmt.Sprintf("block type %q", block.Type)
	case len(block.Headers) > 0:
		return nil, "the block has headers"
	case !onlySpace(rest):
		return nil, "data after the block"
	}
	return block.Bytes, ""
}

// checkRefusal: a refusal of an upload is a DeniedError (a 4xx for the client, not a failure of the server)
// and its text is short.
func checkRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if _, ok := err.(*DeniedError); !ok { //nolint:errorlint // the refusal itself, not a wrapped one
		t.Errorf("%s: refusal is %T, want *DeniedError: %v", what, err, err)
	}
	if n := len(err.Error()); n > 600 {
		t.Errorf("%s: refusal text is %d bytes: %.200q…", what, n, err.Error())
	}
}

// verifyCSRSignature checks the self-signature of a parsed CSR without x509's CheckSignature. checked is
// false for algorithms this helper does not implement (SHA-1 and the like).
func verifyCSRSignature(csr *x509.CertificateRequest) (checked bool, err error) {
	var h crypto.Hash
	var scheme string // the signature scheme the algorithm names: ecdsa, pkcs1 or pss
	switch csr.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		h, scheme = crypto.SHA256, "ecdsa"
	case x509.ECDSAWithSHA384:
		h, scheme = crypto.SHA384, "ecdsa"
	case x509.ECDSAWithSHA512:
		h, scheme = crypto.SHA512, "ecdsa"
	case x509.SHA256WithRSA:
		h, scheme = crypto.SHA256, "pkcs1"
	case x509.SHA384WithRSA:
		h, scheme = crypto.SHA384, "pkcs1"
	case x509.SHA512WithRSA:
		h, scheme = crypto.SHA512, "pkcs1"
	case x509.SHA256WithRSAPSS:
		h, scheme = crypto.SHA256, "pss"
	case x509.SHA384WithRSAPSS:
		h, scheme = crypto.SHA384, "pss"
	case x509.SHA512WithRSAPSS:
		h, scheme = crypto.SHA512, "pss"
	case x509.PureEd25519:
		pub, ok := csr.PublicKey.(ed25519.PublicKey)
		if !ok {
			return true, fmt.Errorf("Ed25519 signature, key is %T", csr.PublicKey)
		}
		if !ed25519.Verify(pub, csr.RawTBSCertificateRequest, csr.Signature) {
			return true, errors.New("Ed25519 signature does not verify")
		}
		return true, nil
	default:
		return false, nil // SHA-1, DSA and the rest: not re-checked here
	}
	var digest []byte
	switch h {
	case crypto.SHA256:
		s := sha256.Sum256(csr.RawTBSCertificateRequest)
		digest = s[:]
	case crypto.SHA384:
		s := sha512.Sum384(csr.RawTBSCertificateRequest)
		digest = s[:]
	default:
		s := sha512.Sum512(csr.RawTBSCertificateRequest)
		digest = s[:]
	}
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if scheme == "ecdsa" {
			if !ecdsa.VerifyASN1(pub, digest, csr.Signature) {
				return true, errors.New("ECDSA signature does not verify")
			}
			return true, nil
		}
	case *rsa.PublicKey:
		switch scheme {
		case "pkcs1":
			return true, rsa.VerifyPKCS1v15(pub, h, digest, csr.Signature)
		case "pss":
			return true, rsa.VerifyPSS(pub, h, digest, csr.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	}
	return true, fmt.Errorf("signature algorithm %v with a %T key", csr.SignatureAlgorithm, csr.PublicKey)
}

// inspectionBytes is every byte the preview of a CSR hands back.
func inspectionBytes(in *CSRInspection) (n, items int) {
	for _, list := range [][]string{in.DNSNames, in.IPs, in.Emails, in.URIs, in.RequestedExtensions, in.Problems, in.Warnings} {
		items += len(list)
		for _, s := range list {
			n += len(s)
		}
	}
	return n + len(in.Subject) + len(in.CommonName) + len(in.KeyAlgorithm), items
}

func FuzzParseCSR(f *testing.F) {
	k := fuzzKeys()
	good := fuzzCSRDER(&x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "nas.homelab.lan", Organization: []string{"Homelab"}},
		DNSNames:       []string{"nas.homelab.lan", "*.nas.homelab.lan"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")},
		EmailAddresses: []string{"admin@homelab.lan"},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "homelab.lan", Path: "/workload"}},
	}, k.ec)
	goodPEM := fuzzPEM("CERTIFICATE REQUEST", good)
	bc, err := asn1.Marshal(struct {
		CA bool `asn1:"optional"`
	}{true})
	if err != nil {
		f.Fatal(err)
	}
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}) // keyCertSign, cRLSign
	if err != nil {
		f.Fatal(err)
	}
	caCSR := fuzzCSRDER(&x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "i want to be a CA"},
		DNSNames: []string{"evil.homelab.lan"},
		ExtraExtensions: []pkix.Extension{
			{Id: oidBasicConstraints, Critical: true, Value: bc},
			{Id: oidKeyUsageExt, Critical: true, Value: ku},
			{Id: oidNameConstraints, Value: []byte{0x30, 0x00}},
		},
	}, k.ec)
	var many []string
	for i := range 2500 {
		many = append(many, "host"+strconv.Itoa(i)+".homelab.lan")
	}
	flipped := bytes.Clone(good)
	flipped[len(flipped)-1] ^= 0xff
	padded := append(bytes.Clone(goodPEM), bytes.Repeat([]byte{'\n'}, MaxCSRSize-len(goodPEM)+1)...)
	twoBlocks := append(bytes.Clone(goodPEM), goodPEM...)
	brokenFirst := append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n"), goodPEM...)

	f.Add(goodPEM)
	f.Add(fuzzPEM("NEW CERTIFICATE REQUEST", good))
	f.Add(fuzzPEM("CERTIFICATE REQUEST", fuzzCSRDER(&x509.CertificateRequest{Subject: pkix.Name{CommonName: "ed"}, DNSNames: []string{"ed.homelab.lan"}}, k.ed)))
	f.Add(fuzzPEM("CERTIFICATE REQUEST", fuzzCSRDER(&x509.CertificateRequest{DNSNames: []string{"rsa.homelab.lan"}}, k.rsa)))
	f.Add(fuzzPEM("CERTIFICATE REQUEST", caCSR))
	f.Add(fuzzPEM("CERTIFICATE REQUEST", fuzzCSRDER(&x509.CertificateRequest{DNSNames: many}, k.ec)))
	f.Add(padded)                                                // valid, but 64 KiB + 1
	f.Add(bytes.Repeat([]byte("A"), MaxCSRSize+1))               // nothing valid, over the limit
	f.Add(twoBlocks)                                             // two CSRs
	f.Add(brokenFirst)                                           // a block that does not decode, then a good one
	f.Add(append(bytes.Clone(goodPEM), []byte("trailing\n")...)) // data after the block
	f.Add(append(bytes.Clone(goodPEM), '\n', '\r', ' '))         // white space after it is fine
	f.Add(append([]byte("Certificate Request:\n  Data:\n"), goodPEM...))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: good}))
	f.Add(fuzzPEM("CERTIFICATE", good))
	f.Add(fuzzPEM("CERTIFICATE REQUEST", flipped))
	f.Add(good) // DER, not PEM
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer fuzzTimer(t)()
		csr, err := parseCSR(data)
		insp, ierr := InspectCSR(data)
		if (err == nil) != (ierr == nil) {
			t.Fatalf("parseCSR says %v, InspectCSR says %v", err, ierr)
		}
		if len(data) > 64<<10 {
			if err == nil {
				t.Fatalf("accepted %d bytes, the limit is 64 KiB", len(data))
			}
		}
		if err != nil {
			checkRefusal(t, "parseCSR", err)
			checkRefusal(t, "InspectCSR", ierr)
			return
		}
		der, why := onePEMBlock(data, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
		if why != "" {
			t.Fatalf("accepted, but %s", why)
		}
		if !bytes.Equal(csr.Raw, der) {
			t.Fatal("the parsed CSR is not the PEM block's DER")
		}
		again, perr := x509.ParseCertificateRequest(der)
		if perr != nil {
			t.Fatalf("accepted a CSR that does not parse: %v", perr)
		}
		if checked, serr := verifyCSRSignature(again); serr != nil {
			t.Fatalf("accepted a CSR whose signature is wrong: %v", serr)
		} else if checked && len(again.Signature) == 0 {
			t.Fatal("accepted a CSR without a signature")
		}

		// The preview.
		if !insp.SignatureValid {
			t.Error("preview of an accepted CSR says the signature is invalid")
		}
		if n, items := inspectionBytes(insp); n > 16*len(data)+4096 || items > len(data)/2+8 {
			t.Errorf("preview is %d bytes in %d items for %d bytes of CSR", n, items, len(data))
		}
		if got, want := len(insp.RequestedExtensions), len(again.Extensions); got != want {
			t.Errorf("preview lists %d extensions, the CSR has %d", got, want)
		}
		if len(again.Extensions) > 0 && len(insp.Warnings) == 0 {
			t.Error("a CSR with extensions gets no warning that they are ignored")
		}
		if len(insp.Problems) == 0 && !keyAllowed(again.PublicKey) {
			t.Errorf("no problem listed for a %T key the policy refuses", again.PublicKey)
		}
	})
}

// keyAllowed is the key policy as docs and pki-rules.md state it, written again for the test.
func keyAllowed(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		name := k.Curve.Params().Name
		return name == "P-256" || name == "P-384" || name == "P-521"
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && k.N.BitLen() <= 8192 && k.E == 65537
	case ed25519.PublicKey:
		return true
	}
	return false
}

// fuzzCert builds a self-signed certificate for a seed.
func fuzzCert(tmpl *x509.Certificate) []byte {
	k := fuzzKeys()
	tmpl.SerialNumber = big.NewInt(42)
	tmpl.NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tmpl.NotAfter = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.ec.PublicKey, k.ec)
	if err != nil {
		panic(err)
	}
	return der
}

func FuzzParseCertificate(f *testing.F) {
	leaf := fuzzCert(&x509.Certificate{
		Subject:        pkix.Name{CommonName: "nas.homelab.lan"},
		DNSNames:       []string{"NAS.homelab.lan", "nas.HOMELAB.lan", "nas.homelab.lan", "*.nas.homelab.lan"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("::ffff:192.0.2.10"), net.ParseIP("192.0.2.10")},
		EmailAddresses: []string{"Admin@homelab.lan", "admin@homelab.lan", "Admin@homelab.lan"},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "homelab.lan", Path: "/w"}, {Scheme: "spiffe", Host: "homelab.lan", Path: "/w"}},
	})
	caCert := fuzzCert(&x509.Certificate{
		Subject: pkix.Name{CommonName: "Homelab Root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains: []string{"homelab.lan"}, PermittedDNSDomainsCritical: true,
	})
	var many []string
	for i := range 2500 {
		many = append(many, "h"+strconv.Itoa(i)+".homelab.lan")
	}
	leafPEM := fuzzPEM("CERTIFICATE", leaf)
	padded := append(bytes.Clone(leafPEM), bytes.Repeat([]byte{'\n'}, MaxCertSize-len(leafPEM)+1)...)

	f.Add(leafPEM)
	f.Add(fuzzPEM("CERTIFICATE", caCert))
	f.Add(fuzzPEM("CERTIFICATE", fuzzCert(&x509.Certificate{DNSNames: many})))
	f.Add(padded)
	f.Add(bytes.Repeat([]byte("A"), MaxCertSize+1))
	f.Add(append(bytes.Clone(leafPEM), leafPEM...))
	f.Add(append([]byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), leafPEM...))
	f.Add(append(bytes.Clone(leafPEM), []byte("trailing\n")...))
	f.Add(append(bytes.Clone(leafPEM), '\n', '\r', ' '))
	f.Add(append([]byte("subject=CN=nas\n"), leafPEM...))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: leaf}))
	f.Add(fuzzPEM("TRUSTED CERTIFICATE", leaf))
	f.Add(fuzzPEM("CERTIFICATE REQUEST", leaf))
	f.Add(leaf) // DER, not PEM
	f.Add([]byte("-----BEGIN CERTIFICATE-----"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer fuzzTimer(t)()
		cert, err := parseOneCertificate(data)
		if len(data) > 64<<10 && err == nil {
			t.Fatalf("accepted %d bytes, the limit is 64 KiB", len(data))
		}
		if err != nil {
			checkRefusal(t, "parseOneCertificate", err)
			return
		}
		der, why := onePEMBlock(data, "CERTIFICATE")
		if why != "" {
			t.Fatalf("accepted, but %s", why)
		}
		if !bytes.Equal(cert.Raw, der) {
			t.Fatal("the parsed certificate is not the PEM block's DER")
		}
		if enc := fuzzPEM("CERTIFICATE", cert.Raw); !bytes.Equal(enc, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) {
			t.Fatal("the certificate does not re-encode to the same PEM")
		}
		if _, perr := x509.ParseCertificate(der); perr != nil {
			t.Fatalf("accepted a certificate that does not parse: %v", perr)
		}

		// The rows ImportExternal stores for the SANs: no row twice, none invented, none lost.
		rows := certNames(cert)
		want := map[[2]string]bool{}
		for _, d := range cert.DNSNames {
			want[[2]string{"dns", strings.ToLower(d)}] = true
		}
		for _, ip := range cert.IPAddresses {
			want[[2]string{"ip", ip.String()}] = true
		}
		for _, m := range cert.EmailAddresses {
			want[[2]string{"email", m}] = true
		}
		for _, u := range cert.URIs {
			want[[2]string{"uri", u.String()}] = true
		}
		seen := map[[2]string]bool{}
		for _, r := range rows {
			if seen[r] {
				t.Fatalf("row %v twice", r)
			}
			seen[r] = true
			if !want[r] {
				t.Fatalf("row %v is not a SAN of the certificate", r)
			}
			if r[0] == "dns" && r[1] != strings.ToLower(r[1]) {
				t.Fatalf("DNS row %q is not lower case", r[1])
			}
		}
		if len(seen) != len(want) {
			t.Fatalf("%d rows for %d distinct SANs", len(seen), len(want))
		}
		if n := len(cert.DNSNames) + len(cert.IPAddresses) + len(cert.EmailAddresses) + len(cert.URIs); len(rows) > n {
			t.Fatalf("%d rows for %d SANs", len(rows), n)
		}
	})
}

// Modes of FuzzNames.
const (
	modeDNS = iota
	modeWildcardDNS
	modeEmail
	modeURI
	modeIP
	modeNCDomain
	modeNCEmail
	modeNCPrefix
	modeCount
)

// ldhLabel is the LDH rule written again for the test: 1 to 63 characters, letters (lower case), digits and
// hyphens, no hyphen at either end.
func ldhLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := range len(l) {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// dnsProblem returns what is wrong with name as an accepted, canonical DNS SAN, or "".
func dnsProblem(name string, wildcard bool) string {
	switch {
	case name == "" || len(name) > 253:
		return fmt.Sprintf("length %d", len(name))
	case strings.HasSuffix(name, "."):
		return "trailing dot"
	}
	labels := strings.Split(name, ".")
	if labels[0] == "*" {
		if !wildcard {
			return "wildcard although none is allowed"
		}
		if len(labels) < 3 {
			return "wildcard with fewer than two labels behind it"
		}
		labels = labels[1:]
	}
	for _, l := range labels {
		if !ldhLabel(l) {
			return fmt.Sprintf("label %q", l)
		}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "an IP address"
	}
	return ""
}

// echoes reports whether msg repeats more than 80 bytes in a row of in, either as written or as the %q
// verb prints it. 80 is what short() lets through.
func echoes(msg, in string) bool {
	const window = 81
	if len(msg) < window || len(in) < window {
		return false
	}
	// Every message of these functions starts from the beginning of the input or cuts it, so a run of more
	// than 80 bytes shows up in the first 2 KiB; looking further would cost seconds on a 1 MiB input.
	in = in[:min(len(in), 2048)]
	for _, v := range []string{in, strings.ToLower(in)} {
		for i := 0; i+window <= len(v); i++ {
			w := v[i : i+window]
			if strings.Contains(msg, w) {
				return true
			}
			if strings.ContainsFunc(w, func(r rune) bool { return r < 0x20 || r >= 0x7f || r == '"' || r == '\\' }) {
				if q := strconv.Quote(w); strings.Contains(msg, q[1:len(q)-1]) {
					return true
				}
			}
		}
	}
	return false
}

func FuzzNames(f *testing.F) {
	seeds := []struct {
		mode uint8
		s    string
	}{
		{modeDNS, "nas.homelab.lan"}, {modeDNS, "NAS.Homelab.LAN"}, {modeDNS, "nas"}, {modeDNS, "xn--mnchen-3ya.example"},
		{modeDNS, "*.homelab.lan"}, {modeWildcardDNS, "*.homelab.lan"}, {modeWildcardDNS, "*.lan"}, {modeWildcardDNS, "a.*.homelab.lan"},
		{modeWildcardDNS, "*"}, {modeWildcardDNS, "*.*.homelab.lan"}, {modeWildcardDNS, "w*.homelab.lan"},
		{modeDNS, "nas.homelab.lan."}, {modeDNS, "a..b"}, {modeDNS, "-a.lan"}, {modeDNS, "a-.lan"}, {modeDNS, "ab--cd.lan"},
		{modeDNS, "192.0.2.1"}, {modeDNS, "1.2.3.4.5"}, {modeDNS, "::1"}, {modeDNS, "a.123"}, {modeDNS, "münchen.example"},
		{modeDNS, strings.Repeat("a", 64) + ".lan"}, {modeDNS, strings.Repeat("a.", 130) + "lan"},
		{modeDNS, strings.Repeat("ab-", 100) + "-x.lan"}, {modeDNS, "a\x00b.lan"}, {modeDNS, "a b.lan"}, {modeDNS, string(rune(0x202e)) + "a.lan"},
		{modeEmail, "admin@homelab.lan"}, {modeEmail, "Admin@HOMELAB.lan"}, {modeEmail, "a.b+c@homelab.lan"}, {modeEmail, "\"a b\"@homelab.lan"},
		{modeEmail, "a..b@homelab.lan"}, {modeEmail, "@homelab.lan"}, {modeEmail, "a@"}, {modeEmail, "a@b@homelab.lan"},
		{modeEmail, strings.Repeat("a", 65) + "@homelab.lan"}, {modeEmail, "a@" + strings.Repeat("b.", 200)},
		{modeURI, "spiffe://homelab.lan/workload"}, {modeURI, "https://user:pw@host/"}, {modeURI, "/relative"}, {modeURI, "https://a b"},
		{modeURI, "1http://x"}, {modeURI, "http://" + strings.Repeat("a", 2100)}, {modeURI, "http://[::1"}, {modeURI, "urn:x"},
		{modeIP, "192.0.2.10"}, {modeIP, "2001:db8::1"}, {modeIP, "::ffff:192.0.2.10"}, {modeIP, "0.0.0.0"}, {modeIP, "::"},
		{modeIP, "fe80::1%eth0"}, {modeIP, "fe80::1%" + strings.Repeat("z", 300)}, {modeIP, "01.2.3.4"}, {modeIP, "::ffff:0"}, {modeIP, "::ffff:a00:1"}, {modeIP, "1.2.3"}, {modeIP, ""},
		{modeNCDomain, "homelab.lan"}, {modeNCDomain, ".homelab.lan"}, {modeNCDomain, ".."}, {modeNCDomain, ".a..b"}, {modeNCDomain, "."},
		{modeNCEmail, "admin@homelab.lan"}, {modeNCEmail, ".homelab.lan"}, {modeNCEmail, "homelab.lan"}, {modeNCEmail, "@homelab.lan"},
		{modeNCPrefix, "10.0.0.0/8"}, {modeNCPrefix, "10.0.0.1/8"}, {modeNCPrefix, "fd00::/8"}, {modeNCPrefix, "::ffff:10.0.0.0/104"},
		{modeNCPrefix, "::ffff:0.0.0.0/96"}, {modeNCPrefix, "0.0.0.0/0"}, {modeNCPrefix, "::/0"}, {modeNCPrefix, "10.0.0.0/33"},
		{modeNCPrefix, "fe80::%eth0/64"}, {modeNCPrefix, "10.0.0.0"},
	}
	for _, s := range seeds {
		f.Add(s.mode, s.s)
	}

	f.Fuzz(func(t *testing.T, mode uint8, s string) {
		defer fuzzTimer(t)()
		mode %= modeCount
		var out string
		var err error
		// again runs the same check on the canonical form: it must be accepted and stay as it is.
		var again func(string) (string, error)
		switch mode {
		case modeDNS, modeWildcardDNS:
			wildcard := mode == modeWildcardDNS
			again = func(v string) (string, error) { return checkDNSName(v, wildcard) }
		case modeEmail:
			again = checkEmail
		case modeURI:
			again = checkURI
		case modeIP:
			again = func(v string) (string, error) {
				a, e := checkIP(v)
				return a.String(), e
			}
		case modeNCDomain:
			again = ncDomain
		case modeNCEmail:
			again = ncEmail
		case modeNCPrefix:
			again = ncPrefix
		}
		out, err = again(s)
		if err != nil {
			if echoes(err.Error(), s) {
				t.Errorf("mode %d: the refusal repeats more than 80 bytes of the input: %.300q", mode, err.Error())
			}
			return
		}
		if len(out) > maxURI && mode == modeURI || len(out) > 253+maxEmail && mode != modeURI {
			t.Fatalf("mode %d: accepted a value of %d bytes", mode, len(out))
		}
		if again2, err2 := again(out); err2 != nil || again2 != out {
			t.Fatalf("mode %d: %q is accepted as %q, but that gives %q (%v)", mode, s, out, again2, err2)
		}
		switch mode {
		case modeDNS, modeWildcardDNS:
			if out != strings.ToLower(s) {
				t.Fatalf("canonical form %q of %q is not its lower case", out, s)
			}
			if p := dnsProblem(out, mode == modeWildcardDNS); p != "" {
				t.Fatalf("accepted DNS name %q: %s", out, p)
			}
		case modeEmail:
			at := strings.LastIndexByte(out, '@')
			if at < 1 || len(out) > 254 || at > 64 || out[:at] != s[:strings.LastIndexByte(s, '@')] {
				t.Fatalf("accepted e-mail %q as %q", s, out)
			}
			if p := dnsProblem(out[at+1:], false); p != "" {
				t.Fatalf("accepted e-mail %q with a bad domain: %s", out, p)
			}
			for part := range strings.SplitSeq(out[:at], ".") {
				if part == "" || strings.ContainsAny(part, "@\"\\ ()<>[],;:\x00\t\r\n") {
					t.Fatalf("accepted e-mail %q with a bad local part", out)
				}
			}
		case modeURI:
			u, perr := url.Parse(out)
			if out != s || perr != nil || !u.IsAbs() || u.User != nil || u.Scheme == "" {
				t.Fatalf("accepted URI %q (%v)", s, perr)
			}
			for i := range len(out) {
				if out[i] <= ' ' || out[i] >= 0x7f {
					t.Fatalf("accepted URI %q with byte %#x", s, out[i])
				}
			}
		case modeIP:
			ip := net.ParseIP(out)
			if ip == nil || ip.IsUnspecified() || strings.Contains(out, "%") || ip.To4() != nil && strings.Contains(out, ":") {
				t.Fatalf("accepted IP %q as %q", s, out)
			}
			if in := net.ParseIP(s); in != nil && !in.Equal(ip) {
				t.Fatalf("IP %q became %q", s, out)
			}
		case modeNCDomain:
			base := strings.TrimPrefix(out, ".")
			if p := dnsProblem(base, false); p != "" {
				t.Fatalf("accepted constraint %q: %s", out, p)
			}
			if strings.HasPrefix(out, ".") != strings.HasPrefix(strings.TrimSpace(s), ".") {
				t.Fatalf("constraint %q lost or gained its leading dot: %q", out, s)
			}
		case modeNCEmail:
			if strings.Contains(s, "@") != strings.Contains(out, "@") {
				t.Fatalf("e-mail constraint %q became %q", s, out)
			}
		case modeNCPrefix:
			if _, _, perr := net.ParseCIDR(out); perr != nil {
				t.Fatalf("accepted prefix %q as %q (%v)", s, out, perr)
			}
			p := netip.MustParsePrefix(out)
			if p.Masked() != p || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				t.Fatalf("accepted prefix %q as %q", s, out)
			}
			// The constraint is written into a certificate and read back (apply and ncFromCert): it has
			// to come back as the same text, or an offline-signed CA is compared against another value.
			ipn := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
			if back := ipNetString(ipn); back != out {
				t.Fatalf("prefix %q is written to a certificate and read back as %q", out, back)
			}
		}
	})
}

func FuzzCRLDER(f *testing.F) {
	k := fuzzKeys()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Homelab Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &k.ec.PublicKey, k.ec)
	if err != nil {
		f.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(caDER)
	if err != nil {
		f.Fatal(err)
	}
	crl := func(entries int) []byte {
		var rev []x509.RevocationListEntry
		for i := range entries {
			rev = append(rev, x509.RevocationListEntry{SerialNumber: big.NewInt(int64(1000 + i)), RevocationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), ReasonCode: 1})
		}
		der, cerr := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(7), ThisUpdate: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), NextUpdate: time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC),
			RevokedCertificateEntries: rev,
		}, issuer, k.ec)
		if cerr != nil {
			f.Fatal(cerr)
		}
		return der
	}
	small, large := crl(2), crl(3000)
	smallPEM := fuzzPEM("X509 CRL", small)

	f.Add(small)
	f.Add(smallPEM)
	f.Add(fuzzPEM("X509 CRL", large))
	f.Add(large)
	f.Add(append([]byte("\r\n  "), smallPEM...))
	f.Add(append(bytes.Clone(smallPEM), smallPEM...))
	f.Add(append(bytes.Clone(smallPEM), []byte("trailing")...))
	f.Add(fuzzPEM("CERTIFICATE", small))
	f.Add(fuzzPEM("CRL", small))
	f.Add(append([]byte("-----BEGIN X509 CRL-----\n!!!\n-----END X509 CRL-----\n"), smallPEM...))
	f.Add(small[:len(small)/2])
	f.Add(bytes.Repeat([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, 100)) // lengths that claim 4 GiB
	f.Add(bytes.Repeat([]byte{0x30, 0x80}, MaxCRLSize/2+1))              // 4 MiB + 2 of indefinite lengths
	f.Add([]byte("-----BEGIN X509 CRL-----"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer fuzzTimer(t)()
		der, err := crlDER(data)
		if len(data) > 4<<20 && err == nil {
			t.Fatalf("accepted %d bytes, the limit is 4 MiB", len(data))
		}
		if err != nil {
			checkRefusal(t, "crlDER", err)
			return
		}
		if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
			want, why := onePEMBlock(data, "X509 CRL")
			if why != "" {
				t.Fatalf("accepted a PEM CRL, but %s", why)
			}
			if !bytes.Equal(der, want) {
				t.Fatal("the DER is not the PEM block's")
			}
		} else if !bytes.Equal(der, data) {
			t.Fatal("a DER upload came back changed")
		}
		rl, perr := parseUploadedCRL(der)
		if perr != nil {
			checkRefusal(t, "parseUploadedCRL", perr)
			return
		}
		if !bytes.Equal(rl.Raw, der) {
			t.Fatal("the parsed list is not the uploaded DER")
		}
		if len(rl.RevokedCertificateEntries) > len(der)/4 {
			t.Fatalf("%d entries from %d bytes", len(rl.RevokedCertificateEntries), len(der))
		}
		for _, e := range rl.RevokedCertificateEntries {
			if e.SerialNumber == nil {
				t.Fatalf("entry without a serial: %+v", e)
			}
		}
	})
}
