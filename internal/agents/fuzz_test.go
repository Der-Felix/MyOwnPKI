package agents

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The targets of docs/PHASE3.md section 18.2 for the agent protocol: what a
// host that holds a join token or an mTLS certificate can send. The
// production functions are called unchanged; every invariant below is
// checked by code of its own, not by calling the parser a second time.

// fuzzBudget is the most a single input may take (section 18.2, rule 2).
const fuzzBudget = 2 * time.Second

// maxNameRefusal bounds the text of a name refusal: it echoes at most 64
// bytes of the input (clip), and %q writes a byte that is no valid UTF-8 as
// four characters ("\xb0"), plus about 200 characters of fixed words.
const maxNameRefusal = 4*64 + 200

func requireFast(tb testing.TB, start time.Time, what string) {
	tb.Helper()
	if d := time.Since(start); d > fuzzBudget {
		tb.Fatalf("%s took %v, more than %v", what, d, fuzzBudget)
	}
}

// fuzzCSR makes a CSR from a key; extra bytes become an opaque extension so
// a test can build one of any size.
func fuzzCSR(tb testing.TB, key any, extra int) []byte {
	tb.Helper()
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: []string{"evil.example"}}
	if extra > 0 {
		tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, extra)}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func FuzzCSRKey(f *testing.F) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	good := fuzzCSR(f, ec, 0)
	badSig := append([]byte(nil), good...)
	badSig[len(badSig)-1] ^= 0xff
	f.Add(good)
	f.Add(fuzzCSR(f, ec384, 0))
	f.Add(fuzzCSR(f, ed, 0))
	f.Add(fuzzCSR(f, rsaKey, 0))
	f.Add(fuzzCSR(f, ec, 6000)) // large, still under the limit
	f.Add(fuzzCSR(f, ec, 9000)) // validly signed, over 8 KiB
	f.Add(badSig)
	f.Add(append(append([]byte(nil), good...), 0)) // trailing byte
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add(good[:len(good)/2])

	f.Fuzz(func(t *testing.T, der []byte) {
		start := time.Now()
		got, err := csrKey(der)
		requireFast(t, start, "csrKey")
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("refusal is not ErrInvalid: %v", err)
			}
			if len(err.Error()) > 300 {
				t.Fatalf("refusal text of %d bytes", len(err.Error()))
			}
			return
		}
		// Accepted: every part of the promise, checked on its own.
		if len(der) == 0 || len(der) > 8192 {
			t.Fatalf("accepted %d bytes (limit 1 to 8192)", len(der))
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatalf("accepted bytes that do not parse: %v", err)
		}
		if sigErr := csr.CheckSignature(); sigErr != nil {
			t.Fatalf("accepted a CSR whose signature fails: %v", sigErr)
		}
		switch csr.PublicKey.(type) {
		case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
		default:
			t.Fatalf("accepted a key of type %T", csr.PublicKey)
		}
		if len(got) != 43 {
			t.Fatalf("result %q has %d characters, want 43", got, len(got))
		}
		raw, err := base64.RawURLEncoding.DecodeString(got)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != got {
			t.Fatalf("result %q is not canonical base64url", got)
		}
		sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
		if !bytes.Equal(raw, sum[:]) {
			t.Fatalf("result is not the SHA-256 of the public key")
		}
		// The key that was hashed is the key of the request.
		reparsed, err := x509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatalf("hashed bytes are not a public key: %v", err)
		}
		if !publicKeysEqual(reparsed, csr.PublicKey) {
			t.Fatal("the hashed key is not the request's key")
		}
	})
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	x, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && x.Equal(b)
}

// FuzzValidReport decodes a report from JSON the way a client could shape
// it and compares validReport with a second, independent statement of the
// limits in docs/PHASE3.md and report.go's comment.
func FuzzValidReport(f *testing.F) {
	valid := ReportInput{
		Version: "0.3.12", OS: "linux", Arch: "amd64", PackageFormat: "deb",
		Deployments: []DeploymentReport{{
			Name: "web", Profile: "server", Names: []string{"proxy1.homelab.lan", "*.homelab.lan"}, Challenge: "http-01",
			State: "deployed", Serial: "0A1B2C", NotAfter: "2027-01-02T03:04:05Z", DeployedAt: "2026-11-16T10:00:00+01:00",
			Fingerprint: strings.Repeat("ab", 32), WrittenFingerprint: strings.Repeat("CD", 32), CheckConfigured: true, HandledRenewalVersion: 3,
		}},
	}
	seed := func(in ReportInput) {
		b, err := json.Marshal(in)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	seed(valid)
	seed(ReportInput{})
	longName := valid
	longName.Deployments = []DeploymentReport{{Name: strings.Repeat("a", 63), State: "pending", Names: []string{strings.Repeat("a", 253)}}}
	seed(longName)
	tooLong := valid
	tooLong.Deployments = []DeploymentReport{{Name: strings.Repeat("a", 64), State: "pending"}}
	seed(tooLong)
	manyNames := valid
	manyNames.Deployments = []DeploymentReport{{Name: "web", State: "failed", Names: make([]string, 101), LastError: strings.Repeat("e", 1025)}}
	seed(manyNames)
	many := valid
	many.Deployments = make([]DeploymentReport, MaxReportDeployments+1)
	for i := range many.Deployments {
		many.Deployments[i] = DeploymentReport{Name: "d" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)), State: "pending"}
	}
	seed(many)
	badHex := valid
	badHex.Deployments = []DeploymentReport{{Name: "web", State: "pending", Serial: "xyz1", Fingerprint: strings.Repeat("a", 62)}}
	seed(badHex)
	badUTF := valid
	badUTF.Version = "v\xff"
	seed(badUTF)
	nul := valid
	nul.OS = "li\x00nux"
	seed(nul)
	dup := valid
	dup.Deployments = []DeploymentReport{{Name: "web", State: "pending"}, {Name: "web", State: "pending"}}
	seed(dup)
	badTime := valid
	badTime.Deployments = []DeploymentReport{{Name: "web", State: "pending", NotAfter: "2027-13-45T00:00:00Z"}}
	seed(badTime)
	negative := valid
	negative.Deployments = []DeploymentReport{{Name: "web", State: "pending", HandledRenewalVersion: -1}}
	seed(negative)
	f.Add([]byte(`{"Deployments":[{"Name":"a","State":"deployed","Names":["` + strings.Repeat("é", 127) + `"]}]}`)) // 254 bytes
	f.Add([]byte(`{"PackageFormat":"zip"}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var in ReportInput
		if json.Unmarshal(raw, &in) != nil {
			return
		}
		start := time.Now()
		err := validReport(in)
		requireFast(t, start, "validReport")
		want := reportLimitsHold(in)
		if err == nil && !want {
			t.Fatalf("accepted a report that breaks a limit: %+v", in)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("refusal is not ErrInvalid: %v", err)
			}
			if len(err.Error()) > 300 {
				t.Fatalf("refusal text of %d bytes", len(err.Error()))
			}
			if want {
				t.Fatalf("refused a report within every limit: %+v", in)
			}
			return
		}
		// What Report does with an accepted value must not fail either.
		for _, d := range in.Deployments {
			for _, s := range []string{d.NotAfter, d.DeployedAt} {
				if got := reportTime(s); s != "" && len(got) != len("2006-01-02T15:04:05Z") {
					t.Fatalf("reportTime(%q) = %q", s, got)
				}
			}
		}
	})
}

// reportLimitsHold states the limits of a report again, in other words than
// validReport: byte lengths and UTF-8 for text, a closed set for states and
// formats, a hand-written scan for the deployment name, hex by character.
func reportLimitsHold(in ReportInput) bool {
	text := func(s string, limit int) bool {
		return len(s) <= limit && utf8.ValidString(s) && !strings.Contains(s, "\x00")
	}
	isHex := func(s string, exactly int) bool {
		if len(s) > 64 || len(s)%2 == 1 || (exactly > 0 && s != "" && len(s) != exactly) {
			return false
		}
		for _, c := range []byte(s) {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
		return true
	}
	oneOf := func(s string, set ...string) bool {
		return slices.Contains(set, s)
	}
	if !text(in.Version, 64) || !text(in.OS, 32) || !text(in.Arch, 32) {
		return false
	}
	if len(in.Deployments) > 101 || !oneOf(in.PackageFormat, "", "deb", "rpm", "tarball") {
		return false
	}
	names := map[string]struct{}{}
	for _, d := range in.Deployments {
		if !deploymentNameOK(d.Name) {
			return false
		}
		if _, dup := names[d.Name]; dup {
			return false
		}
		names[d.Name] = struct{}{}
		if !text(d.Profile, 32) || !text(d.Challenge, 32) || !text(d.LastError, 1024) ||
			!oneOf(d.State, "pending", "deployed", "failed", "rolled_back") || d.HandledRenewalVersion < 0 || len(d.Names) > 100 {
			return false
		}
		for _, n := range d.Names {
			if !text(n, 253) {
				return false
			}
		}
		for _, v := range []string{d.NotAfter, d.DeployedAt} {
			if v == "" {
				continue
			}
			if len(v) > 35 {
				return false
			}
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return false
			}
		}
		if !isHex(d.Serial, 0) || !isHex(d.Fingerprint, 64) || !isHex(d.WrittenFingerprint, 64) {
			return false
		}
	}
	return true
}

// deploymentNameOK: 1 to 64 characters, lower case letters, digits and
// hyphens, no hyphen at either end.
func deploymentNameOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && (c != '-' || i == 0 || i == len(s)-1) {
			return false
		}
	}
	return true
}

// hostOK is a statement of a fully qualified host name on its own: lower
// case letters, digits and hyphens, two or more labels of 1 to 63
// characters without a hyphen at either end, at most 253 characters in all,
// and not an IP address (the last label is not all digits).
func hostOK(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := range len(l) {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

func FuzzHostnamePattern(f *testing.F) {
	for _, s := range []string{
		"proxy1.homelab.lan", "Proxy1.Homelab.LAN.", " proxy1.homelab.lan\t", "*.homelab.lan", "*.lan", "*", "lan", "",
		"a..lan", "-a.lan", "a-.lan", "a_b.lan", "10.0.0.1", "::1", "1.2.3.4.5", "a.1", "*.*.lan", "**.lan", "*.a.b.c.lan",
		"xn--bcher-kva.example", "bücher.example", "examplK.lan", "İ.lan", "a .lan", "a.lan\x00", "a b.lan",
		strings.Repeat("a", 63) + ".lan", strings.Repeat("a", 64) + ".lan", strings.Repeat("a.", 126) + "ab",
		strings.Repeat("a.", 127) + "ab", "a.lan..", "..lan", ".lan", "a.lan.\n",
	} {
		f.Add(s, "proxy1.homelab.lan")
		f.Add(s, s)
	}
	f.Add("*.homelab.lan", "a.b.homelab.lan")
	f.Add("*.homelab.lan", "*.homelab.lan")
	f.Add("*.homelab.lan", "homelab.lan")
	f.Add("*.homelab.lan", "evilhomelab.lan")
	f.Add("*.homelab.lan", "*.a.homelab.lan")

	f.Fuzz(func(t *testing.T, s, name string) {
		start := time.Now()
		defer func() { requireFast(t, start, "name functions") }()

		host, herr := CheckHostname(s)
		if herr == nil {
			if !hostOK(host) {
				t.Fatalf("CheckHostname(%q) accepted %q, which is not a host name", s, host)
			}
			if again, err := CheckHostname(host); err != nil || again != host {
				t.Fatalf("CheckHostname is not idempotent: %q -> %q -> %q, %v", s, host, again, err)
			}
		} else {
			if !errors.Is(herr, ErrInvalid) {
				t.Fatalf("refusal is not ErrInvalid: %v", herr)
			}
			if len(herr.Error()) > maxNameRefusal {
				t.Fatalf("refusal text of %d bytes", len(herr.Error()))
			}
		}

		pat, perr := CheckPattern(s)
		if perr != nil {
			if !errors.Is(perr, ErrInvalid) {
				t.Fatalf("refusal is not ErrInvalid: %v", perr)
			}
			if len(perr.Error()) > maxNameRefusal {
				t.Fatalf("refusal text of %d bytes", len(perr.Error()))
			}
			return
		}
		suffix, wild := strings.CutPrefix(pat, "*.")
		if !hostOK(suffix) {
			t.Fatalf("CheckPattern(%q) accepted %q", s, pat)
		}
		if wild && strings.Count(suffix, ".") < 1 {
			t.Fatalf("pattern %q covers a single label", pat)
		}
		if strings.Contains(suffix, "*") {
			t.Fatalf("pattern %q has a second wildcard", pat)
		}
		if again, err := CheckPattern(pat); err != nil || again != pat {
			t.Fatalf("CheckPattern is not idempotent: %q -> %q -> %q, %v", s, pat, again, err)
		}
		if herr == nil && pat != host {
			t.Fatalf("one input, two answers: host %q, pattern %q", host, pat)
		}

		// Whatever the string, a pattern covers only itself or, as a
		// wildcard, a name that ends in "." plus its suffix and is no
		// wildcard name itself.
		if Matches(pat, name) && name != pat {
			if !wild || !strings.HasSuffix(name, "."+suffix) || strings.HasPrefix(name, "*.") {
				t.Fatalf("Matches(%q, %q) is true for an unrelated string", pat, name)
			}
		}
		// Matches takes names that were checked before (ACME identifiers,
		// the enrolling host): a host name or a "*." name below one.
		nm, nerr := CheckPattern(name)
		if nerr != nil {
			return
		}
		got := Matches(pat, nm)
		nmWild := strings.HasPrefix(nm, "*.")
		var want bool
		switch {
		case nm == pat:
			want = true
		case !wild || nmWild:
			want = false
		default:
			// below the suffix: at least one label in front of it
			want = len(nm) > len(suffix)+1 && strings.HasSuffix(nm, "."+suffix)
		}
		if got != want {
			t.Fatalf("Matches(%q, %q) = %v, want %v", pat, nm, got, want)
		}
		if got && nm != pat && !hostOK(nm) {
			t.Fatalf("pattern %q covers %q, which is no host name", pat, nm)
		}
		if got && wild && nm == suffix {
			t.Fatalf("pattern %q covers its own suffix", pat)
		}
		if MatchesAny([]string{pat}, nm) != got || MatchesAny(nil, nm) {
			t.Fatal("MatchesAny disagrees with Matches")
		}
	})
}
