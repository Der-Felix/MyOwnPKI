package ca

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func certOf(t *testing.T, r *CAResult) *x509.Certificate {
	t.Helper()
	if r.CertDER == nil {
		t.Fatalf("CA %s generation %d has no certificate", r.Name, r.Generation)
	}
	return parse(t, r.CertDER)
}

func (v *env) root(t *testing.T, name string, mod func(*RootRequest)) *CAResult {
	t.Helper()
	req := RootRequest{
		CASettings: CASettings{Name: name, BaseURL: baseURL + "/"},
		Subject:    Subject{CommonName: "Homelab " + name, Organization: "Homelab"}, Who: tester,
	}
	if mod != nil {
		mod(&req)
	}
	r, err := v.e.CreateRoot(t.Context(), req)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	return r
}

func (v *env) intermediate(t *testing.T, name, parent string, mod func(*IntermediateRequest)) *CAResult {
	t.Helper()
	req := IntermediateRequest{
		CASettings: CASettings{Name: name, BaseURL: baseURL}, Parent: parent,
		Subject: Subject{CommonName: "Homelab " + name, Organization: "Homelab"}, Who: tester,
	}
	if mod != nil {
		mod(&req)
	}
	r, err := v.e.CreateIntermediate(t.Context(), req)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	return r
}

func deniedErr(t *testing.T, err error) string {
	t.Helper()
	var d *DeniedError
	if !errors.As(err, &d) {
		t.Fatalf("want a denial, got %v", err)
	}
	return strings.Join(d.Reasons, "\n")
}

func TestOnlineRootAndIntermediate(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	r := v.root(t, "root", nil)
	root := certOf(t, r)
	if bc, _ := findExt(root, oidBasicConstr); !bc.Critical || !root.IsCA || root.MaxPathLen != -1 {
		t.Error("root: basicConstraints critical CA:TRUE without path length")
	}
	if ku, _ := findExt(root, oidKeyUsage); !ku.Critical || root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("root key usage %b", root.KeyUsage)
	}
	if root.SignatureAlgorithm != x509.ECDSAWithSHA384 || len(root.SubjectKeyId) != 20 || len(root.IssuingCertificateURL) != 0 {
		t.Errorf("root: sig %v, SKI %x, AIA %v", root.SignatureAlgorithm, root.SubjectKeyId, root.IssuingCertificateURL)
	}
	if days := root.NotAfter.Sub(root.NotBefore) + time.Second; days != DefaultRootDays*day {
		t.Errorf("root lifetime %v", days)
	}
	if !strings.Contains(strings.Join(r.Warnings, "|"), "online root") {
		t.Errorf("warnings %v", r.Warnings)
	}

	ir := v.intermediate(t, "issuing", "root", func(req *IntermediateRequest) {
		req.KeyAlgorithm = AlgECDSAP256
		req.NameConstraints = NameConstraints{PermittedDNS: []string{"homelab.lan"}, PermittedIP: []string{"10.0.0.0/8", "fd00::/8"}, ExcludedDNS: []string{"secret.homelab.lan"}}
		req.EKULimit = []string{"serverAuth", "clientAuth"}
	})
	inter := certOf(t, ir)
	if !inter.MaxPathLenZero || inter.MaxPathLen != 0 || inter.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("intermediate: pathlen %d/%v, KU %b", inter.MaxPathLen, inter.MaxPathLenZero, inter.KeyUsage)
	}
	if !inter.PermittedDNSDomainsCritical || !slices.Equal(inter.PermittedDNSDomains, []string{"homelab.lan"}) || len(inter.PermittedIPRanges) != 2 ||
		!slices.Equal(inter.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("intermediate: NC %v %v crit %v, EKU %v", inter.PermittedDNSDomains, inter.PermittedIPRanges, inter.PermittedDNSDomainsCritical, inter.ExtKeyUsage)
	}
	if !slices.Equal(inter.IssuingCertificateURL, []string{baseURL + "/ca/root/1.crt"}) || !slices.Equal(inter.CRLDistributionPoints, []string{baseURL + "/crl/root/1.crl"}) {
		t.Errorf("intermediate AIA %v CDP %v", inter.IssuingCertificateURL, inter.CRLDistributionPoints)
	}
	if !slices.Equal(inter.AuthorityKeyId, root.SubjectKeyId) || inter.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Error("intermediate: AKI must be the root's SKI, signature by the P-384 root")
	}

	// The new CAs issue right away, and the chain holds for OpenSSL.
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, IPAddresses: []string{"fd00::5"}})
	opensslVerifyAt(t, t0, [][]byte{ir.CertDER, r.CertDER}, out.CertDER, "sslserver")
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"x.secret.homelab.lan"}}); !strings.Contains(got, "excluded") {
		t.Errorf("NC of a created CA: %q", got)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "codesign", Subject: Subject{CommonName: "x"}}); !strings.Contains(got, "is not allowed by CA") {
		t.Errorf("EKU limit of a created CA: %q", got)
	}

	cas, err := ListCAs(t.Context(), v.pki)
	if err != nil || len(cas) != 2 {
		t.Fatal(cas, err)
	}
	if c := cas[0]; c.Name != "issuing" || c.Parent != "root" || c.BaseURL != baseURL || c.CRLDays != 7 || c.MaxValidityDays != 397 ||
		*c.PathLen != 0 || !slices.Equal(c.EKULimit, []string{"serverAuth", "clientAuth"}) || len(c.NameConstraints) != 4 ||
		len(c.Generations) != 1 || c.Generations[0].Issuer != "root/1" || !c.Generations[0].Current {
		t.Errorf("list: %+v", c)
	}
	if c := cas[1]; c.Name != "root" || c.CRLDays != DefaultCRLDaysOnlineRoot || c.PathLen != nil || c.KeyMode != KeyModeOnlineEncrypted {
		t.Errorf("list: %+v", c)
	}
	actions := map[string]int{}
	for _, row := range v.auditRows(t) {
		actions[row.action+"/"+row.result]++
	}
	if actions["ca.create/success"] != 2 || actions["certificate.issue/success"] != 1 {
		t.Errorf("audit %v", actions)
	}
}

func TestCARequestsAreChecked(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.root(t, "root", nil)
	v.intermediate(t, "leafonly", "root", nil) // path length 0

	rootTests := map[string]func(*RootRequest){
		"want 1-63 characters":         func(r *RootRequest) { r.Name = "Root CA" },
		"exists already":               func(r *RootRequest) { r.Name = "root" },
		"want http://":                 func(r *RootRequest) { r.BaseURL = "ftp://pki.homelab.lan" },
		"query or fragment":            func(r *RootRequest) { r.BaseURL = "http://pki.homelab.lan/?x=1" },
		"base URL is required":         func(r *RootRequest) { r.BaseURL = "" },
		"not offered for new CAs":      func(r *RootRequest) { r.KeyAlgorithm = AlgEd25519 },
		"RSA 2048 is too weak":         func(r *RootRequest) { r.KeyAlgorithm = AlgRSA2048 },
		"a CA needs a common name":     func(r *RootRequest) { r.Subject = Subject{Organization: "Homelab"} },
		"another CA has the subject":   func(r *RootRequest) { r.Subject = Subject{CommonName: "Homelab root", Organization: "Homelab"} },
		"want 1 to 10950":              func(r *RootRequest) { r.ValidityDays = 20000 },
		"CRL validity of 400 days":     func(r *RootRequest) { r.CRLDays = 400 },
		"maximum certificate validity": func(r *RootRequest) { r.MaxValidityDays = 5000 },
	}
	for want, mod := range rootTests {
		req := RootRequest{CASettings: CASettings{Name: "other", BaseURL: baseURL}, Subject: Subject{CommonName: "Other Root"}, Who: tester}
		mod(&req)
		_, err := v.e.CreateRoot(t.Context(), req)
		if got := deniedErr(t, err); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}

	interTests := map[string]func(*IntermediateRequest){
		"no parent CA named":            func(r *IntermediateRequest) { r.Parent = "nope" },
		"may only issue end-entity":     func(r *IntermediateRequest) { r.Parent = "leafonly" },
		"host bits are set":             func(r *IntermediateRequest) { r.NameConstraints.PermittedIP = []string{"10.0.0.1/8"} },
		"name constraint dns":           func(r *IntermediateRequest) { r.NameConstraints.PermittedDNS = []string{"*.homelab.lan"} },
		"anyExtendedKeyUsage":           func(r *IntermediateRequest) { r.EKULimit = []string{"2.5.29.37.0"} },
		"path length 9":                 func(r *IntermediateRequest) { r.PathLen = 9 },
		"would end after the parent CA": func(r *IntermediateRequest) { r.ValidityDays = DefaultRootDays + 10 },
	}
	for want, mod := range interTests {
		req := IntermediateRequest{CASettings: CASettings{Name: "other", BaseURL: baseURL}, Parent: "root", Subject: Subject{CommonName: "Other CA"}, Who: tester}
		mod(&req)
		_, err := v.e.CreateIntermediate(t.Context(), req)
		if got := deniedErr(t, err); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}

	// Choices that stay in every certificate are warned about.
	r := v.root(t, "warned", func(r *RootRequest) { r.BaseURL = "https://pki.homelab.lan:8443/pki/" })
	if w := strings.Join(r.Warnings, "|"); !strings.Contains(w, "port 8443") || !strings.Contains(w, "uses https") {
		t.Errorf("warnings %v", r.Warnings)
	}
	cas, _ := ListCAs(t.Context(), v.pki)
	if cas[len(cas)-1].BaseURL != "https://pki.homelab.lan:8443/pki" {
		t.Errorf("base URL %q – trailing slash not removed", cas[len(cas)-1].BaseURL)
	}

	// Refusals are audited with their reasons.
	denied := 0
	for _, row := range v.auditRows(t) {
		if row.result == "denied" && strings.HasPrefix(row.action, "ca.") {
			denied++
		}
	}
	if denied != len(rootTests)+len(interTests) {
		t.Errorf("%d denied CA actions audited, want %d", denied, len(rootTests)+len(interTests))
	}
}

func TestPathLengthAndEKUFitTheParent(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.root(t, "root", func(r *RootRequest) { r.ValidityDays = 1000 })
	ir := v.intermediate(t, "policy", "root", func(r *IntermediateRequest) { r.PathLen = 1; r.EKULimit = []string{"serverAuth"} })
	if !strings.Contains(strings.Join(ir.Notes, "|"), "shortened to the end of the parent") {
		t.Errorf("notes %v", ir.Notes)
	}
	v.intermediate(t, "issuing", "policy", func(r *IntermediateRequest) { r.EKULimit = []string{"serverAuth"} })
	for want, mod := range map[string]func(*IntermediateRequest){
		"allows at most 0 below":      func(r *IntermediateRequest) { r.PathLen = 1 },
		"is not allowed by parent CA": func(r *IntermediateRequest) { r.EKULimit = []string{"clientAuth"} },
	} {
		req := IntermediateRequest{CASettings: CASettings{Name: "other", BaseURL: baseURL}, Parent: "policy", Subject: Subject{CommonName: "Other CA"}, Who: tester}
		mod(&req)
		_, err := v.e.CreateIntermediate(t.Context(), req)
		if got := deniedErr(t, err); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}
	// Three tiers verify end to end.
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	if len(out.Chain) != 3 {
		t.Fatalf("chain length %d", len(out.Chain))
	}
	opensslVerifyAt(t, t0, out.Chain, out.CertDER, "sslserver")
}

// offlineRoot is a root created outside MyOwnPKI – here in Go, standing in
// for an offline machine.
type offlineRoot struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newOfflineRoot(t *testing.T, cn string, notBefore time.Time) *offlineRoot {
	t.Helper()
	key := mustKey(t, elliptic.P384())
	serial, err := newSerial(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Homelab"}},
		NotBefore:    notBefore, NotAfter: notBefore.AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &offlineRoot{cert: parse(t, der), key: key}
}

func (r *offlineRoot) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.cert.Raw})
}

// sign signs a CSR the way an offline root following the bundle would;
// mod changes the template to build a wrong certificate on purpose.
func (r *offlineRoot) sign(t *testing.T, b *OfflineBundle, nc NameConstraints, mod func(*x509.Certificate, *crypto.PublicKey)) []byte {
	t.Helper()
	block, _ := pem.Decode(b.CSRPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := new(big.Int).SetString(b.Serial, 16)
	tmpl := &x509.Certificate{
		SerialNumber: serial, RawSubject: csr.RawSubject,
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.AddDate(0, 0, b.Days),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IssuingCertificateURL: []string{baseURL + "/ca/offline-root/1.crt"}, CRLDistributionPoints: []string{baseURL + "/crl/offline-root/1.crl"},
		PermittedDNSDomains: nc.PermittedDNS, PermittedDNSDomainsCritical: true,
	}
	var pub crypto.PublicKey = csr.PublicKey
	if mod != nil {
		mod(tmpl, &pub)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, pub, r.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (v *env) importRoot(t *testing.T, name string, r *offlineRoot) *CAResult {
	t.Helper()
	res, err := v.e.ImportRoot(t.Context(), ImportRootRequest{CASettings: CASettings{Name: name, BaseURL: baseURL}, CertPEM: r.pem(), Who: tester})
	if err != nil {
		t.Fatalf("import root: %v", err)
	}
	return res
}

func TestOfflineRootImport(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	res := v.importRoot(t, "offline-root", off)
	if res.Fingerprint != fingerprint(off.cert.Raw) || !strings.Contains(strings.Join(res.Notes, "|"), res.Fingerprint) {
		t.Errorf("fingerprint %s, notes %v", res.Fingerprint, res.Notes)
	}
	cas, _ := ListCAs(t.Context(), v.pki)
	if c := cas[0]; c.KeyMode != KeyModeOffline || c.Status != StatusActive || c.CRLDays != DefaultCRLDaysOfflineRoot {
		t.Errorf("imported root: %+v", c)
	}
	if got := v.denied(t, Request{CA: "offline-root", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "offline") {
		t.Errorf("issue from offline root: %q", got)
	}
	other := newOfflineRoot(t, "Other Root", t0.Add(-day))
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(day)}, other.cert, mustKey(t, elliptic.P256()).Public(), other.key)
	future := newOfflineRoot(t, "Future Root", t0.Add(day))
	for want, certPEM := range map[string][]byte{
		"not self-signed":            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"not valid now":              future.pem(),
		"no PEM block":               []byte("nope"),
		"exactly one":                append(other.pem(), other.pem()...),
		"another CA has the subject": newOfflineRoot(t, "Offline Root", t0.Add(-day)).pem(),
	} {
		name := "new-root"
		if want == "another CA has the subject" {
			name = "twin"
		}
		_, err := v.e.ImportRoot(t.Context(), ImportRootRequest{CASettings: CASettings{Name: name, BaseURL: baseURL}, CertPEM: certPEM, Who: tester})
		if got := deniedErr(t, err); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}

	// Renewal of an offline root: same name, same subject, new key.
	renewed := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	if r2 := v.importRoot(t, "offline-root", renewed); r2.Generation != 2 || !strings.Contains(strings.Join(r2.Warnings, "|"), "new trust anchor") {
		t.Errorf("renewed root: %+v", r2)
	}
	_, err := v.e.ImportRoot(t.Context(), ImportRootRequest{CASettings: CASettings{Name: "offline-root", BaseURL: baseURL}, CertPEM: other.pem(), Who: tester})
	if got := deniedErr(t, err); !strings.Contains(got, "subject differs") {
		t.Errorf("other subject: %q", got)
	}
	_, err = v.e.RenewCA(t.Context(), RenewRequest{Name: "offline-root", Who: tester})
	if got := deniedErr(t, err); !strings.Contains(got, "renew it offline") {
		t.Errorf("RenewCA on an offline root: %q", got)
	}
}

func TestOfflineSigningFlow(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	nc := NameConstraints{PermittedDNS: []string{"homelab.lan"}}
	ir := v.intermediate(t, "issuing", "offline-root", func(r *IntermediateRequest) { r.NameConstraints = nc })
	if ir.Status != StatusPendingSignature || ir.CertDER != nil || ir.Offline == nil {
		t.Fatalf("pending intermediate: %+v", ir)
	}
	b := ir.Offline
	for _, want := range []string{"pathlen:0", "critical, @myownpki_nc", "permitted;DNS.0 = homelab.lan",
		"caIssuers;URI:" + baseURL + "/ca/offline-root/1.crt", "URI:" + baseURL + "/crl/offline-root/1.crl", "keyid:always"} {
		if !strings.Contains(b.ExtConfig, want) {
			t.Errorf("extension file lacks %q:\n%s", want, b.ExtConfig)
		}
	}
	if b.Digest != "sha384" || b.CSRFile != "issuing-1.csr" || !strings.Contains(b.Instructions, "pki ca-sign issuing-1.csr --ext issuing-1.ext") ||
		!strings.Contains(b.Instructions, "-copy_extensions none") || !strings.Contains(b.Instructions, "openssl ca -gencrl") {
		t.Errorf("bundle: digest %q\n%s", b.Digest, b.Instructions)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "pending_signature") {
		t.Errorf("issue while pending: %q", got)
	}
	again, err := v.e.OfflineBundleFor(t.Context(), "issuing")
	if err != nil || !bytes.Equal(again.CSRPEM, b.CSRPEM) || again.ExtConfig != b.ExtConfig {
		t.Errorf("bundle download again: %v", err)
	}

	// Every deviation from the order is refused – and audited.
	otherRoot := newOfflineRoot(t, "Other Root", t0.Add(-day))
	tests := map[string]struct {
		signer *offlineRoot
		mod    func(*x509.Certificate, *crypto.PublicKey)
	}{
		"another key than the CSR":      {off, func(_ *x509.Certificate, pub *crypto.PublicKey) { *pub = mustKey(t, elliptic.P256()).Public() }},
		"name constraints differ":       {off, func(c *x509.Certificate, _ *crypto.PublicKey) { c.PermittedDNSDomains = nil }},
		"path length 1, ordered 0":      {off, func(c *x509.Certificate, _ *crypto.PublicKey) { c.MaxPathLen, c.MaxPathLenZero = 1, false }},
		"not signed by parent CA":       {otherRoot, nil},
		"before the parent's notBefore": {off, func(c *x509.Certificate, _ *crypto.PublicKey) { c.NotBefore = t0.Add(-2 * day) }},
		"after the end of the parent":   {off, func(c *x509.Certificate, _ *crypto.PublicKey) { c.NotAfter = t0.AddDate(30, 0, 0) }},
		"extended key usages differ": {off, func(c *x509.Certificate, _ *crypto.PublicKey) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}},
		"keyUsage must be exactly": {off, func(c *x509.Certificate, _ *crypto.PublicKey) {
			c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}},
		"basicConstraints must be": {off, func(c *x509.Certificate, _ *crypto.PublicKey) { c.IsCA = false; c.MaxPathLenZero = false }},
	}
	for want, tt := range tests {
		_, ierr := v.e.InstallCACertificate(t.Context(), "issuing", tt.signer.sign(t, b, nc, tt.mod), tester)
		if got := deniedErr(t, ierr); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}
	// A wrong authority key identifier: the root's key, but another SKI.
	fake := *off.cert
	fake.SubjectKeyId = []byte{1, 2, 3}
	_, err = v.e.InstallCACertificate(t.Context(), "issuing", (&offlineRoot{cert: &fake, key: off.key}).sign(t, b, nc, nil), tester)
	if got := deniedErr(t, err); !strings.Contains(got, "authority key identifier") {
		t.Errorf("AKI: %q", got)
	}

	good := off.sign(t, b, nc, nil)
	res, err := v.e.InstallCACertificate(t.Context(), "issuing", good, tester)
	if err != nil || res.Status != StatusActive || res.Generation != 1 {
		t.Fatalf("install: %+v %v", res, err)
	}
	if _, ierr := v.e.InstallCACertificate(t.Context(), "issuing", good, tester); !strings.Contains(deniedErr(t, ierr), "no generation waiting") {
		t.Error("installed twice")
	}
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	opensslVerifyAt(t, t0, out.Chain, out.CertDER, "sslserver")

	// Renewal below the offline root: a second pending generation; the first
	// keeps issuing until the new certificate is installed. Its serial must
	// not repeat one the root has used.
	rr, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "issuing", Who: tester})
	if err != nil || rr.Generation != 2 || rr.Status != StatusActive || rr.Offline == nil {
		t.Fatalf("renew: %+v %v", rr, err)
	}
	v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"b.homelab.lan"}})
	firstSerial := parse(t, pemBytes(t, good)).SerialNumber
	_, err = v.e.InstallCACertificate(t.Context(), "issuing", off.sign(t, rr.Offline, nc, func(c *x509.Certificate, _ *crypto.PublicKey) { c.SerialNumber = firstSerial }), tester)
	if got := deniedErr(t, err); !strings.Contains(got, "already used") {
		t.Errorf("reused serial: %q", got)
	}
	if _, err := v.e.InstallCACertificate(t.Context(), "issuing", off.sign(t, rr.Offline, nc, nil), tester); err != nil {
		t.Fatal(err)
	}
	out = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"c.homelab.lan"}})
	if leaf := parse(t, out.CertDER); !slices.Equal(leaf.IssuingCertificateURL, []string{baseURL + "/ca/issuing/2.crt"}) {
		t.Errorf("leaf of generation 2: AIA %v", leaf.IssuingCertificateURL)
	}

	actions := map[string]int{}
	for _, row := range v.auditRows(t) {
		actions[row.action+"/"+row.result]++
	}
	if actions["ca.csr_create/success"] != 1 || actions["ca.certificate_install/success"] != 2 || actions["ca.renew/success"] != 1 ||
		actions["ca.certificate_install/denied"] != len(tests)+3 {
		t.Errorf("audit %v", actions)
	}
}

func pemBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(p)
	return block.Bytes
}

func TestOnlineRenewal(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	r1 := v.root(t, "root", nil)
	i1 := v.intermediate(t, "issuing", "root", nil)
	old := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})

	i2, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "issuing", Who: tester})
	if err != nil || i2.Generation != 2 {
		t.Fatalf("renew intermediate: %+v %v", i2, err)
	}
	c1, c2 := certOf(t, i1), certOf(t, i2)
	if string(c1.RawSubject) != string(c2.RawSubject) || publicKeyEqual(c1.PublicKey, c2.PublicKey) || c2.MaxPathLen != 0 || !c2.MaxPathLenZero {
		t.Error("a renewal keeps the exact subject and the profile, with a new key")
	}
	cur := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"b.homelab.lan"}})
	if !slices.Equal(parse(t, cur.CertDER).IssuingCertificateURL, []string{baseURL + "/ca/issuing/2.crt"}) {
		t.Error("new leaves point to generation 2")
	}
	// Both generations' leaves verify – older chains keep working.
	opensslVerifyAt(t, t0, [][]byte{i1.CertDER, r1.CertDER}, old.CertDER, "sslserver")
	opensslVerifyAt(t, t0, [][]byte{i2.CertDER, r1.CertDER}, cur.CertDER, "sslserver")

	r2, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "root", KeyAlgorithm: AlgRSA4096, Who: tester})
	if err != nil || r2.Generation != 2 || certOf(t, r2).PublicKeyAlgorithm != x509.RSA || !strings.Contains(strings.Join(r2.Warnings, "|"), "new trust anchor") {
		t.Fatalf("renew root: %+v %v", r2, err)
	}
	// The intermediate is still signed by root generation 1 until it is renewed.
	i3, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "issuing", Who: tester})
	if err != nil || !slices.Equal(certOf(t, i3).IssuingCertificateURL, []string{baseURL + "/ca/root/2.crt"}) {
		t.Fatalf("renew below the renewed root: %v", err)
	}
	if cas, _ := ListCAs(t.Context(), v.pki); len(cas[0].Generations) != 3 || cas[0].Generations[2].Issuer != "root/2" {
		t.Errorf("generations %+v", cas[0].Generations)
	}
}

func TestRetireAndUpdate(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.root(t, "root", nil)
	v.intermediate(t, "issuing", "root", nil)

	if err := v.e.UpdateCA(t.Context(), UpdateRequest{Name: "issuing", MaxValidityDays: 90, CRLDays: 2, Who: tester}); err != nil {
		t.Fatal(err)
	}
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	if out.NotAfter.Sub(out.NotBefore)+time.Second != 90*day {
		t.Errorf("new maximum not applied: %v", out.NotAfter.Sub(out.NotBefore))
	}
	for want, req := range map[string]UpdateRequest{
		"nothing to change": {Name: "issuing", MaxValidityDays: 90},
		"want 1 to 366":     {Name: "issuing", CRLDays: 400},
		"no CA named":       {Name: "nope", CRLDays: 1},
	} {
		req.Who = tester
		if got := deniedErr(t, v.e.UpdateCA(t.Context(), req)); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}

	if err := v.e.RetireCA(t.Context(), "issuing", tester); err != nil {
		t.Fatal(err)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "is retired") {
		t.Errorf("issue after retire: %q", got)
	}
	if got := deniedErr(t, v.e.RetireCA(t.Context(), "issuing", tester)); !strings.Contains(got, "retired already") {
		t.Errorf("retire twice: %q", got)
	}
	if _, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "issuing", Who: tester}); !strings.Contains(deniedErr(t, err), "not active") {
		t.Error("renewed a retired CA")
	}
}

func TestSealedCreationFails(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.e.Keys = keys.New(nil, nil, v.clk)
	_, err := v.e.CreateRoot(t.Context(), RootRequest{CASettings: CASettings{Name: "root", BaseURL: baseURL}, Subject: Subject{CommonName: "Root"}, Who: tester})
	if !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("sealed: %v", err)
	}
	if n, _ := pkidb.New(v.pki).ListCAs(t.Context()); len(n) != 0 {
		t.Error("CA stored while sealed")
	}
}

// TestLegacyPkiShAsOfflineRoot runs the offline flow end to end with
// legacy/pki.sh as the offline root (PHASE1 step 8). It needs bash and
// OpenSSL; in CI on Linux it must run. On Windows (Git Bash) it runs when
// LEGACY_TEST_OPENSSL names an OpenSSL that understands POSIX paths,
// e.g. /usr/bin/openssl.
func TestLegacyPkiShAsOfflineRoot(t *testing.T) {
	t.Parallel()
	bash, err := exec.LookPath("bash")
	legacyOpenSSL := os.Getenv("LEGACY_TEST_OPENSSL")
	if err != nil || (runtime.GOOS != "linux" && legacyOpenSSL == "") {
		if runtime.GOOS == "linux" && os.Getenv("CI") != "" {
			t.Fatal("bash missing in CI")
		}
		t.Skip("the legacy offline root test needs bash and POSIX paths: Linux, or LEGACY_TEST_OPENSSL=/usr/bin/openssl in Git Bash")
	}
	opensslBin(t)
	script, err := filepath.Abs("../../legacy/pki.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pki := func(args ...string) string {
		t.Helper()
		// #nosec G204 -- test: runs the repository's own legacy script
		cmd := exec.CommandContext(t.Context(), bash, append([]string{posixPath(script), "--dir", posixPath(filepath.Join(dir, "pki")), "-y", "--no-color"}, args...)...)
		cmd.Dir = dir
		if legacyOpenSSL != "" {
			cmd.Env = append(os.Environ(), "OPENSSL="+legacyOpenSSL)
		}
		out, cerr := cmd.CombinedOutput()
		if cerr != nil {
			t.Fatalf("pki %s: %v\n%s", strings.Join(args, " "), cerr, out)
		}
		return string(out)
	}
	pki("init", "--org", "Legacy Test", "--cn", "Legacy Offline Root", "--key", "rsa3072", "--no-pass")
	rootPEM, err := os.ReadFile(filepath.Join(dir, "pki", "root", "certs", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	rootCert := parse(t, pemBytes(t, rootPEM))

	v := newEnv(t)
	v.clk.Set(rootCert.NotBefore.Add(time.Minute))
	if _, ierr := v.e.ImportRoot(t.Context(), ImportRootRequest{CASettings: CASettings{Name: "root", BaseURL: baseURL}, CertPEM: rootPEM, Who: tester}); ierr != nil {
		t.Fatal(ierr)
	}
	ir := v.intermediate(t, "issuing", "root", func(r *IntermediateRequest) {
		r.NameConstraints = NameConstraints{PermittedDNS: []string{"homelab.lan"}, PermittedIP: []string{"10.0.0.0/8"}}
	})
	b := ir.Offline
	for name, data := range map[string][]byte{b.CSRFile: b.CSRPEM, b.ExtFile: []byte(b.ExtConfig)} {
		if werr := os.WriteFile(filepath.Join(dir, name), data, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	pki("ca-sign", b.CSRFile, "--ext", b.ExtFile, "--days", strconv.Itoa(b.Days), "--out", b.CertFile)
	certPEM, err := os.ReadFile(filepath.Join(dir, b.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, pemBytes(t, certPEM))
	v.clk.Set(cert.NotBefore.Add(time.Minute))
	if _, ierr := v.e.InstallCACertificate(t.Context(), "issuing", certPEM, tester); ierr != nil {
		t.Fatalf("install the certificate signed by pki.sh: %v", ierr)
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("signature %v", cert.SignatureAlgorithm)
	}
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, IPAddresses: []string{"10.0.0.5"}})
	opensslVerifyAt(t, v.clk.Now(), out.Chain, out.CertDER, "sslserver")

	// Step 9: the root CRL from pki.sh is uploaded; with the CRL the server
	// signs for the intermediate, the whole chain passes -crl_check_all.
	pki("crl", "--ca", "root")
	rootCRL, err := os.ReadFile(filepath.Join(dir, "pki", "publish", "root.crl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, uerr := v.e.UploadCRL(t.Context(), "root", rootCRL, tester); uerr != nil {
		t.Fatalf("upload the CRL of pki.sh: %v", uerr)
	}
	signed, err := v.e.RenewCRLs(t.Context(), "test")
	if err != nil || len(signed) != 1 {
		t.Fatalf("intermediate CRL: %+v %v", signed, err)
	}
	if res, ok := opensslWithCRLs(t, v.clk.Now(), out.Chain, [][]byte{rootCRL, signed[0].DER}, out.CertDER, "-crl_check_all"); !ok {
		t.Errorf("chain with both CRLs:\n%s", res)
	}
}

// posixPath turns C:\x\y into /c/x/y for Git Bash; other systems keep it.
func posixPath(p string) string {
	if runtime.GOOS != "windows" || len(p) < 2 || p[1] != ':' {
		return p
	}
	return "/" + strings.ToLower(p[:1]) + filepath.ToSlash(p[2:])
}

// TestOfflineSigningWithPlainOpenSSL runs the OpenSSL command exactly as the
// instructions print it, so the documented way can't drift from what works.
func TestOfflineSigningWithPlainOpenSSL(t *testing.T) {
	t.Parallel()
	bin := opensslBin(t)
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	ir := v.intermediate(t, "issuing", "offline-root", func(r *IntermediateRequest) {
		r.NameConstraints = NameConstraints{PermittedDNS: []string{"homelab.lan"}, PermittedIP: []string{"10.0.0.0/8", "fd00::/8"}}
		r.EKULimit = []string{"serverAuth", "clientAuth"}
	})
	b := ir.Offline

	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(off.key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		b.CSRFile: b.CSRPEM, b.ExtFile: []byte(b.ExtConfig), "root.crt": off.pem(),
		"root.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if werr := os.WriteFile(filepath.Join(dir, name), data, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	// The command is the "B)" block of the instructions: two lines joined
	// at the backslash.
	lines := strings.Split(b.Instructions, "\n")
	var command string
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "openssl x509 -req") {
			command = strings.TrimSuffix(strings.TrimSpace(l), "\\") + " " + strings.TrimSpace(lines[i+1])
		}
	}
	args := strings.Fields(command)
	if len(args) < 10 || !slices.Contains(args, "-sha384") || !slices.Contains(args, "none") {
		t.Fatalf("command %q", command)
	}
	cmd := exec.CommandContext(t.Context(), bin, args[1:]...)
	cmd.Dir = dir
	if out, cerr := cmd.CombinedOutput(); cerr != nil {
		t.Fatalf("%s: %v\n%s", command, cerr, out)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, b.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, pemBytes(t, certPEM))
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 || SerialHex(cert.SerialNumber) != b.Serial {
		t.Errorf("signature %v, serial %s (bundle %s)", cert.SignatureAlgorithm, SerialHex(cert.SerialNumber), b.Serial)
	}
	v.clk.Set(cert.NotBefore.Add(time.Minute))
	res, err := v.e.InstallCACertificate(t.Context(), "issuing", certPEM, tester)
	if err != nil {
		t.Fatalf("install the certificate signed by plain OpenSSL: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings %v", res.Warnings)
	}
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, IPAddresses: []string{"fd00::1"}})
	opensslVerifyAt(t, v.clk.Now(), out.Chain, out.CertDER, "sslserver")
}

// TestIssuerBytesComeFromTheUploadedCertificate: OpenSSL re-encodes the
// subject when it is set on the command line (-subj, string_mask utf8only):
// the CSR says PrintableString, the certificate UTF8String. The names are
// equal, the bytes are not – and clients compare the leaf's issuer with the
// CA's subject. So leaves must carry the bytes of the uploaded certificate,
// and the stored subject_dn must come from it as well.
func TestIssuerBytesComeFromTheUploadedCertificate(t *testing.T) {
	t.Parallel()
	bin := opensslBin(t)
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	ir := v.intermediate(t, "issuing", "offline-root", func(r *IntermediateRequest) {
		r.Subject = Subject{CommonName: "Homelab Issuing CA", Organization: "Homelab"}
	})
	b := ir.Offline
	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(off.key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		b.CSRFile: b.CSRPEM, b.ExtFile: []byte(b.ExtConfig), "root.crt": off.pem(),
		"root.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if werr := os.WriteFile(filepath.Join(dir, name), data, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	// Same name, same order as the CSR (O before CN, as Go writes it).
	cmd := exec.CommandContext(t.Context(), bin, "x509", "-req", "-in", b.CSRFile, "-subj", "/O=Homelab/CN=Homelab Issuing CA",
		"-CA", "root.crt", "-CAkey", "root.key", "-copy_extensions", "none", "-extfile", b.ExtFile, "-extensions", extSection,
		"-days", strconv.Itoa(b.Days), "-"+b.Digest, "-set_serial", "0x"+b.Serial, "-out", b.CertFile)
	cmd.Dir = dir
	if out, cerr := cmd.CombinedOutput(); cerr != nil {
		t.Fatalf("openssl: %v\n%s", cerr, out)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, b.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, pemBytes(t, certPEM))
	csr, err := x509.ParseCertificateRequest(pemBytes(t, b.CSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	// The premise: same name, other bytes (UTF8String 0x0c instead of PrintableString 0x13).
	if cert.Subject.String() != csr.Subject.String() || bytes.Equal(cert.RawSubject, csr.RawSubject) ||
		!bytes.Contains(cert.RawSubject, append([]byte{0x0c, byte(len("Homelab Issuing CA"))}, "Homelab Issuing CA"...)) ||
		!bytes.Contains(csr.RawSubject, append([]byte{0x13, byte(len("Homelab Issuing CA"))}, "Homelab Issuing CA"...)) {
		t.Fatalf("OpenSSL did not re-encode the subject:\ncert %x\ncsr  %x", cert.RawSubject, csr.RawSubject)
	}

	v.clk.Set(cert.NotBefore.Add(time.Minute))
	if _, ierr := v.e.InstallCACertificate(t.Context(), "issuing", certPEM, tester); ierr != nil {
		t.Fatalf("install: %v", ierr)
	}
	gen, err := pkidb.New(v.pki).GetCAGeneration(t.Context(), pkidb.GetCAGenerationParams{CaID: ir.ID, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gen.SubjectDn != cert.Subject.String() || !bytes.Equal(gen.CertDer, cert.Raw) {
		t.Errorf("stored generation: subject_dn %q, certificate stored as uploaded: %v", gen.SubjectDn, bytes.Equal(gen.CertDer, cert.Raw))
	}

	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})
	leaf := parse(t, out.CertDER)
	if !bytes.Equal(leaf.RawIssuer, cert.RawSubject) || bytes.Equal(leaf.RawIssuer, csr.RawSubject) {
		t.Errorf("leaf issuer %x, want the uploaded certificate's subject %x", leaf.RawIssuer, cert.RawSubject)
	}
	if !bytes.Equal(out.Chain[0], cert.Raw) {
		t.Error("the chain must contain the uploaded certificate")
	}
	opensslVerifyAt(t, v.clk.Now(), out.Chain, out.CertDER, "sslserver")
}

// TestWrongURLsStayVisible: an offline-signed CA certificate with a CDP or
// AIA elsewhere is accepted, but the warning is in the audit entry and in
// every listing of the CA – not only in the upload response.
func TestWrongURLsStayVisible(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	ir := v.intermediate(t, "issuing", "offline-root", nil)
	wrong := off.sign(t, ir.Offline, NameConstraints{}, func(c *x509.Certificate, _ *crypto.PublicKey) {
		c.CRLDistributionPoints = []string{"http://old-server.lan/root.crl"}
	})
	res, err := v.e.InstallCACertificate(t.Context(), "issuing", wrong, tester)
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(res.Warnings, "|"); !strings.Contains(w, "http://old-server.lan/root.crl") || !strings.Contains(w, "strict revocation") {
		t.Errorf("result warnings %v", res.Warnings)
	}
	var installed *auditRow
	rows := v.auditRows(t)
	for i := range rows {
		if rows[i].action == ActionCACertInstall {
			installed = &rows[i]
		}
	}
	if installed == nil || !strings.Contains(fmt.Sprint(installed.details["warnings"]), "old-server.lan") {
		t.Errorf("audit entry: %+v", installed)
	}
	cas, err := ListCAs(t.Context(), v.pki)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		if c.Name == "issuing" && (len(c.Generations[0].Warnings) != 1 || !strings.Contains(c.Generations[0].Warnings[0], "old-server.lan")) {
			t.Errorf("listing: %+v", c.Generations[0])
		}
		if c.Name == "offline-root" && len(c.Generations[0].Warnings) != 0 {
			t.Errorf("a root has no AIA/CDP to warn about: %v", c.Generations[0].Warnings)
		}
	}
}

// TestUnreadableGenerationIsAnError: a stored CA certificate that doesn't
// parse is a database problem – reported as a failure, never skipped.
func TestUnreadableGenerationIsAnError(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.importRoot(t, "offline-root", newOfflineRoot(t, "Offline Root", t0.Add(-day)))
	for _, s := range []string{`DROP TRIGGER ca_generations_cert_immutable`, `UPDATE ca_generations SET cert_der = x'3000'`} {
		if _, err := v.pki.ExecContext(t.Context(), s); err != nil {
			t.Fatal(err)
		}
	}
	_, err := v.e.ImportRoot(t.Context(), ImportRootRequest{
		CASettings: CASettings{Name: "offline-root", BaseURL: baseURL}, CertPEM: newOfflineRoot(t, "Offline Root", t0.Add(-day)).pem(), Who: tester,
	})
	if err == nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "can't be read") {
		t.Errorf("renewal over an unreadable generation: %v", err)
	}
	failed := false
	for _, row := range v.auditRows(t) {
		failed = failed || (row.action == ActionCAImportRoot && row.result == "failure" && strings.Contains(fmt.Sprint(row.details["error"]), "can't be read"))
	}
	if !failed {
		t.Error("the failed renewal is not in the audit log")
	}
}
