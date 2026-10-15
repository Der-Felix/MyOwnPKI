package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Offline signing (owner decision 2026-10-14, step 8 a): the server creates
// the key and the CSR of an intermediate below an offline root and hands out
// an OpenSSL extension file. The offline root signs with exactly that file –
// never with extensions from the CSR – and the signed certificate is
// uploaded and checked against the order before the CA becomes active.

// extSection is the section name in the extension file.
const extSection = "v3_myownpki_ca"

// OfflineBundle is what the admin takes to the offline root.
type OfflineBundle struct {
	CSRPEM    []byte
	ExtConfig string // contents of the extension file
	// Suggested file names: <name>-<generation>.csr / .ext / .crt.
	CSRFile, ExtFile, CertFile string
	Days                       int    // -days for the signature; ends before the parent does
	Digest                     string // matches the root key: sha384 for P-384; "" for Ed25519
	Serial                     string // random 159-bit serial for plain OpenSSL (-set_serial)
	Instructions               string
}

// offlineBundle builds the bundle for a planned generation.
func (e *Engine) offlineBundle(plan *caPlan, csrDER []byte) (*OfflineBundle, error) {
	p := plan.parent
	base := fmt.Sprintf("%s-%d", plan.name, plan.generation)
	serial, err := newSerial(e.rand())
	if err != nil {
		return nil, err
	}
	b := &OfflineBundle{
		CSRPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		CSRFile: base + ".csr", ExtFile: base + ".ext", CertFile: base + ".crt",
		Digest: digestFor(p.cert().PublicKey), Serial: SerialHex(serial),
	}
	// -days counts from the moment of signing: keep a day of slack so the
	// certificate still ends before the parent when it is signed tomorrow.
	b.Days = plan.v.days
	if left := int(p.cert().NotAfter.Sub(e.now())/day) - 1; b.Days > left {
		b.Days = left
	}
	if b.Days < 1 {
		return nil, deny("parent CA %q ends too soon to sign a new CA below it", p.ca.Name)
	}
	b.ExtConfig = extConfig(plan)
	b.Instructions = instructions(plan, b)
	return b, nil
}

// digestFor names the OpenSSL digest that matches the signing key.
func digestFor(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return "sha384"
		case elliptic.P521():
			return "sha512"
		}
		return "sha256"
	case *rsa.PublicKey:
		return "sha256"
	}
	return ""
}

// extConfig writes the OpenSSL extension section for the CA certificate.
func extConfig(plan *caPlan) string {
	var b strings.Builder
	p := plan.parent
	fmt.Fprintf(&b, "# MyOwnPKI - extensions for the intermediate CA %q, generation %d\n", plan.name, plan.generation)
	fmt.Fprintf(&b, "# Sign with exactly this file; extensions in the CSR are never copied.\n")
	fmt.Fprintf(&b, "[ %s ]\n", extSection)
	fmt.Fprintf(&b, "basicConstraints       = critical, CA:TRUE, pathlen:%d\n", plan.pathLen)
	fmt.Fprintf(&b, "keyUsage               = critical, digitalSignature, keyCertSign, cRLSign\n")
	fmt.Fprintf(&b, "subjectKeyIdentifier   = hash\n")
	fmt.Fprintf(&b, "authorityKeyIdentifier = keyid:always\n")
	if len(plan.ekuLimit) > 0 {
		names := make([]string, len(plan.ekuLimit))
		for i, oid := range plan.ekuLimit {
			if n := preset.ExtKeyUsageName(oid); n != "" {
				names[i] = n
			} else {
				names[i] = oid.String()
			}
		}
		fmt.Fprintf(&b, "extendedKeyUsage       = %s\n", strings.Join(names, ", "))
	}
	if len(plan.nc.rows) > 0 {
		crit := ""
		if plan.nc.critical {
			crit = "critical, "
		}
		fmt.Fprintf(&b, "nameConstraints        = %s@myownpki_nc\n", crit)
	}
	fmt.Fprintf(&b, "authorityInfoAccess    = caIssuers;URI:%s\n", CertURL(p.ca.PublicBaseUrl, p.ca.Name, p.gen.Generation))
	fmt.Fprintf(&b, "crlDistributionPoints  = URI:%s\n", CRLURL(p.ca.PublicBaseUrl, p.ca.Name, p.gen.Generation))
	if len(plan.nc.rows) > 0 {
		fmt.Fprintf(&b, "\n[ myownpki_nc ]\n")
		n := map[string]int{}
		for _, r := range plan.nc.rows {
			mode := "excluded"
			if r.permitted {
				mode = "permitted"
			}
			kind, value := map[string]string{"dns": "DNS", "ip": "IP", "email": "email", "uri": "URI"}[r.kind], r.value
			if r.kind == "ip" {
				value = opensslIPMask(r.value)
			}
			key := mode + ";" + kind
			fmt.Fprintf(&b, "%s.%d = %s\n", key, n[key], value)
			n[key]++
		}
	}
	return b.String()
}

// opensslIPMask writes a prefix the way OpenSSL's config expects it:
// address/netmask (10.0.0.0/255.0.0.0, fd00::/ff00::).
func opensslIPMask(prefix string) string {
	p := netip.MustParsePrefix(prefix)
	mask := net.IP(net.CIDRMask(p.Bits(), p.Addr().BitLen()))
	return p.Addr().String() + "/" + mask.String()
}

func instructions(plan *caPlan, b *OfflineBundle) string {
	p := plan.parent
	digest := ""
	if b.Digest != "" {
		digest = " -" + b.Digest
	}
	var s strings.Builder
	fmt.Fprintf(&s, "Sign the intermediate CA %q (generation %d) with the offline root %q.\n\n", plan.name, plan.generation, p.ca.Name)
	fmt.Fprintf(&s, "Files: %s (request), %s (extensions - use exactly this file).\n\n", b.CSRFile, b.ExtFile)
	fmt.Fprintf(&s, "A) With legacy pki.sh as the offline root:\n")
	fmt.Fprintf(&s, "   pki ca-sign %s --ext %s --days %d --out %s\n\n", b.CSRFile, b.ExtFile, b.Days, b.CertFile)
	fmt.Fprintf(&s, "B) With plain OpenSSL (root.crt and root.key of the offline root).\n")
	fmt.Fprintf(&s, "   Needs OpenSSL 3.0 or newer – macOS ships LibreSSL, there: brew install openssl@3\n")
	fmt.Fprintf(&s, "   openssl x509 -req -in %s -CA root.crt -CAkey root.key -copy_extensions none \\\n", b.CSRFile)
	fmt.Fprintf(&s, "     -extfile %s -extensions %s -days %d%s -set_serial 0x%s -out %s\n\n", b.ExtFile, extSection, b.Days, digest, b.Serial, b.CertFile)
	fmt.Fprintf(&s, "Then upload %s to MyOwnPKI. It is checked against this order before the CA becomes active.\n\n", b.CertFile)
	fmt.Fprintf(&s, "The CRL of the offline root (served at %s) can only be signed offline.\n", CRLURL(p.ca.PublicBaseUrl, p.ca.Name, p.gen.Generation))
	fmt.Fprintf(&s, "Create it there and upload it to MyOwnPKI; renew it before half of its lifetime (%d days) has passed:\n", p.ca.CrlDays)
	fmt.Fprintf(&s, "   legacy:  pki crl --ca root            (writes publish/root.crl)\n")
	fmt.Fprintf(&s, "   OpenSSL: openssl ca -gencrl -config <root openssl.cnf> -crldays %d%s -out root-crl.pem\n", p.ca.CrlDays, digest)
	fmt.Fprintf(&s, "            openssl crl -in root-crl.pem -outform DER -out root.crl\n")
	fmt.Fprintf(&s, "            (openssl ca needs the CA database of the root: index.txt and crlnumber)\n")
	return s.String()
}

// OfflineBundleFor rebuilds the bundle of a CA generation that waits for its
// signature, e.g. to download it again.
func (e *Engine) OfflineBundleFor(ctx context.Context, name string) (*OfflineBundle, error) {
	q := pkidb.New(e.PKI)
	ca, pending, parent, err := loadPending(ctx, q, name, e.now())
	if err != nil {
		return nil, err
	}
	plan, err := planFromCA(ctx, q, ca, parent)
	if err != nil {
		return nil, err
	}
	plan.generation = pending.Generation
	plan.v = caValidity(e.now(), 0, DefaultIntermediateDays, parent.cert())
	return e.offlineBundle(plan, pending.CsrDer)
}

// loadPending reads a CA, its generation waiting for a signature and the
// intended parent generation.
func loadPending(ctx context.Context, q *pkidb.Queries, name string, now time.Time) (pkidb.Ca, pkidb.CaGeneration, *parentInfo, error) {
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return ca, pkidb.CaGeneration{}, nil, deny("there is no CA named %q", short(name))
	}
	if err != nil {
		return ca, pkidb.CaGeneration{}, nil, err
	}
	pending, err := q.GetPendingGeneration(ctx, ca.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return ca, pending, nil, deny("CA %q has no generation waiting for a signature", name)
	}
	if err != nil {
		return ca, pending, nil, err
	}
	if ca.Status == StatusRetired {
		return ca, pending, nil, deny("CA %q is retired", name)
	}
	pca, err := q.GetCA(ctx, pending.IssuerCaID.String)
	if err != nil {
		return ca, pending, nil, fmt.Errorf("load parent of CA %q: %w", name, err)
	}
	pgen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: pca.ID, Generation: pending.IssuerGeneration.Int64})
	if err != nil {
		return ca, pending, nil, err
	}
	certs, _, err := loadChain(ctx, q, pca, pgen)
	if err != nil {
		return ca, pending, nil, err
	}
	return ca, pending, &parentInfo{ca: pca, gen: pgen, certs: certs}, nil
}

// planFromCA rebuilds the order of an existing CA from the database.
func planFromCA(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, parent *parentInfo) (*caPlan, error) {
	plan := &caPlan{caID: ca.ID, name: ca.Name, kind: ca.Kind, parent: parent, pathLen: -1, baseURL: ca.PublicBaseUrl}
	if ca.PathLen.Valid {
		plan.pathLen = int(ca.PathLen.Int64)
	}
	rows, err := q.ListNameConstraints(ctx, ca.ID)
	if err != nil {
		return nil, err
	}
	plan.nc.critical = ca.NcCritical == 1
	for _, r := range rows {
		plan.nc.rows = append(plan.nc.rows, constraint{kind: r.Kind, value: r.Value, permitted: r.Permitted == 1})
	}
	var limit []string
	if err := json.Unmarshal([]byte(ca.EkuLimit), &limit); err != nil {
		return nil, fmt.Errorf("CA %q: eku_limit: %w", ca.Name, err)
	}
	for _, s := range limit {
		oid, err := parseDottedOID(s)
		if err != nil {
			return nil, err
		}
		plan.ekuLimit = append(plan.ekuLimit, oid)
	}
	return plan, nil
}

// InstallCACertificate takes the certificate the offline root signed and
// activates the waiting generation – after checking that it is exactly what
// was ordered.
func (e *Engine) InstallCACertificate(ctx context.Context, name string, certPEM []byte, who keys.Who) (*CAResult, error) {
	now := e.now()
	out, err := e.installCACertificate(ctx, name, certPEM, who, now)
	return e.finish(ctx, now, ActionCACertInstall, who, name, out, err)
}

func (e *Engine) installCACertificate(ctx context.Context, name string, certPEM []byte, who keys.Who, now time.Time) (*CAResult, error) {
	if err := e.authorize(who, authz.ManageCA, short(name), now); err != nil {
		return nil, err
	}
	// The generation's key is on this server: it signs its first CRL at once.
	if e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	q := pkidb.New(e.PKI)
	ca, pending, parent, err := loadPending(ctx, q, name, now)
	if err != nil {
		return nil, err
	}
	cert, err := parseOneCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(pending.CsrDer)
	if err != nil {
		return nil, fmt.Errorf("CA %q: stored CSR: %w", name, err)
	}
	plan, err := planFromCA(ctx, q, ca, parent)
	if err != nil {
		return nil, err
	}
	reasons, warnings := checkOrdered(cert, csr, plan, now)
	if berr := checkKeyNotBlocked(ctx, q, cert.PublicKey); berr != nil {
		reasons = append(reasons, berr.Error())
	}
	if serr := checkSerialFree(ctx, q, parent.ca.ID, SerialHex(cert.SerialNumber)); serr != nil {
		reasons = append(reasons, serr.Error()+" – sign again with a new serial")
	}
	if len(reasons) == 0 {
		if verr := verifyCAChain(cert, parent.certs, now); verr != nil {
			reasons = append(reasons, verr.Error())
		}
	}
	if len(reasons) > 0 {
		return nil, &DeniedError{Reasons: reasons}
	}

	if !pending.KeyID.Valid {
		return nil, fmt.Errorf("CA %q generation %d has no key on this server", ca.Name, pending.Generation)
	}
	key, err := keys.LoadKey(ctx, e.PKI, pending.KeyID.String)
	if err != nil {
		return nil, err
	}
	var gen pkidb.InsertCAGenerationParams
	fillGeneration(&gen, cert)
	out := &CAResult{ID: ca.ID, Name: ca.Name, Status: StatusActive, Generation: pending.Generation, CertDER: cert.Raw,
		Fingerprint: gen.FingerprintSha256.String, Warnings: warnings}
	details := map[string]any{
		"name": ca.Name, "generation": pending.Generation, "parent": parent.ca.Name, "parent_generation": parent.gen.Generation,
		"serial": gen.SerialHex.String, "fingerprint": out.Fingerprint, "not_after": gen.NotAfter.String,
	}
	if len(warnings) > 0 {
		details["warnings"] = warnings
	}
	updated := now.Format(audit.TimeFormat)
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := checkSerialFree(ctx, q, parent.ca.ID, gen.SerialHex.String); terr != nil {
			return terr
		}
		n, terr := q.InstallCAGenerationCert(ctx, pkidb.InstallCAGenerationCertParams{
			SerialHex: gen.SerialHex, NotBefore: gen.NotBefore, NotAfter: gen.NotAfter, CertDer: gen.CertDer,
			FingerprintSha256: gen.FingerprintSha256, SkiHex: gen.SkiHex, CaID: ca.ID, Generation: pending.Generation,
		})
		if terr != nil {
			return terr
		}
		if n != 1 {
			return fmt.Errorf("CA %q generation %d was signed meanwhile", ca.Name, pending.Generation)
		}
		if terr = q.SetCurrentGeneration(ctx, pkidb.SetCurrentGenerationParams{
			CurrentGeneration: sql.NullInt64{Int64: pending.Generation, Valid: true}, UpdatedAt: updated, ID: ca.ID,
		}); terr != nil {
			return terr
		}
		if ca.Status == StatusPendingSignature {
			if terr = q.SetCAStatus(ctx, pkidb.SetCAStatusParams{Status: StatusActive, UpdatedAt: updated, ID: ca.ID}); terr != nil {
				return terr
			}
		}
		if terr = audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionCACertInstall, Target: audit.Target{Type: "ca", ID: ca.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
		}); terr != nil {
			return terr
		}
		out.CRL, terr = e.writeCRL(ctx, q, tx, ca.ID, pending.Generation, cert, func(fn func(crypto.Signer) error) error {
			return e.Keys.WithSigner(key.ID, key.Purpose, key.Algorithm, key.Envelope, fn)
		}, ActionCACertInstall, who, now)
		return terr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// checkOrdered compares an offline-signed CA certificate with the order:
// every difference is a reason; AIA/CDP elsewhere are warnings.
func checkOrdered(cert *x509.Certificate, csr *x509.CertificateRequest, plan *caPlan, now time.Time) (reasons, warnings []string) {
	p := plan.parent
	pc := p.cert()
	add := func(format string, args ...any) { reasons = append(reasons, fmt.Sprintf(format, args...)) }

	if !acceptedSignature(cert.SignatureAlgorithm) {
		add("the certificate is signed with %v – only SHA-2 (RSA, ECDSA) and Ed25519 signatures are accepted; sign with %s", cert.SignatureAlgorithm, orDefault(digestFor(pc.PublicKey), "the default digest"))
	}
	if !publicKeyEqual(csr.PublicKey, cert.PublicKey) {
		add("the certificate is for another key than the CSR of this CA – upload the certificate signed from %s", plan.name)
	}
	// Compared by content: OpenSSL may re-encode string types (PrintableString
	// to UTF8String) when it signs, which doesn't change the name.
	if cert.Subject.String() != csr.Subject.String() {
		add("the subject %q differs from the CSR (%q)", cert.Subject, csr.Subject)
	}
	if err := cert.CheckSignatureFrom(pc); err != nil || !bytes.Equal(cert.RawIssuer, pc.RawSubject) {
		add("the certificate is not signed by parent CA %q generation %d", p.ca.Name, p.gen.Generation)
	}
	if !bytes.Equal(cert.AuthorityKeyId, pc.SubjectKeyId) {
		add("the authority key identifier doesn't match the subject key identifier of parent CA %q – use authorityKeyIdentifier = keyid:always", p.ca.Name)
	}
	reasons = append(reasons, checkCACertBasics(cert, now)...)
	if want := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		add("keyUsage must be exactly digitalSignature, keyCertSign, cRLSign")
	}
	if cert.MaxPathLen != plan.pathLen || (plan.pathLen == 0 && !cert.MaxPathLenZero) {
		add("path length %s, ordered %d", pathLenString(cert), plan.pathLen)
	}
	if got := ncFromCert(cert); !sameConstraints(got, plan.nc) {
		add("name constraints differ from the order: certificate %v (critical %v), ordered %v (critical %v)",
			ncStrings(got.rows), got.critical, ncStrings(plan.nc.rows), plan.nc.critical)
	}
	if got, ok := certEKUs(cert); !ok || !sameOIDs(got, plan.ekuLimit) {
		add("extended key usages differ from the order: certificate %s, ordered %s", oidList(got), orDefault(oidList(plan.ekuLimit), "none"))
	}
	if cert.NotBefore.Before(pc.NotBefore) {
		add("notBefore %s is before the parent's notBefore %s", cert.NotBefore.Format(time.RFC3339), pc.NotBefore.Format(time.RFC3339))
	}
	if cert.NotAfter.After(pc.NotAfter) {
		add("notAfter %s is after the end of the parent (%s) – a CA never issues beyond its own end; sign with fewer days",
			cert.NotAfter.Format(time.DateOnly), pc.NotAfter.Format(time.DateOnly))
	}
	if s := cert.SerialNumber; s.Sign() <= 0 || len(s.Bytes()) > 20 {
		add("serial %s: want a positive serial of at most 20 bytes (RFC 5280)", SerialHex(s))
	}
	return reasons, urlWarnings(cert, p.ca, p.gen.Generation)
}

// urlWarnings compares the AIA and CDP URLs of a CA certificate with the
// URLs MyOwnPKI publishes for its issuer generation. A certificate signed
// offline may point elsewhere; that is accepted, but stays visible: with a
// wrong CDP, clients with strict revocation checking reject every
// certificate below this CA. Derived from the stored certificate, so the
// warning is shown wherever the CA is shown (ca show, later API and UI).
func urlWarnings(cert *x509.Certificate, issuer pkidb.Ca, issuerGeneration int64) []string {
	var warnings []string
	wantAIA, wantCDP := CertURL(issuer.PublicBaseUrl, issuer.Name, issuerGeneration), CRLURL(issuer.PublicBaseUrl, issuer.Name, issuerGeneration)
	if !slices.Equal(cert.IssuingCertificateURL, []string{wantAIA}) {
		warnings = append(warnings, fmt.Sprintf("AIA caIssuers is %v, MyOwnPKI serves %s – clients may not find the parent certificate", cert.IssuingCertificateURL, wantAIA))
	}
	if !slices.Equal(cert.CRLDistributionPoints, []string{wantCDP}) {
		warnings = append(warnings, fmt.Sprintf("CRL distribution point is %v, MyOwnPKI serves %s – clients with strict revocation checking may reject every certificate below this CA", cert.CRLDistributionPoints, wantCDP))
	}
	return warnings
}

func pathLenString(c *x509.Certificate) string {
	if c.MaxPathLen < 0 || (c.MaxPathLen == 0 && !c.MaxPathLenZero) {
		return "none"
	}
	return strconv.Itoa(c.MaxPathLen)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
