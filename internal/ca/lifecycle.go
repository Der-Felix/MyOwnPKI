package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// CA lifecycle (PHASE1 step 8): create an online root, import an offline
// root, create intermediates (signed at once by an online parent, or through
// the offline flow: CSR out, certificate in), renew with a new key (a new
// generation), retire, change limits. Every change is audited in the same
// pki.db transaction; refusals go to the tenant audit log directly.

// Audit actions of the CA lifecycle.
const (
	ActionCACreate      = "ca.create"
	ActionCAImportRoot  = "ca.import_root"
	ActionCACSRCreate   = "ca.csr_create"
	ActionCACertInstall = "ca.certificate_install"
	ActionCARenew       = "ca.renew"
	ActionCARetire      = "ca.retire"
	ActionCAUpdate      = "ca.update"
)

// Kinds of CA (cas.kind).
const (
	KindRoot         = "root"
	KindIntermediate = "intermediate"
)

// CASettings are what every CA has, whatever its kind.
type CASettings struct {
	Name            string // immutable: part of every AIA/CRL URL
	BaseURL         string // public base URL for AIA/CRL; immutable once used
	CRLDays         int    // 0 = default for the kind
	MaxValidityDays int    // cap for leaves; 0 = 397
}

// RootRequest creates an online root: its key is encrypted in pki.db.
type RootRequest struct {
	CASettings
	Subject      Subject
	KeyAlgorithm string // "" = ecdsa-p384
	ValidityDays int    // 0 = 7300
	Who          keys.Who
}

// ImportRootRequest imports the certificate of an offline root. A request
// for an existing offline root with a new key adds its next generation.
type ImportRootRequest struct {
	CASettings
	CertPEM []byte
	Who     keys.Who
}

// IntermediateRequest creates an intermediate under Parent.
type IntermediateRequest struct {
	CASettings
	Parent          string
	Subject         Subject
	KeyAlgorithm    string // "" = ecdsa-p384
	ValidityDays    int    // 0 = 3650, never beyond the parent
	PathLen         int    // 0 = may only issue end-entity certificates
	NameConstraints NameConstraints
	EKULimit        []string // EKU names or OIDs; empty = no limit
	Who             keys.Who
}

// RenewRequest renews a CA with a new key: a new generation.
type RenewRequest struct {
	Name         string
	KeyAlgorithm string // "" = the current algorithm (if allowed for new CAs)
	ValidityDays int
	Who          keys.Who
}

// CAResult describes the CA after a change.
type CAResult struct {
	ID, Name, Status string
	Generation       int64
	CertDER          []byte // nil while the generation waits for its offline signature
	Fingerprint      string // SHA-256 of CertDER, upper-case hex
	Offline          *OfflineBundle
	CRL              *CRLResult // the first CRL of a generation whose key is on this server
	Notes, Warnings  []string
}

// caPlan is a checked CA change, ready to be signed and stored.
type caPlan struct {
	newCA    *pkidb.InsertCAParams // nil when a generation is added to an existing CA
	nc       checkedNC
	ekuLimit []asn1.ObjectIdentifier
	pathLen  int // -1 = none (root)

	caID, name, kind string
	baseURL          string
	generation       int64
	subject          pkix.Name
	rawSubject       []byte // renewal: the exact DN bytes of the current generation
	alg              string
	v                validity
	parent           *parentInfo // nil for a root

	action          string
	notes, warnings []string
}

// parentInfo is the signing generation of the parent CA.
type parentInfo struct {
	ca    pkidb.Ca
	gen   pkidb.CaGeneration
	certs []*x509.Certificate // the parent's chain, parent first
}

func (p *parentInfo) cert() *x509.Certificate { return p.certs[0] }

func (e *Engine) now() time.Time { return e.Clock.Now().UTC().Truncate(time.Second) }

// CreateRoot creates an online root CA.
func (e *Engine) CreateRoot(ctx context.Context, req RootRequest) (*CAResult, error) {
	now := e.now()
	out, err := e.createRoot(ctx, req, now)
	return e.finish(ctx, now, ActionCACreate, req.Who, req.Name, out, err)
}

func (e *Engine) createRoot(ctx context.Context, req RootRequest, now time.Time) (*CAResult, error) {
	if err := e.authorize(req.Who, authz.ManageCA, "", now); err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	plan := &caPlan{kind: KindRoot, name: req.Name, generation: 1, pathLen: -1, action: ActionCACreate}
	var reasons []string
	reasons = append(reasons, e.checkNewCA(ctx, q, &plan.newCA, req.CASettings, KindRoot, KeyModeOnlineEncrypted, DefaultCRLDaysOnlineRoot, plan)...)
	subj, sp := checkCASubject(req.Subject)
	reasons = append(reasons, sp...)
	plan.subject = subj.pkix()
	plan.alg, sp = newCAAlgorithm(req.KeyAlgorithm, "")
	reasons = append(reasons, sp...)
	plan.v = caValidity(now, req.ValidityDays, DefaultRootDays, nil)
	if plan.v.problem != "" {
		reasons = append(reasons, plan.v.problem)
	}
	reasons = append(reasons, checkSubjectFree(ctx, q, plan.subject.String(), "")...)
	if len(reasons) > 0 {
		return nil, &DeniedError{Reasons: reasons}
	}
	plan.caID = plan.newCA.ID
	plan.warnings = append(plan.warnings, "online root: its key is on this server – fine for tests and a homelab; best practice is an offline root (import its certificate instead)")
	return e.signAndStore(ctx, now, plan, req.Who)
}

// CreateIntermediate creates an intermediate CA. An online parent signs it
// at once; under an offline parent it waits for the signed certificate
// (InstallCACertificate) and the result carries the offline bundle.
func (e *Engine) CreateIntermediate(ctx context.Context, req IntermediateRequest) (*CAResult, error) {
	now := e.now()
	out, err := e.createIntermediate(ctx, req, now)
	return e.finish(ctx, now, ActionCACreate, req.Who, req.Name, out, err)
}

func (e *Engine) createIntermediate(ctx context.Context, req IntermediateRequest, now time.Time) (*CAResult, error) {
	if err := e.authorize(req.Who, authz.ManageCA, "", now); err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	parent, err := loadParent(ctx, q, req.Parent, now)
	if err != nil {
		return nil, err
	}
	plan := &caPlan{kind: KindIntermediate, name: req.Name, generation: 1, pathLen: req.PathLen, parent: parent, action: ActionCACreate}
	var reasons []string
	reasons = append(reasons, e.checkNewCA(ctx, q, &plan.newCA, req.CASettings, KindIntermediate, KeyModeOnlineEncrypted, DefaultCRLDaysIntermediate, plan)...)
	subj, sp := checkCASubject(req.Subject)
	reasons = append(reasons, sp...)
	plan.subject = subj.pkix()
	plan.alg, sp = newCAAlgorithm(req.KeyAlgorithm, "")
	reasons = append(reasons, sp...)

	var np []string
	plan.nc, np = checkNameConstraints(req.NameConstraints)
	reasons = append(reasons, np...)
	plan.ekuLimit, np = resolveEKULimit(req.EKULimit)
	reasons = append(reasons, np...)
	reasons = append(reasons, checkUnderParent(parent, plan)...)
	plan.v = caValidity(now, req.ValidityDays, DefaultIntermediateDays, parent.cert())
	if plan.v.problem != "" {
		reasons = append(reasons, plan.v.problem)
	}
	reasons = append(reasons, checkSubjectFree(ctx, q, plan.subject.String(), "")...)
	if len(reasons) > 0 {
		return nil, &DeniedError{Reasons: reasons}
	}
	plan.caID = plan.newCA.ID
	plan.newCA.ParentID = sql.NullString{String: parent.ca.ID, Valid: true}
	plan.newCA.PathLen = sql.NullInt64{Int64: int64(req.PathLen), Valid: true}
	plan.newCA.NcCritical = boolInt(plan.nc.critical)
	limit, _ := json.Marshal(oidStrings(plan.ekuLimit))
	plan.newCA.EkuLimit = string(limit)
	if parent.ca.KeyMode == KeyModeOffline {
		plan.newCA.Status = StatusPendingSignature
		plan.action = ActionCACSRCreate
	}
	plan.warnings = append(plan.warnings, ncOutsideParent(parent.cert(), plan.nc)...)
	return e.signAndStore(ctx, now, plan, req.Who)
}

// checkNewCA checks name, base URL and limits and fills the cas row.
func (e *Engine) checkNewCA(ctx context.Context, q *pkidb.Queries, row **pkidb.InsertCAParams, s CASettings, kind, keyMode string, crlDefault int, plan *caPlan) []string {
	var reasons []string
	if err := checkCAName(s.Name); err != nil {
		reasons = append(reasons, err.Error())
	} else if _, err := q.GetCAByName(ctx, s.Name); err == nil {
		reasons = append(reasons, fmt.Sprintf("a CA named %q exists already – CA names are unique and never reused", s.Name))
	}
	base, warnings, err := checkBaseURL(s.BaseURL)
	if err != nil {
		reasons = append(reasons, err.Error())
	}
	plan.baseURL = base
	plan.warnings = append(plan.warnings, warnings...)
	crlDays, maxDays := s.CRLDays, s.MaxValidityDays
	if crlDays == 0 {
		crlDays = crlDefault
	}
	if maxDays == 0 {
		maxDays = DefaultMaxValidityDays
	}
	reasons = append(reasons, checkLimits(crlDays, maxDays)...)
	id, err := ids.New("ca", e.now(), nil)
	if err != nil {
		return append(reasons, err.Error())
	}
	created := e.now().Format(audit.TimeFormat)
	*row = &pkidb.InsertCAParams{
		ID: id, Name: s.Name, Kind: kind, Status: StatusActive, KeyMode: keyMode, NcCritical: 1, EkuLimit: "[]",
		PublicBaseUrl: base, CrlDays: int64(crlDays), MaxValidityDays: int64(maxDays), CreatedAt: created, UpdatedAt: created,
	}
	return reasons
}

func checkLimits(crlDays, maxDays int) []string {
	var reasons []string
	if crlDays < 1 || crlDays > 366 {
		reasons = append(reasons, fmt.Sprintf("CRL validity of %d days: want 1 to 366", crlDays))
	}
	if maxDays < 1 || maxDays > 3650 {
		reasons = append(reasons, fmt.Sprintf("maximum certificate validity of %d days: want 1 to 3650", maxDays))
	}
	return reasons
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// newCAAlgorithm applies the key policy for CAs MyOwnPKI creates.
func newCAAlgorithm(requested, current string) (string, []string) {
	alg := requested
	if alg == "" {
		alg = DefaultCAKeyAlgorithm
		if slices.Contains(CAAlgorithms, current) {
			alg = current
		}
	}
	if !slices.Contains(CAAlgorithms, alg) {
		return alg, []string{fmt.Sprintf("key algorithm %q is not offered for new CAs (allowed: %s) – browsers and Windows don't accept Ed25519 or P-521 chains, and RSA 2048 is too weak for a CA",
			short(alg), strings.Join(CAAlgorithms, ", "))}
	}
	return alg, nil
}

// caValidity: like leaves (decision b) – explicit is accepted or denied, the
// default adapts to the parent's end with a note.
func caValidity(now time.Time, requested, def int, parent *x509.Certificate) validity {
	var v validity
	explicit := requested != 0
	switch {
	case requested < 0 || requested > maxCADays:
		v.problem = fmt.Sprintf("validity of %d days: want 1 to %d", requested, maxCADays)
		return v
	case explicit:
		v.days = requested
	default:
		v.days = def
	}
	v.notBefore = now.Add(-Backdate)
	if parent != nil && v.notBefore.Before(parent.NotBefore) {
		v.notBefore = parent.NotBefore
	}
	v.notAfter = v.notBefore.Add(time.Duration(v.days)*day - time.Second)
	if parent != nil && v.notAfter.After(parent.NotAfter) {
		if explicit {
			v.problem = fmt.Sprintf("validity of %d days would end after the parent CA certificate (%s) – a CA never issues beyond its own end",
				requested, parent.NotAfter.Format(time.DateOnly))
			return v
		}
		v.notAfter = parent.NotAfter
		v.notes = append(v.notes, fmt.Sprintf("validity shortened to the end of the parent CA certificate (%s)", parent.NotAfter.Format(time.DateOnly)))
	}
	v.days = int(v.notAfter.Sub(v.notBefore)/day) + 1
	return v
}

func checkSubjectFree(ctx context.Context, q *pkidb.Queries, dn, caID string) []string {
	n, err := q.CountSubjectElsewhere(ctx, pkidb.CountSubjectElsewhereParams{SubjectDn: dn, CaID: caID})
	if err != nil {
		return []string{err.Error()}
	}
	if n > 0 {
		return []string{fmt.Sprintf("another CA has the subject %q – two CAs with one name confuse chain building in clients; choose another common name", dn)}
	}
	return nil
}

// loadParent reads the parent CA and its signing (current) generation.
func loadParent(ctx context.Context, q *pkidb.Queries, name string, now time.Time) (*parentInfo, error) {
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, deny("there is no parent CA named %q", short(name))
	}
	if err != nil {
		return nil, err
	}
	switch {
	case ca.Status != StatusActive:
		return nil, deny("parent CA %q is %s, not active", name, ca.Status)
	case ca.KeyMode == KeyModeHSM:
		return nil, deny("parent CA %q uses an HSM key, which this build can't use", name)
	case !ca.CurrentGeneration.Valid:
		return nil, deny("parent CA %q has no signed certificate yet", name)
	}
	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: ca.ID, Generation: ca.CurrentGeneration.Int64})
	if err != nil {
		return nil, err
	}
	certs, _, err := loadChain(ctx, q, ca, gen)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, deny("the chain of parent CA %q is not valid now (%s valid from %s to %s)",
				name, c.Subject.CommonName, c.NotBefore.Format(time.DateOnly), c.NotAfter.Format(time.DateOnly))
		}
	}
	return &parentInfo{ca: ca, gen: gen, certs: certs}, nil
}

// checkUnderParent: path length and EKU limit must fit into the parent's.
func checkUnderParent(parent *parentInfo, plan *caPlan) []string {
	var reasons []string
	pc := parent.cert()
	switch {
	case plan.pathLen < 0 || plan.pathLen > 8:
		reasons = append(reasons, fmt.Sprintf("path length %d: want 0 to 8", plan.pathLen))
	case pc.MaxPathLen == 0:
		reasons = append(reasons, fmt.Sprintf("parent CA %q has path length 0 – it may only issue end-entity certificates, no further CA", parent.ca.Name))
	case pc.MaxPathLen > 0 && plan.pathLen >= pc.MaxPathLen:
		reasons = append(reasons, fmt.Sprintf("path length %d is too large: parent CA %q allows at most %d below the new CA", plan.pathLen, parent.ca.Name, pc.MaxPathLen-1))
	}
	if parentEKU, _ := certEKUs(pc); len(parentEKU) > 0 {
		if len(plan.ekuLimit) == 0 {
			plan.notes = append(plan.notes, fmt.Sprintf("parent CA %q limits the extended key usages; certificates below the new CA inherit that limit", parent.ca.Name))
		}
		for _, oid := range plan.ekuLimit {
			if !slices.ContainsFunc(parentEKU, oid.Equal) {
				reasons = append(reasons, fmt.Sprintf("EKU limit %s is not allowed by parent CA %q (allowed: %s)", oid, parent.ca.Name, oidList(parentEKU)))
			}
		}
	}
	return reasons
}

// ncOutsideParent warns about permitted DNS names the parent doesn't permit:
// certificates for them would never verify.
func ncOutsideParent(pc *x509.Certificate, nc checkedNC) []string {
	if len(pc.PermittedDNSDomains) == 0 {
		return nil
	}
	var w []string
	for _, r := range nc.rows {
		if r.kind != "dns" || !r.permitted {
			continue
		}
		name := strings.TrimPrefix(r.value, ".")
		if !slices.ContainsFunc(pc.PermittedDNSDomains, func(p string) bool { return matchDNS(name, p) }) {
			w = append(w, fmt.Sprintf("permitted DNS name %s is outside the parent's name constraints (%s) – certificates for it would not verify",
				r.value, strings.Join(pc.PermittedDNSDomains, ", ")))
		}
	}
	return w
}

// caTemplate builds the certificate of a CA generation (pki-rules.md §3).
func caTemplate(plan *caPlan, pub crypto.PublicKey, serialRand func() (*x509.Certificate, error)) (*x509.Certificate, error) {
	tmpl, err := serialRand()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	tmpl.Subject = plan.subject
	tmpl.RawSubject = plan.rawSubject
	tmpl.NotBefore, tmpl.NotAfter = plan.v.notBefore, plan.v.notAfter
	tmpl.IsCA, tmpl.BasicConstraintsValid = true, true // crypto/x509 writes basicConstraints critical
	tmpl.SubjectKeyId = ski
	if plan.kind == KindRoot {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.MaxPathLen = -1
		return tmpl, nil
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl.MaxPathLen, tmpl.MaxPathLenZero = plan.pathLen, plan.pathLen == 0
	plan.nc.apply(tmpl)
	applyEKU(tmpl, plan.ekuLimit)
	p := plan.parent
	tmpl.IssuingCertificateURL = []string{CertURL(p.ca.PublicBaseUrl, p.ca.Name, p.gen.Generation)}
	tmpl.CRLDistributionPoints = []string{CRLURL(p.ca.PublicBaseUrl, p.ca.Name, p.gen.Generation)}
	return tmpl, nil
}

// signAndStore generates the key, signs (or creates the CSR for the offline
// flow) and stores everything with the audit event in one transaction.
func (e *Engine) signAndStore(ctx context.Context, now time.Time, plan *caPlan, who keys.Who) (*CAResult, error) {
	offline := plan.parent != nil && plan.parent.ca.KeyMode == KeyModeOffline
	if !offline && e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	priv, err := generateKey(plan.alg, e.rand())
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err = checkKeyNotBlocked(ctx, pkidb.New(e.PKI), priv.Public()); err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer clear(pkcs8)

	gen := pkidb.InsertCAGenerationParams{CaID: plan.caID, Generation: plan.generation, KeyAlgorithm: plan.alg, CreatedAt: now.Format(audit.TimeFormat)}
	if plan.parent != nil {
		gen.IssuerCaID = sql.NullString{String: plan.parent.ca.ID, Valid: true}
		gen.IssuerGeneration = sql.NullInt64{Int64: plan.parent.gen.Generation, Valid: true}
	}
	var cert *x509.Certificate
	var bundle *OfflineBundle
	if offline {
		var csr []byte
		if csr, err = x509.CreateCertificateRequest(e.rand(), &x509.CertificateRequest{Subject: plan.subject, RawSubject: plan.rawSubject}, priv); err != nil {
			return nil, fmt.Errorf("create CSR: %w", err)
		}
		var parsed *x509.CertificateRequest
		if parsed, err = x509.ParseCertificateRequest(csr); err != nil {
			return nil, err
		}
		gen.CsrDer, gen.SubjectDn = csr, parsed.Subject.String()
		if bundle, err = e.offlineBundle(plan, csr); err != nil {
			return nil, err
		}
	} else {
		var tmpl *x509.Certificate
		if tmpl, err = caTemplate(plan, priv.Public(), e.serialTemplate); err != nil {
			return nil, err
		}
		if cert, err = e.signCA(ctx, plan, tmpl, priv); err != nil {
			return nil, err
		}
		fillGeneration(&gen, cert)
	}

	keyID, err := ids.New("key", now, nil)
	if err != nil {
		return nil, err
	}
	gen.KeyID = sql.NullString{String: keyID, Valid: true}
	env, err := e.Keys.EncryptKey(keyID, keys.PurposeCA, plan.alg, pkcs8)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}

	out := &CAResult{ID: plan.caID, Name: plan.name, Status: StatusActive, Generation: plan.generation, Offline: bundle,
		Notes: append(plan.notes, plan.v.notes...), Warnings: plan.warnings}
	if plan.newCA != nil {
		out.Status = plan.newCA.Status
	}
	details := map[string]any{
		"name": plan.name, "kind": plan.kind, "generation": plan.generation, "key_algorithm": plan.alg,
		"subject": gen.SubjectDn, "validity_days": plan.v.days,
	}
	if plan.parent != nil {
		details["parent"] = plan.parent.ca.Name
		details["parent_generation"] = plan.parent.gen.Generation
	}
	if len(plan.nc.rows) > 0 {
		details["name_constraints"] = ncStrings(plan.nc.rows)
	}
	if len(plan.ekuLimit) > 0 {
		details["eku_limit"] = oidStrings(plan.ekuLimit)
	}
	if cert != nil {
		out.CertDER, out.Fingerprint = cert.Raw, gen.FingerprintSha256.String
		details["serial"], details["fingerprint"] = gen.SerialHex.String, out.Fingerprint
		details["not_after"] = gen.NotAfter.String
	}
	if len(out.Warnings) > 0 {
		details["warnings"] = out.Warnings
	}

	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := keys.SaveKey(ctx, tx, keys.StoredKey{ID: keyID, Purpose: keys.PurposeCA, Algorithm: plan.alg, Envelope: env}, gen.CreatedAt); terr != nil {
			return terr
		}
		if plan.newCA != nil {
			if terr := q.InsertCA(ctx, *plan.newCA); terr != nil {
				return terr
			}
			for _, r := range plan.nc.rows {
				if terr := q.InsertNameConstraint(ctx, pkidb.InsertNameConstraintParams{CaID: plan.caID, Kind: r.kind, Value: r.value, Permitted: boolInt(r.permitted)}); terr != nil {
					return terr
				}
			}
		}
		if cert != nil && plan.parent != nil {
			if terr := checkSerialFree(ctx, q, plan.parent.ca.ID, gen.SerialHex.String); terr != nil {
				return terr
			}
		}
		if terr := q.InsertCAGeneration(ctx, gen); terr != nil {
			return terr
		}
		if cert != nil {
			if terr := q.SetCurrentGeneration(ctx, pkidb.SetCurrentGenerationParams{
				CurrentGeneration: sql.NullInt64{Int64: plan.generation, Valid: true}, UpdatedAt: gen.CreatedAt, ID: plan.caID,
			}); terr != nil {
				return terr
			}
		}
		if terr := audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: plan.action, Target: audit.Target{Type: "ca", ID: plan.caID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
		}); terr != nil || cert == nil {
			return terr
		}
		// The first CRL of the new generation, in the same transaction:
		// relying parties that check revocation strictly refuse every
		// certificate below a CA whose CRL URL answers 404.
		var terr error
		out.CRL, terr = e.writeCRL(ctx, q, tx, plan.caID, plan.generation, cert, func(fn func(crypto.Signer) error) error { return fn(priv) }, plan.action, who, now)
		return terr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// serialTemplate starts a certificate template with a fresh serial.
func (e *Engine) serialTemplate() (*x509.Certificate, error) {
	serial, err := newSerial(e.rand())
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{SerialNumber: serial}, nil
}

// signCA signs a CA certificate: a root with its own new key, an
// intermediate with the parent's key; the result is checked before storing.
func (e *Engine) signCA(ctx context.Context, plan *caPlan, tmpl *x509.Certificate, priv crypto.Signer) (*x509.Certificate, error) {
	var der []byte
	var err error
	if plan.parent == nil {
		if tmpl.SignatureAlgorithm, err = signatureAlgorithm(priv.Public()); err != nil {
			return nil, err
		}
		der, err = x509.CreateCertificate(e.rand(), tmpl, tmpl, priv.Public(), priv)
	} else {
		p := plan.parent
		if tmpl.SignatureAlgorithm, err = signatureAlgorithm(p.cert().PublicKey); err != nil {
			return nil, err
		}
		is := &issuer{ca: p.ca, gen: p.gen, certs: p.certs}
		der, err = e.sign(ctx, is, tmpl, priv.Public())
	}
	if err != nil {
		return nil, fmt.Errorf("sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	if plan.parent != nil {
		chain = plan.parent.certs
	}
	if err := verifyCAChain(cert, chain, e.now()); err != nil {
		return nil, err
	}
	return cert, nil
}

// verifyCAChain checks a CA certificate against its parent chain (or itself
// for a root) with crypto/x509 – including path length and constraints.
func verifyCAChain(cert *x509.Certificate, parents []*x509.Certificate, now time.Time) error {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	if len(parents) == 0 {
		roots.AddCert(cert)
	} else {
		roots.AddCert(parents[len(parents)-1])
		for _, c := range parents[:len(parents)-1] {
			inter.AddCert(c)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("CA certificate doesn't verify against its chain: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return errors.New("CA certificate is not marked CA:TRUE")
	}
	return nil
}

// fillGeneration copies the certificate facts into a generation row.
func fillGeneration(gen *pkidb.InsertCAGenerationParams, cert *x509.Certificate) {
	gen.SubjectDn = cert.Subject.String()
	gen.SerialHex = sql.NullString{String: SerialHex(cert.SerialNumber), Valid: true}
	gen.NotBefore = sql.NullString{String: cert.NotBefore.UTC().Format(dbTime), Valid: true}
	gen.NotAfter = sql.NullString{String: cert.NotAfter.UTC().Format(dbTime), Valid: true}
	gen.CertDer = cert.Raw
	gen.FingerprintSha256 = sql.NullString{String: fingerprintHex(cert.Raw), Valid: true}
	gen.SkiHex = sql.NullString{String: strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId)), Valid: true}
}

func ncStrings(rows []constraint) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		mode := "excluded"
		if r.permitted {
			mode = "permitted"
		}
		out[i] = mode + " " + r.kind + " " + r.value
	}
	return out
}

// inTx runs fn in one pki.db transaction and wakes the deliverer afterwards.
func (e *Engine) inTx(ctx context.Context, fn func(q *pkidb.Queries, tx *sql.Tx) error) error {
	tx, err := e.PKI.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(pkidb.New(tx), tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if e.Wake != nil {
		e.Wake()
	}
	return nil
}

// finish audits a refusal of a lifecycle action and passes the result on.
func (e *Engine) finish(ctx context.Context, now time.Time, action string, who keys.Who, name string, out *CAResult, err error) (*CAResult, error) {
	if err == nil {
		return out, nil
	}
	if aerr := e.refuse(ctx, now, action, who, audit.Target{Type: "ca", ID: short(name)}, map[string]any{"name": short(name)}, err); aerr != nil {
		return nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
	}
	return nil, err
}

// ImportRoot imports an offline root certificate. For a new name it creates
// the CA; for an existing offline root it adds the next generation – the
// renewal of an offline root with a new key.
func (e *Engine) ImportRoot(ctx context.Context, req ImportRootRequest) (*CAResult, error) {
	now := e.now()
	out, err := e.importRoot(ctx, req, now)
	return e.finish(ctx, now, ActionCAImportRoot, req.Who, req.Name, out, err)
}

func (e *Engine) importRoot(ctx context.Context, req ImportRootRequest, now time.Time) (*CAResult, error) {
	if err := e.authorize(req.Who, authz.ManageCA, "", now); err != nil {
		return nil, err
	}
	cert, err := parseOneCertificate(req.CertPEM)
	if err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	var reasons, warnings []string
	switch {
	case !bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignatureFrom(cert) != nil:
		reasons = append(reasons, "the certificate is not self-signed – a root signs its own certificate")
	case !acceptedSignature(cert.SignatureAlgorithm):
		reasons = append(reasons, fmt.Sprintf("the certificate is signed with %v – only SHA-2 (RSA, ECDSA) and Ed25519 signatures are accepted; SHA-1 and MD5 can be forged", cert.SignatureAlgorithm))
	}
	reasons = append(reasons, checkCACertBasics(cert, now)...)
	if berr := checkKeyNotBlocked(ctx, q, cert.PublicKey); berr != nil {
		reasons = append(reasons, berr.Error())
	}
	if alg, kerr := keyAlgorithm(cert.PublicKey); kerr != nil {
		reasons = append(reasons, kerr.Error())
	} else if w, werr := importedCAKey(alg); werr != nil {
		reasons = append(reasons, werr.Error())
	} else {
		warnings = append(warnings, w...)
	}

	existing, err := q.GetCAByName(ctx, req.Name)
	isNew := errors.Is(err, sql.ErrNoRows)
	if err != nil && !isNew {
		return nil, err
	}
	plan := &caPlan{name: req.Name, kind: KindRoot, generation: 1}
	if isNew {
		reasons = append(reasons, e.checkNewCA(ctx, q, &plan.newCA, req.CASettings, KindRoot, KeyModeOffline, DefaultCRLDaysOfflineRoot, plan)...)
		reasons = append(reasons, checkSubjectFree(ctx, q, cert.Subject.String(), "")...)
		if plan.newCA != nil {
			plan.caID = plan.newCA.ID
		}
	} else {
		plan.caID = existing.ID
		r, rerr := e.checkRootRenewal(ctx, q, existing, cert)
		if rerr != nil {
			return nil, rerr
		}
		reasons = append(reasons, r...)
		if plan.generation, err = q.MaxGeneration(ctx, existing.ID); err != nil {
			return nil, err
		}
		plan.generation++
	}
	if len(reasons) > 0 {
		return nil, &DeniedError{Reasons: reasons}
	}

	gen := pkidb.InsertCAGenerationParams{CaID: plan.caID, Generation: plan.generation, CreatedAt: now.Format(audit.TimeFormat)}
	gen.KeyAlgorithm, _ = keyAlgorithm(cert.PublicKey)
	fillGeneration(&gen, cert)
	out := &CAResult{ID: plan.caID, Name: req.Name, Status: StatusActive, Generation: plan.generation, CertDER: cert.Raw,
		Fingerprint: gen.FingerprintSha256.String, Warnings: append(plan.warnings, warnings...)}
	out.Notes = append(out.Notes, "compare the SHA-256 fingerprint "+out.Fingerprint+" with the one shown by the offline root – this import decides what the server trusts")
	if !isNew {
		out.Warnings = append(out.Warnings, "a renewed root is a new trust anchor: distribute it to every trust store before certificates below it are used")
	}
	details := map[string]any{
		"name": req.Name, "kind": KindRoot, "generation": plan.generation, "key_algorithm": gen.KeyAlgorithm,
		"subject": gen.SubjectDn, "serial": gen.SerialHex.String, "fingerprint": out.Fingerprint, "not_after": gen.NotAfter.String,
	}
	if len(out.Warnings) > 0 {
		details["warnings"] = out.Warnings
	}
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if plan.newCA != nil {
			if terr := q.InsertCA(ctx, *plan.newCA); terr != nil {
				return terr
			}
		}
		if terr := q.InsertCAGeneration(ctx, gen); terr != nil {
			return terr
		}
		if terr := q.SetCurrentGeneration(ctx, pkidb.SetCurrentGenerationParams{
			CurrentGeneration: sql.NullInt64{Int64: plan.generation, Valid: true}, UpdatedAt: gen.CreatedAt, ID: plan.caID,
		}); terr != nil {
			return terr
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: req.Who.Actor, Action: ActionCAImportRoot, Target: audit.Target{Type: "ca", ID: plan.caID},
			Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// checkRootRenewal: a new generation of an offline root keeps the subject
// and brings a new key (phase 1 renews only with a new key).
func (e *Engine) checkRootRenewal(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, cert *x509.Certificate) ([]string, error) {
	if ca.Kind != KindRoot || ca.KeyMode != KeyModeOffline {
		return []string{fmt.Sprintf("a CA named %q exists already and is not an offline root – CA names are unique", ca.Name)}, nil
	}
	if ca.Status != StatusActive {
		return []string{fmt.Sprintf("CA %q is %s", ca.Name, ca.Status)}, nil
	}
	gens, err := q.ListCAGenerations(ctx, ca.ID)
	if err != nil {
		return nil, err
	}
	var reasons []string
	for _, g := range gens {
		// An unreadable generation is a database problem, not a normal case.
		old, perr := x509.ParseCertificate(g.CertDer)
		if perr != nil {
			return nil, fmt.Errorf("CA %q generation %d: stored certificate can't be read: %w", ca.Name, g.Generation, perr)
		}
		// Compared by content: another tool may encode the same name differently.
		if old.Subject.String() != cert.Subject.String() {
			reasons = append(reasons, fmt.Sprintf("the subject differs from generation %d (%s) – a renewed root keeps its name", g.Generation, old.Subject))
			break
		}
		if publicKeyEqual(old.PublicKey, cert.PublicKey) {
			reasons = append(reasons, fmt.Sprintf("the key is the one of generation %d – renewing with the same key is not supported (phase 1 renews with a new key only)", g.Generation))
			break
		}
	}
	return reasons, nil
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// checkCACertBasics: what every CA certificate needs.
func checkCACertBasics(cert *x509.Certificate, now time.Time) []string {
	var reasons []string
	bc, _ := findExtension(cert, oidBasicConstraints)
	ku, _ := findExtension(cert, oidKeyUsageExt)
	switch {
	case !cert.IsCA || !cert.BasicConstraintsValid || !bc.Critical:
		reasons = append(reasons, "basicConstraints must be critical CA:TRUE")
	case cert.KeyUsage&x509.KeyUsageCertSign == 0 || !ku.Critical:
		reasons = append(reasons, "keyUsage must be critical and contain keyCertSign")
	}
	if len(cert.SubjectKeyId) == 0 {
		reasons = append(reasons, "the certificate has no subject key identifier (RFC 5280 requires it for CA certificates; certificates below it would lack the authority key identifier)")
	}
	if len(cert.UnhandledCriticalExtensions) > 0 {
		reasons = append(reasons, fmt.Sprintf("unknown critical extensions: %v", cert.UnhandledCriticalExtensions))
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		reasons = append(reasons, fmt.Sprintf("the certificate is not valid now (valid from %s to %s)", cert.NotBefore.Format(time.DateOnly), cert.NotAfter.Format(time.DateOnly)))
	}
	return reasons
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsageExt      = asn1.ObjectIdentifier{2, 5, 29, 15}
)

func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

// MaxCertSize limits an uploaded certificate.
const MaxCertSize = 64 << 10

// parseOneCertificate reads exactly one PEM certificate.
func parseOneCertificate(data []byte) (*x509.Certificate, error) {
	if len(data) > MaxCertSize {
		return nil, deny("the certificate file is larger than %d KiB", MaxCertSize>>10)
	}
	block, rest := pem.Decode(data)
	switch {
	case block == nil:
		return nil, deny("no PEM block found – expected -----BEGIN CERTIFICATE-----")
	case block.Type != "CERTIFICATE":
		return nil, deny("PEM block %q is not a certificate", short(block.Type))
	case len(block.Headers) > 0:
		return nil, deny("the PEM block has headers – send a plain PEM certificate")
	case len(bytes.TrimSpace(rest)) > 0:
		return nil, deny("there is data after the certificate – send exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, deny("the certificate can't be parsed: %v", err)
	}
	return cert, nil
}

func fingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
