package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Import of a legacy/pki.sh directory (PHASE1 step 15). internal/ca/legacy
// reads the files; this checks everything and writes it in one pki.db
// transaction – the whole PKI or nothing. Serials, revocations (time and
// reason) and CRL numbers stay as pki.sh left them; an online CA signs its
// next CRL in the same transaction, so the numbering continues exactly.

// Audit actions of the import.
const (
	ActionCAImportLegacy = "ca.import_legacy"
	ActionImportLegacy   = "import.legacy"
)

// legacyActor marks rows that pki.sh made (requested_by, revoked_by); who
// imported them is in the audit log.
const legacyActor = "pki.sh"

// LegacyImportRequest imports a directory read by legacy.Read.
type LegacyImportRequest struct {
	PKI *legacy.PKI
	// BaseURL for the AIA/CRL URLs of new certificates; "" = AIA_BASE_URL of
	// pki.conf. With the pki.sh URL, <base>/<name>.crt|.crl stay served.
	BaseURL string
	// RootOnline imports the root key encrypted (default: an offline root –
	// pki.sh stays the offline root tool).
	RootOnline bool
	// DryRun checks everything and writes nothing.
	DryRun bool
	Who    keys.Who
}

// LegacyImportReport is what was (or, in a dry run, would be) imported.
type LegacyImportReport struct {
	DryRun       bool              `json:"dry_run"`
	Imported     bool              `json:"imported"`
	BaseURL      string            `json:"base_url"`
	LegacyURLs   bool              `json:"legacy_urls"`
	CAs          []LegacyCAReport  `json:"cas"`
	Certificates int               `json:"certificates"`
	Revoked      int               `json:"revoked"`
	Keys         int               `json:"keys"`
	External     int               `json:"external"`
	Warnings     []string          `json:"warnings"`
	Problems     []string          `json:"problems"`
	CRLs         []CRLResult       `json:"-"`
	caIDs        map[string]string // name -> ID
}

// LegacyCAReport describes one CA of the import.
type LegacyCAReport struct {
	Name, Kind, KeyMode, Status string
	ID                          string `json:"id,omitempty"`
	Subject, Fingerprint        string
	Certificates, Revoked       int
	// LastCRLNumber is the newest number pki.sh used; the next CRL gets +1.
	LastCRLNumber int64
	History       int // older certificates of the same key
}

// ImportLegacy checks and imports a pki.sh directory. Problems refuse the
// whole import (a DeniedError listing them); the report always comes back.
func (e *Engine) ImportLegacy(ctx context.Context, req LegacyImportRequest) (*LegacyImportReport, error) {
	now := e.now()
	rep, err := e.importLegacy(ctx, req, now)
	if err != nil && !req.DryRun {
		if aerr := e.refuse(ctx, now, ActionImportLegacy, req.Who, audit.Target{Type: "import", ID: "legacy"}, map[string]any{"problems": len(rep.Problems)}, err); aerr != nil {
			err = errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
	}
	return rep, err
}

// legacyCA is one CA of the plan.
type legacyCA struct {
	src     *legacy.CA
	row     *pkidb.InsertCAParams
	gen     pkidb.InsertCAGenerationParams
	nc      checkedNC
	online  bool
	key     crypto.Signer
	history []*x509.Certificate
	revoked *legacyRevocation // revoked by the root
	lastCRL int64
	crl     *x509.RevocationList // pki.sh's current CRL, signature checked
	rep     *LegacyCAReport
}

type legacyRevocation struct {
	reason     string
	at         time.Time
	invalidity *time.Time
}

// legacyCert is one certificate of the plan.
type legacyCert struct {
	ca      *legacyCA // nil: external (self-signed)
	cert    *x509.Certificate
	preset  string
	keyHash string // of a key that is imported with it
	rev     *legacyRevocation
	custom  [2]string
}

type legacyPlan struct {
	pki      *legacy.PKI
	rep      *LegacyImportReport
	cas      []*legacyCA
	certs    []*legacyCert
	leafKeys map[string]crypto.Signer // by key hash, only those used
	now      time.Time
}

func (p *legacyPlan) problem(format string, a ...any) {
	p.rep.Problems = append(p.rep.Problems, fmt.Sprintf(format, a...))
}

func (p *legacyPlan) warn(format string, a ...any) {
	p.rep.Warnings = append(p.rep.Warnings, fmt.Sprintf(format, a...))
}

func (e *Engine) importLegacy(ctx context.Context, req LegacyImportRequest, now time.Time) (*LegacyImportReport, error) {
	rep := &LegacyImportReport{DryRun: req.DryRun, Warnings: []string{}, Problems: []string{}, CAs: []LegacyCAReport{}, caIDs: map[string]string{}}
	if err := e.authorize(req.Who, authz.ManageCA, "", now); err != nil {
		return rep, err
	}
	src := req.PKI
	rep.Problems = append(rep.Problems, src.Problems...)
	rep.Warnings = append(rep.Warnings, src.Warnings...)
	p := &legacyPlan{pki: src, rep: rep, leafKeys: map[string]crypto.Signer{}, now: now}
	q := pkidb.New(e.PKI)

	rep.BaseURL = strings.TrimRight(req.BaseURL, "/")
	if rep.BaseURL == "" {
		rep.BaseURL = src.Config.BaseURL
	}
	switch {
	case rep.BaseURL == "":
		p.problem("pki.conf has no AIA_BASE_URL – give the public base URL of this server (--base-url); it goes into every new certificate")
	case src.Config.BaseURL == "":
		p.warn("the certificates of pki.sh have no CRL distribution point or AIA (AIA_BASE_URL was empty) – clients can't check their revocation; new certificates use %s", rep.BaseURL)
	case src.Config.BaseURL == rep.BaseURL:
		rep.LegacyURLs = true
	default:
		p.warn("the certificates of pki.sh point to %s/<name>.crl and .crt; new ones use %s – keep the old URLs answering (DNS or a redirect to this server), or clients can't check the old certificates", src.Config.BaseURL, rep.BaseURL)
	}

	if !req.DryRun && e.Keys.Status().Sealed {
		return rep, keys.ErrSealed
	}
	if src.Root.Cert != nil {
		root := e.planLegacyCA(ctx, q, p, src.Root, nil, req)
		for _, c := range src.Intermediates {
			if c.Cert != nil {
				e.planLegacyCA(ctx, q, p, c, root, req)
			}
		}
		e.planLegacyCerts(ctx, q, p)
	}
	for _, c := range p.cas {
		rep.CAs = append(rep.CAs, *c.rep)
	}
	if len(rep.Problems) > 0 {
		return rep, &DeniedError{Reasons: capReasons(rep.Problems)}
	}
	if req.DryRun {
		return rep, nil
	}
	if err := e.writeLegacy(ctx, p, req.Who); err != nil {
		return rep, err
	}
	rep.Imported = true
	if e.Wake != nil {
		e.Wake()
	}
	return rep, nil
}

// planLegacyCA checks one CA and adds it to the plan.
func (e *Engine) planLegacyCA(ctx context.Context, q *pkidb.Queries, p *legacyPlan, src *legacy.CA, root *legacyCA, req LegacyImportRequest) *legacyCA {
	cert := src.Cert
	kind, keyMode, crlDefault := KindIntermediate, KeyModeOnlineEncrypted, DefaultCRLDaysIntermediate
	if root == nil {
		kind, keyMode, crlDefault = KindRoot, KeyModeOffline, DefaultCRLDaysOfflineRoot
		if req.RootOnline {
			keyMode, crlDefault = KeyModeOnlineEncrypted, DefaultCRLDaysOnlineRoot
		}
	}
	c := &legacyCA{src: src, online: keyMode == KeyModeOnlineEncrypted, rep: &LegacyCAReport{
		Name: src.Name, Kind: kind, KeyMode: keyMode, Status: StatusActive, Subject: cert.Subject.String(), Fingerprint: fingerprintHex(cert.Raw),
	}}
	where := fmt.Sprintf("CA %q", src.Name)
	if p.rep.BaseURL != "" {
		crlDays := p.rep.CRLDaysOr(crlDefault, req.PKI.Config.CRLDays)
		plan := &caPlan{}
		for _, r := range e.checkNewCA(ctx, q, &c.row, CASettings{Name: src.Name, BaseURL: p.rep.BaseURL, CRLDays: crlDays}, kind, keyMode, crlDefault, plan) {
			p.problem("%s: %s", where, r)
		}
		p.rep.Warnings = append(p.rep.Warnings, plan.warnings...)
	}
	for _, r := range checkSubjectFree(ctx, q, cert.Subject.String(), "") {
		p.problem("%s: %s", where, r)
	}
	if err := checkKeyNotBlocked(ctx, q, cert.PublicKey); err != nil {
		p.problem("%s: %v", where, err)
	}

	// The certificate itself.
	switch {
	case root == nil && (!bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignatureFrom(cert) != nil):
		p.problem("%s: certs/ca.crt is not self-signed – a root signs its own certificate", where)
	case root != nil && cert.CheckSignatureFrom(root.src.Cert) != nil:
		p.problem("%s: certs/ca.crt is not signed by the root of this directory", where)
	case !acceptedSignature(cert.SignatureAlgorithm):
		p.problem("%s: the certificate is signed with %v – only SHA-2 (RSA, ECDSA) and Ed25519 are accepted; SHA-1 and MD5 can be forged", where, cert.SignatureAlgorithm)
	}
	// Validity is judged apart: an expired CA is imported as retired.
	for _, r := range checkCACertBasics(cert, cert.NotBefore) {
		p.problem("%s: %s", where, r)
	}
	switch {
	case p.now.Before(cert.NotBefore):
		p.problem("%s: the certificate is valid only from %s", where, cert.NotBefore.Format(time.DateOnly))
	case p.now.After(cert.NotAfter):
		c.rep.Status = StatusRetired
		p.warn("%s expired on %s – imported as retired: it keeps its records and CRLs, but signs nothing new", where, cert.NotAfter.Format(time.DateOnly))
	}
	alg, err := keyAlgorithm(cert.PublicKey)
	if err != nil {
		p.problem("%s: %v", where, err)
	} else if w, kerr := importedCAKey(alg); kerr != nil {
		p.problem("%s: %v", where, kerr)
	} else {
		for _, s := range w {
			p.warn("%s: %s", where, s)
		}
	}
	if c.online {
		if src.Key == nil {
			p.problem("%s: %s", where, src.KeyProblem)
		} else {
			c.key = src.Key
		}
	}

	if c.row != nil {
		c.row.Status = c.rep.Status
		c.rep.ID = c.row.ID
		p.rep.caIDs[src.Name] = c.row.ID
		c.gen = pkidb.InsertCAGenerationParams{CaID: c.row.ID, Generation: 1, KeyAlgorithm: alg, CreatedAt: p.now.Format(audit.TimeFormat)}
		fillGeneration(&c.gen, cert)
		if root != nil && root.row != nil {
			c.row.ParentID = sql.NullString{String: root.row.ID, Valid: true}
			c.gen.IssuerCaID = sql.NullString{String: root.row.ID, Valid: true}
			c.gen.IssuerGeneration = sql.NullInt64{Int64: 1, Valid: true}
			pathLen := 0
			if cert.MaxPathLen > 0 {
				pathLen = cert.MaxPathLen
			}
			c.row.PathLen = sql.NullInt64{Int64: int64(pathLen), Valid: true}
		}
		e.legacyConstraints(p, c, where)
	}

	// Older certificates of the same key (pki.sh renew-ca): history.
	seen := map[string]bool{c.rep.Fingerprint: true}
	addHistory := func(h *x509.Certificate) {
		fp := fingerprintHex(h.Raw)
		if seen[fp] || !publicKeyEqual(h.PublicKey, cert.PublicKey) || h.Subject.String() != cert.Subject.String() {
			return
		}
		seen[fp] = true
		c.history = append(c.history, h)
	}
	for _, h := range src.History {
		addHistory(h)
	}
	if root != nil {
		for _, h := range root.src.Signed {
			addHistory(h)
		}
	}
	slices.SortFunc(c.history, func(a, b *x509.Certificate) int { return a.NotBefore.Compare(b.NotBefore) })
	c.rep.History = len(c.history)

	// Revoked on the root's index (the current certificate).
	if root != nil {
		serial := SerialHex(cert.SerialNumber)
		found := false
		for _, en := range root.src.Index {
			if en.Serial != serial {
				continue
			}
			found = true
			if en.Revoked != nil {
				c.revoked = p.legacyReason(en.Revoked, true, fmt.Sprintf("%s (serial %s)", where, serial))
				if c.revoked != nil {
					p.warn("%s is revoked on the root since %s (%s) – imported with its records, it can't issue", where, en.Revoked.Time.Format(time.DateOnly), c.revoked.reason)
				}
			}
		}
		if !found {
			p.warn("%s: its certificate (serial %s) is not in the root's index.txt", where, serial)
		}
	}

	e.legacyCRL(p, c, where)
	c.rep.LastCRLNumber = c.lastCRL
	p.cas = append(p.cas, c)
	return c
}

// CRLDaysOr picks the CRL lifetime: pki.conf's CRL_DAYS, else the default.
func (r *LegacyImportReport) CRLDaysOr(def, conf int) int {
	if conf > 0 {
		return conf
	}
	return def
}

// legacyConstraints takes path length, name constraints and EKU limit from
// the certificate – what clients enforce – not from ca.meta.
func (e *Engine) legacyConstraints(p *legacyPlan, c *legacyCA, where string) {
	cert := c.src.Cert
	var nc NameConstraints
	nc.PermittedDNS, nc.ExcludedDNS = cert.PermittedDNSDomains, cert.ExcludedDNSDomains
	nc.PermittedEmail, nc.ExcludedEmail = cert.PermittedEmailAddresses, cert.ExcludedEmailAddresses
	nc.PermittedURI, nc.ExcludedURI = cert.PermittedURIDomains, cert.ExcludedURIDomains
	for _, n := range cert.PermittedIPRanges {
		nc.PermittedIP = append(nc.PermittedIP, n.String())
	}
	for _, n := range cert.ExcludedIPRanges {
		nc.ExcludedIP = append(nc.ExcludedIP, n.String())
	}
	if ext, ok := findExtension(cert, oidNameConstraints); ok {
		nc.NotCritical = !ext.Critical
		if !ext.Critical {
			p.warn("%s: its name constraints are not critical (RFC 5280 requires critical) – kept as they are", where)
		}
	}
	var problems []string
	c.nc, problems = checkNameConstraints(nc)
	for _, pr := range problems {
		p.problem("%s: %s", where, pr)
	}
	c.row.NcCritical = boolInt(c.nc.critical)
	eku, _ := certEKUs(cert)
	limit, _ := json.Marshal(oidStrings(eku))
	c.row.EkuLimit = string(limit)
}

// legacyCRL keeps the current CRL of pki.sh as evidence and sets the number
// the next CRL continues from.
func (e *Engine) legacyCRL(p *legacyPlan, c *legacyCA, where string) {
	src := c.src
	if src.NextCRLNumber > 0 {
		c.lastCRL = src.NextCRLNumber - 1
	}
	if src.CRL == nil {
		if c.online {
			p.warn("%s has no CRL in crl/ca.crl – the server signs one at the import", where)
		} else {
			p.warn("%s has no CRL in crl/ca.crl – create and upload one: pki crl --ca %s, then upload publish/%s.crl", where, src.Name, src.Name)
		}
		return
	}
	crl := src.CRL
	if err := crl.CheckSignatureFrom(src.Cert); err != nil {
		p.warn("%s: crl/ca.crl is not signed by this CA (%v) – not kept", where, err)
		return
	}
	if crl.Number == nil || crl.Number.Sign() <= 0 || !crl.Number.IsInt64() {
		p.warn("%s: crl/ca.crl has no usable CRL number – not kept", where)
		return
	}
	n := crl.Number.Int64()
	if src.NextCRLNumber > 0 && n >= src.NextCRLNumber {
		p.problem("%s: crl/ca.crl has number %d, but crlnumber says the next is %d – the files don't fit together", where, n, src.NextCRLNumber)
		return
	}
	c.lastCRL = max(c.lastCRL, n)
	c.crl = crl
	if !p.now.Before(crl.NextUpdate) && !c.online {
		p.warn("%s: its CRL expired on %s – clients that check revocation refuse the chain until a new one is uploaded (pki crl --ca %s)", where, crl.NextUpdate.Format(time.DateOnly), src.Name)
	}
}

// legacyReason maps an OpenSSL revocation to the reasons MyOwnPKI keeps;
// nil when the entry isn't a revocation any more (removeFromCRL).
func (p *legacyPlan) legacyReason(r *legacy.Revocation, isCA bool, what string) *legacyRevocation {
	out := &legacyRevocation{at: r.Time, invalidity: r.Invalidity, reason: r.Reason}
	switch r.Reason {
	case "":
		out.reason = "unspecified"
	case "CACompromise":
		out.reason = "cACompromise"
		if !isCA {
			out.reason = "keyCompromise"
			p.warn("%s: revoked as CACompromise, which an end-entity certificate can't have – kept as keyCompromise", what)
		}
	case "certificateHold":
		out.reason = "unspecified"
		p.warn("%s: certificateHold is not supported – for MyOwnPKI this certificate is revoked for good (recorded as unspecified)", what)
	case "removeFromCRL":
		p.warn("%s: marked removeFromCRL – treated as not revoked", what)
		return nil
	}
	if out.invalidity != nil && out.reason != "keyCompromise" && out.reason != "cACompromise" {
		out.invalidity = nil
	}
	return out
}
