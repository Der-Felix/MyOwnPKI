// Package ca is the CA engine: it issues end-entity certificates from a
// preset, after checking everything a request contains (PHASE1 step 7).
//
// Order of an issuance – every check runs before anything is signed:
//
//  1. preset and CA (active, key online, unsealed, CA certificates valid now)
//  2. key: verify the CSR's signature and apply the key policy, or generate
//     the key on the server if the tenant allows it
//  3. names: the CSR's names are only a wish list; every name is checked,
//     the preset's SAN rules apply, then the name constraints and EKU limits
//     of every CA up to the root
//  4. validity: explicit requests are accepted or denied, defaults adapt
//  5. build from the preset (never from the CSR), sign, check the result
//     against the chain, store certificate, names, key and audit event in
//     one pki.db transaction
//
// Refused requests are written to the tenant audit log as denied (policy)
// or failure (sealed, internal error).
package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// ActionIssue is the audit action of an issuance, allowed or not.
const ActionIssue = "certificate.issue"

// Engine issues certificates for one tenant.
type Engine struct {
	PKI     *sql.DB // writer of tenants/<t>/pki.db
	Audit   *sql.DB // writer of tenants/<t>/audit.db: refused requests are logged directly
	Scope   string  // audit scope of Audit, store.TenantScope(tenant)
	Keys    *keys.Keyring
	Presets *preset.Set
	Clock   clock.Clock
	// ServerKeygen reports the tenant switch allow_server_keygen (system.db).
	// It is asked per request, so a change applies at once.
	ServerKeygen func(context.Context) (bool, error)
	// Wake, if set, is called after a commit with an outbox row.
	Wake func()
	// Rand is the randomness for serials and keys; nil = crypto/rand.
	Rand io.Reader
}

// Request is one certificate request. Every field is untrusted input.
type Request struct {
	CA     string
	Preset string
	// CSR is a PEM certificate request. nil = generate the key on the server.
	CSR []byte
	// KeyAlgorithm for server-side generation; "" = DefaultKeyAlgorithm.
	KeyAlgorithm string

	DNSNames, IPAddresses, EmailAddresses, URIs []string
	// IgnoreCSRNames uses only the names given here and ignores the CSR's
	// names and subject (legacy --no-csr-san).
	IgnoreCSRNames bool
	Subject        Subject

	ValidityDays int // 0 = the preset's default
	// CustomKeyUsage and CustomExtKeyUsage: only for customizable presets.
	CustomKeyUsage, CustomExtKeyUsage []string
	RenewalOf                         string // certificate ID, optional
	Who                               keys.Who
}

// Issued is a stored certificate.
type Issued struct {
	ID           string
	SerialHex    string
	Fingerprint  string // SHA-256, upper-case hex
	CertDER      []byte
	Chain        [][]byte // issuing CA first, root last
	KeyID        string   // server-generated key; "" for a CSR
	KeyAlgorithm string
	NotBefore    time.Time
	NotAfter     time.Time
	// Notes say what a default changed (validity shortened, base domain added).
	Notes []string
	// DroppedCSRNames are names from the CSR the preset doesn't take, as
	// "type:value" – shown to the requester and written to the audit log.
	DroppedCSRNames []string
	// Warnings are compatibility problems that didn't stop the issuance.
	Warnings []string
}

const dbTime = "2006-01-02T15:04:05Z" // certificate times have whole seconds

// Issue checks req, signs and stores the certificate. A *DeniedError
// (errors.Is ErrDenied) lists what the requester or an admin must change.
func (e *Engine) Issue(ctx context.Context, req Request) (*Issued, error) {
	now := e.Clock.Now().UTC().Truncate(time.Second)
	out, err := e.issue(ctx, req, now)
	if err != nil {
		if aerr := e.logRefusal(ctx, req, now, err); aerr != nil {
			return nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
		return nil, err
	}
	return out, nil
}

func (e *Engine) rand() io.Reader {
	if e.Rand != nil {
		return e.Rand
	}
	return rand.Reader
}

func (e *Engine) issue(ctx context.Context, req Request, now time.Time) (*Issued, error) {
	p, ok := e.Presets.Get(req.Preset)
	if !ok {
		return nil, deny("there is no preset named %q", short(req.Preset))
	}
	q := pkidb.New(e.PKI)
	is, err := loadIssuer(ctx, q, req.CA)
	if err != nil {
		return nil, err
	}
	if e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	for i, c := range is.certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, deny("the certificate of CA %q is not valid now (valid from %s to %s)",
				is.constraints[i].ca, c.NotBefore.Format(time.DateOnly), c.NotAfter.Format(time.DateOnly))
		}
	}

	// Key: from the CSR, or generated here.
	var csr *x509.CertificateRequest
	l := leaf{}
	if req.CSR != nil {
		if req.KeyAlgorithm != "" {
			return nil, deny("a key algorithm is only chosen for server-side key generation – a CSR brings its own key")
		}
		if csr, err = parseCSR(req.CSR); err != nil {
			return nil, err
		}
		if l.alg, err = keyAlgorithm(csr.PublicKey); err != nil {
			return nil, deny("%v", err)
		}
		l.pub = csr.PublicKey
	} else {
		allowed, kerr := e.ServerKeygen(ctx)
		if kerr != nil {
			return nil, fmt.Errorf("tenant setting: %w", kerr)
		}
		if !allowed {
			return nil, deny("server-side key generation is switched off for this tenant – send a CSR")
		}
		l.alg = req.KeyAlgorithm
		if l.alg == "" {
			l.alg = DefaultKeyAlgorithm
		}
		if !slices.Contains(GeneratedAlgorithms, l.alg) {
			return nil, deny("key algorithm %q can't be generated (allowed: %s)", short(l.alg), strings.Join(GeneratedAlgorithms, ", "))
		}
	}
	if l.preset, err = customize(p, req, l.alg); err != nil {
		return nil, err
	}

	// Names, constraints, limits, validity – all problems at once.
	rq := subjectAndNames(l.preset, req, csr)
	l.subject, l.names = rq.subject, rq.names
	notes, reasons := rq.notes, rq.problems
	reasons = append(reasons, checkConstraints(is.constraints, l.names, cnHost(l.subject.CommonName, l.names))...)
	reasons = append(reasons, checkEKULimit(is.constraints, l.preset.ExtKeyUsageOIDs())...)
	l.v = computeValidity(now, req.ValidityDays, l.preset.ValidityDays, int(is.ca.MaxValidityDays), is.certs[0].NotBefore, is.certs[0].NotAfter)
	if l.v.problem != "" {
		reasons = append(reasons, l.v.problem)
	}
	if req.RenewalOf != "" {
		if _, gerr := q.GetCertificate(ctx, req.RenewalOf); errors.Is(gerr, sql.ErrNoRows) {
			reasons = append(reasons, fmt.Sprintf("certificate %q to renew doesn't exist", short(req.RenewalOf)))
		} else if gerr != nil {
			return nil, gerr
		}
	}
	if len(reasons) > 0 {
		return nil, &DeniedError{Reasons: reasons, DroppedCSRNames: rq.dropped}
	}
	notes = append(notes, l.v.notes...)

	// From here on nothing is the requester's fault: errors are failures.
	var pkcs8 []byte
	if csr == nil {
		var priv crypto.Signer
		if priv, err = generateKey(l.alg, e.rand()); err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		l.pub = priv.Public()
		if pkcs8, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		defer clear(pkcs8)
	}
	tmpl, err := buildTemplate(is, l, e.rand())
	if err != nil {
		return nil, err
	}
	der, err := e.sign(ctx, is, tmpl, l.pub)
	if err != nil {
		return nil, err
	}
	cert, err := checkIssued(der, l, is, now)
	if err != nil {
		return nil, err
	}
	return e.store(ctx, req, now, is, l, cert, pkcs8, notes, rq.dropped)
}

// customize applies custom key usages for customizable presets.
func customize(p *preset.Preset, req Request, alg string) (*preset.Preset, error) {
	if len(req.CustomKeyUsage) == 0 && len(req.CustomExtKeyUsage) == 0 {
		return p, nil
	}
	if !p.Customizable {
		return nil, deny("preset %q has fixed key usages – custom usages need a customizable preset", p.Name)
	}
	if !isRSA(alg) {
		for _, ku := range req.CustomKeyUsage {
			if preset.RSAOnlyKeyUsage(ku) {
				return nil, deny("key usage %q needs an RSA key – a %s key can only sign", short(ku), alg)
			}
		}
	}
	c, err := p.Customize(req.CustomKeyUsage, req.CustomExtKeyUsage)
	if err != nil {
		return nil, deny("%v", err)
	}
	return c, nil
}

// requested are the subject and names after merging request and CSR.
type requested struct {
	subject pkix.Name
	names   Names
	notes   []string
	// dropped lists the CSR names the preset doesn't take ("ip:10.0.0.1").
	// Both the caller and the audit log get them (owner 2026-10-13).
	dropped  []string
	problems []string
}

// subjectAndNames merges request and CSR and applies the preset's name rules.
func subjectAndNames(p *preset.Preset, req Request, csr *x509.CertificateRequest) requested {
	var r requested
	var notes, problems []string
	in := nameInput{
		DNS: slices.Clone(req.DNSNames), IPs: slices.Clone(req.IPAddresses),
		Emails: slices.Clone(req.EmailAddresses), URIs: slices.Clone(req.URIs),
	}
	want := req.Subject
	if csr != nil && !req.IgnoreCSRNames {
		// The CSR's names are a wish list: types the preset doesn't take are
		// dropped and reported, the rest is checked like explicit names.
		// (ACME will differ: there the CSR must match the order exactly.)
		var ips, uris []string
		for _, ip := range csr.IPAddresses {
			ips = append(ips, ip.String())
		}
		for _, u := range csr.URIs {
			uris = append(uris, u.String())
		}
		take := func(t preset.SANType, names []string, dst *[]string) {
			if slices.Contains(p.SubjectAltNames.Offered, t) {
				*dst = append(*dst, names...)
				return
			}
			for _, n := range names {
				r.dropped = append(r.dropped, string(t)+":"+short(n))
			}
			if len(names) > 0 {
				notes = append(notes, fmt.Sprintf("ignored %d %s name(s) from the CSR – preset %q doesn't take them", len(names), t, p.Name))
			}
		}
		take(preset.SANDNS, csr.DNSNames, &in.DNS)
		take(preset.SANIP, ips, &in.IPs)
		take(preset.SANEmail, csr.EmailAddresses, &in.Emails)
		take(preset.SANURI, uris, &in.URIs)
		want = mergeSubject(want, csrSubject(csr.Subject))
	}

	subj, sp := checkSubject(want)
	problems = append(problems, sp...)

	// A CN that is a host name (or address) also goes into the SANs, first –
	// TLS clients only look there (legacy CN_AUTO).
	cn := subj.CommonName
	switch {
	case cn == "":
	case p.CommonNameFrom == preset.SANDNS:
		if _, err := netip.ParseAddr(cn); err == nil {
			in.IPs = append([]string{cn}, in.IPs...)
		} else if _, err := checkDNSName(cn, p.Wildcard); err == nil {
			in.DNS = append([]string{cn}, in.DNS...)
		}
	case p.CommonNameFrom == preset.SANEmail:
		if _, err := checkEmail(cn); err == nil {
			in.Emails = append([]string{cn}, in.Emails...)
		}
	}

	names, np := checkNames(in, p.Wildcard)
	problems = append(problems, np...)
	if p.Wildcard {
		var bases []string
		for _, d := range names.DNS {
			if base, ok := strings.CutPrefix(d, "*."); ok && !slices.Contains(names.DNS, base) && !slices.Contains(bases, base) {
				bases = append(bases, base)
			}
		}
		if !slices.ContainsFunc(names.DNS, func(d string) bool { return strings.HasPrefix(d, "*.") }) {
			problems = append(problems, fmt.Sprintf("preset %q needs a wildcard name like *.homelab.lan", p.Name))
		}
		for _, b := range bases {
			names.DNS = append(names.DNS, b)
			notes = append(notes, fmt.Sprintf("added the base domain %s – the wildcard doesn't cover it", b))
		}
	}
	for _, t := range []preset.SANType{preset.SANDNS, preset.SANIP, preset.SANEmail, preset.SANURI} {
		if names.has(t) && !slices.Contains(p.SubjectAltNames.Offered, t) {
			problems = append(problems, fmt.Sprintf("preset %q doesn't take %s names", p.Name, t))
		}
	}
	if req := p.SubjectAltNames.RequiredAnyOf; len(req) > 0 && !slices.ContainsFunc(req, names.has) {
		problems = append(problems, fmt.Sprintf("preset %q needs at least one name of type %s", p.Name, joinTypes(req)))
	}

	// The CN: given, or derived from the first name of the preset's type.
	derived := false
	if cn == "" {
		derived = true
		switch {
		case p.CommonNameFrom == preset.SANDNS && len(names.DNS) > 0:
			cn = names.DNS[0]
		case p.CommonNameFrom == preset.SANDNS && len(names.IPs) > 0:
			cn = names.IPs[0].String()
		case p.CommonNameFrom == preset.SANEmail && len(names.Emails) > 0:
			cn = names.Emails[0]
		}
	}
	if utf8.RuneCountInString(cn) > maxCommonName {
		if derived {
			notes = append(notes, fmt.Sprintf("no common name: %q is longer than %d characters – the SANs carry the name", cn, maxCommonName))
			cn = ""
		} else {
			problems = append(problems, fmt.Sprintf("the common name is longer than %d characters (RFC 5280)", maxCommonName))
		}
	}
	if cn == "" && names.count() == 0 && len(problems) == 0 {
		problems = append(problems, "the certificate needs a common name or at least one subject alternative name")
	}

	name := pkix.Name{CommonName: cn}
	add := func(dst *[]string, v string) {
		if v != "" {
			*dst = []string{v}
		}
	}
	add(&name.Organization, subj.Organization)
	add(&name.OrganizationalUnit, subj.OrganizationalUnit)
	add(&name.Locality, subj.Locality)
	add(&name.Province, subj.Province)
	add(&name.Country, subj.Country)
	r.subject, r.names, r.notes, r.problems = name, names, notes, problems
	return r
}

// cnHost returns the CN if a client could take it for a host name: one that
// contains a dot, when the certificate has no DNS SAN. Only then do clients
// fall back to the CN (RFC 6125 §6.4.4, OpenSSL's name constraint check), so
// only then must it satisfy the DNS name constraints.
func cnHost(cn string, n Names) string {
	if len(n.DNS) > 0 || cn == "" || strings.ContainsAny(cn, " @") || !strings.Contains(cn, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(cn); err == nil {
		return ""
	}
	return strings.ToLower(cn)
}

func joinTypes(ts []preset.SANType) string {
	s := make([]string, len(ts))
	for i, t := range ts {
		s[i] = string(t)
	}
	return strings.Join(s, " or ")
}

// sign signs with the CA key; the key is decrypted only for this call.
func (e *Engine) sign(ctx context.Context, is *issuer, tmpl *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
	if !is.gen.KeyID.Valid {
		return nil, fmt.Errorf("CA %q generation %d has no key on this server", is.ca.Name, is.gen.Generation)
	}
	key, err := keys.LoadKey(ctx, e.PKI, is.gen.KeyID.String)
	if err != nil {
		return nil, fmt.Errorf("CA %q: %w", is.ca.Name, err)
	}
	if key.Purpose != keys.PurposeCA {
		return nil, fmt.Errorf("CA %q: key %s is not a CA key", is.ca.Name, key.ID)
	}
	var der []byte
	err = e.Keys.WithSigner(key.ID, key.Purpose, key.Algorithm, key.Envelope, func(s crypto.Signer) error {
		type equaler interface{ Equal(crypto.PublicKey) bool }
		if k, ok := s.Public().(equaler); !ok || !k.Equal(is.certs[0].PublicKey) {
			return fmt.Errorf("CA %q: key %s doesn't belong to the CA certificate", is.ca.Name, key.ID)
		}
		var cerr error
		der, cerr = x509.CreateCertificate(e.rand(), tmpl, is.certs[0], pub, s)
		return cerr
	})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return der, nil
}

// store writes key, certificate, names and the audit event in one pki.db
// transaction: all of it exists, or none of it.
func (e *Engine) store(ctx context.Context, req Request, now time.Time, is *issuer, l leaf, cert *x509.Certificate, pkcs8 []byte, notes, dropped []string) (*Issued, error) {
	sum := sha256.Sum256(cert.Raw)
	out := &Issued{
		SerialHex: SerialHex(cert.SerialNumber), Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])),
		CertDER: cert.Raw, KeyAlgorithm: l.alg, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		Notes: notes, DroppedCSRNames: dropped, Warnings: keyWarnings(l.alg, l.preset),
	}
	for _, c := range is.certs {
		out.Chain = append(out.Chain, c.Raw)
	}
	var err error
	if out.ID, err = ids.New("crt", now, nil); err != nil {
		return nil, err
	}
	var env keys.Envelope
	if pkcs8 != nil {
		if out.KeyID, err = ids.New("key", now, nil); err != nil {
			return nil, err
		}
		if env, err = e.Keys.EncryptKey(out.KeyID, keys.PurposeLeaf, l.alg, pkcs8); err != nil {
			return nil, fmt.Errorf("encrypt key: %w", err)
		}
	}

	created := now.Format(audit.TimeFormat)
	nullable := func(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
	row := pkidb.InsertCertificateParams{
		ID: out.ID, CaID: nullable(is.ca.ID), CaGeneration: sql.NullInt64{Int64: is.gen.Generation, Valid: true},
		Source: "issued", Preset: nullable(l.preset.Name), SerialHex: out.SerialHex,
		SubjectDn: cert.Subject.String(), CommonName: cert.Subject.CommonName,
		NotBefore: cert.NotBefore.UTC().Format(dbTime), NotAfter: cert.NotAfter.UTC().Format(dbTime),
		KeyAlgorithm: l.alg, KeyID: nullable(out.KeyID), CertDer: cert.Raw, FingerprintSha256: out.Fingerprint,
		RenewalOf: nullable(req.RenewalOf), RequestedBy: requestedBy(req.Who), CreatedAt: created,
	}
	if l.preset.Customizable {
		row.CustomKu = sql.NullString{String: joinNonEmpty(l.preset.KeyUsage.RSA), Valid: true}
		row.CustomEku = sql.NullString{String: joinNonEmpty(l.preset.ExtKeyUsage.Usages), Valid: true}
	}
	details := map[string]any{
		"ca": is.ca.Name, "ca_generation": is.gen.Generation, "preset": l.preset.Name,
		"serial": out.SerialHex, "subject": row.SubjectDn, "sans": sanStrings(l.names, 4096),
		"not_before": row.NotBefore, "not_after": row.NotAfter, "validity_days": l.v.days,
		"key_algorithm": l.alg, "key_source": "csr",
	}
	if out.KeyID != "" {
		details["key_source"] = "server"
	}
	if req.RenewalOf != "" {
		details["renewal_of"] = req.RenewalOf
	}
	if len(out.Notes) > 0 {
		details["notes"] = out.Notes
	}
	if len(dropped) > 0 {
		details["dropped_csr_names"] = capReasons(dropped)
	}
	if len(out.Warnings) > 0 {
		details["warnings"] = out.Warnings
	}

	tx, err := e.PKI.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := pkidb.New(tx)
	if out.KeyID != "" {
		if err := keys.SaveKey(ctx, tx, keys.StoredKey{ID: out.KeyID, Purpose: keys.PurposeLeaf, Algorithm: l.alg, Envelope: env}, created); err != nil {
			return nil, fmt.Errorf("store key: %w", err)
		}
	}
	if err := checkSerialFree(ctx, q, is.ca.ID, out.SerialHex); err != nil {
		return nil, err
	}
	if err := q.InsertCertificate(ctx, row); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}
	for _, kv := range l.names.list() {
		if err := q.InsertCertificateSAN(ctx, pkidb.InsertCertificateSANParams{CertificateID: out.ID, Type: kv[0], Value: kv[1]}); err != nil {
			return nil, fmt.Errorf("store certificate names: %w", err)
		}
	}
	entry := audit.Entry{
		Time: now, Actor: req.Who.Actor, Action: ActionIssue, Target: audit.Target{Type: "certificate", ID: out.ID},
		Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: details,
	}
	if err := audit.Enqueue(ctx, tx, now, entry); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}
	if e.Wake != nil {
		e.Wake()
	}
	return out, nil
}

func requestedBy(w keys.Who) string {
	if w.Actor.ID != "" {
		return w.Actor.ID
	}
	return w.Actor.Name
}

// logRefusal writes a refused request to the tenant audit log directly –
// there is no business change whose transaction could carry it.
func (e *Engine) logRefusal(ctx context.Context, req Request, now time.Time, cause error) error {
	details := map[string]any{"ca": short(req.CA), "preset": short(req.Preset), "key_source": "csr"}
	if req.CSR == nil {
		details["key_source"] = "server"
	}
	return e.refuse(ctx, now, ActionIssue, req.Who, audit.Target{Type: "ca", ID: short(req.CA)}, details, cause)
}

// refuse writes a refused or failed action to the tenant audit log: denied
// (with every reason) for policy refusals, failure for everything else.
func (e *Engine) refuse(ctx context.Context, now time.Time, action string, who keys.Who, target audit.Target, details map[string]any, cause error) error {
	result := audit.ResultFailure
	var d *DeniedError
	if errors.As(cause, &d) {
		result = audit.ResultDenied
		details["reasons"] = capReasons(d.Reasons)
		if len(d.DroppedCSRNames) > 0 {
			details["dropped_csr_names"] = capReasons(d.DroppedCSRNames)
		}
	} else {
		details["error"] = capText(cause.Error(), 512)
	}
	_, _, err := audit.Append(ctx, e.Audit, e.Scope, audit.Entry{
		Time: now, Actor: who.Actor, Action: action, Target: target,
		Result: result, SourceIP: who.SourceIP, Details: details,
	}, "")
	return err
}

// capReasons keeps a refusal's audit entry below the entry size limit.
func capReasons(reasons []string) []string {
	const maxReasons, maxLen = 10, 300
	var out []string
	for i, r := range reasons {
		if i == maxReasons {
			out = append(out, fmt.Sprintf("… and %d more", len(reasons)-maxReasons))
			break
		}
		out = append(out, capText(r, maxLen))
	}
	return out
}

func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
