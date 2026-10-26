package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Renewal, CSR inspection and external certificates (PHASE1 step 18).

// RenewCertRequest asks for a successor of a certificate: same CA, preset,
// subject and names; always a new key – a server-generated one for a
// server-generated original, a new CSR otherwise.
type RenewCertRequest struct {
	ID string
	// CSR is required when the original came from a CSR.
	CSR []byte
	// KeyAlgorithm of a new server key; "" = the original's.
	KeyAlgorithm string
	ValidityDays int
	// RevokePrevious is the legacy tri-state pointer: true = now, false = never,
	// nil = tenant default. Predecessor wins when both are present.
	RevokePrevious *bool
	Predecessor    *predecessor.Policy
	Who            keys.Who
}

// Renewed is the successor and, for an immediate choice, its predecessor revocation.
type Renewed struct {
	*Issued
	Revoked   *RevokeResult
	PlannedAt *time.Time
}

// EffectiveOtherPredecessor reads the tenant policy for UI, REST and ACME.
func (e *Engine) EffectiveOtherPredecessor(ctx context.Context) (predecessor.Policy, error) {
	if e.OtherPredecessor == nil {
		return predecessor.DefaultOther, nil
	}
	policy, err := e.OtherPredecessor(ctx)
	if err != nil {
		return predecessor.Policy{}, err
	}
	return policy.Normalize(), policy.Validate()
}

// RenewCertificate issues the successor through the normal issuance path
// (same checks and audit, renewal_of set). Its predecessor action is atomic
// with the new certificate; CRL signing follows the commit.
func (e *Engine) RenewCertificate(ctx context.Context, req RenewCertRequest) (*Renewed, error) {
	info, err := e.Certificate(ctx, req.Who, req.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case info.Source == "external":
		return nil, deny("an external certificate is renewed by the CA that issued it")
	case info.Preset == "":
		return nil, deny("the certificate has no preset (imported without one) – issue a new certificate instead")
	case !info.KeyStored && req.CSR == nil:
		return nil, deny("the certificate was issued from a CSR – send a new CSR for the successor (a renewal always gets a new key)")
	case info.KeyStored && req.CSR != nil:
		return nil, deny("the certificate has a server-generated key – the successor gets a new one; don't send a CSR")
	}
	policy := predecessor.Policy{}
	if req.Predecessor != nil {
		policy = *req.Predecessor
	} else if req.RevokePrevious != nil {
		policy.Choice = predecessor.Never
		if *req.RevokePrevious {
			policy.Choice = predecessor.Now
		}
	} else if policy, err = e.EffectiveOtherPredecessor(ctx); err != nil {
		return nil, err
	}
	policy = policy.Normalize()
	if verr := policy.Validate(); verr != nil {
		return nil, deny("%s", verr)
	}
	if policy.Choice != predecessor.Never {
		if derr := e.authorize(req.Who, authz.RevokeCert, info.CAName, e.now()); derr != nil {
			return nil, derr
		}
	}
	cert, err := x509.ParseCertificate(info.certDER)
	if err != nil {
		return nil, err
	}
	r := Request{
		CA: info.CAName, Preset: info.Preset, CSR: req.CSR, IgnoreCSRNames: req.CSR != nil,
		DNSNames: info.DNSNames, IPAddresses: info.IPs, EmailAddresses: info.Emails, URIs: info.URIs,
		Subject: csrSubject(cert.Subject), ValidityDays: req.ValidityDays, RenewalOf: info.ID, Who: req.Who,
	}
	if info.KeyStored {
		r.KeyAlgorithm = req.KeyAlgorithm
		if r.KeyAlgorithm == "" {
			r.KeyAlgorithm = info.KeyAlgorithm
		}
	}
	if custom, cerr := e.customUsages(ctx, info.ID); cerr != nil {
		return nil, cerr
	} else if custom != nil {
		r.CustomKeyUsage, r.CustomExtKeyUsage = custom[0], custom[1]
	}
	var revocations []*RevokeResult
	r.Stored = func(ctx context.Context, tx *sql.Tx, issued *Issued) error {
		var applyErr error
		revocations, applyErr = e.ApplyPredecessor(ctx, pkidb.New(tx), tx, info.ID, issued.ID, policy, "renewal", req.Who, e.now())
		return applyErr
	}
	issued, err := e.Issue(ctx, r)
	if err != nil {
		return nil, err
	}
	out := &Renewed{Issued: issued}
	if len(revocations) > 0 {
		out.Revoked = revocations[0]
		e.PublishPredecessorRevocations(ctx, revocations, req.Who)
	} else if policy.Choice == predecessor.After && info.Status != CertRevoked {
		if plan, perr := pkidb.New(e.PKI).GetRevocationPlan(ctx, info.ID); perr == nil {
			t := parseDBTime(plan.PlannedAt)
			out.PlannedAt = &t
		} else if !errors.Is(perr, sql.ErrNoRows) {
			return nil, perr
		}
	}
	return out, nil
}

// customUsages are the stored usages of a customizable preset, or nil.
func (e *Engine) customUsages(ctx context.Context, id string) (*[2][]string, error) {
	row, err := pkidb.New(e.PKI).GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	if !row.CustomKu.Valid && !row.CustomEku.Valid {
		return nil, nil
	}
	split := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return &[2][]string{split(row.CustomKu.String), split(row.CustomEku.String)}, nil
}

// CSRInspection is what a CSR asks for, parsed for a preview. Nothing is
// stored; the CSR's extensions are listed for information only.
type CSRInspection struct {
	Subject             string
	CommonName          string
	DNSNames, IPs       []string
	Emails, URIs        []string
	KeyAlgorithm        string
	SignatureValid      bool
	RequestedExtensions []string
	Problems, Warnings  []string
}

// InspectCSR parses a CSR. A broken CSR is a DeniedError; a CSR whose key
// the policy refuses comes back with Problems.
func InspectCSR(data []byte) (*CSRInspection, error) {
	csr, err := parseCSR(data)
	if err != nil {
		return nil, err
	}
	out := &CSRInspection{Subject: csr.Subject.String(), CommonName: csr.Subject.CommonName, SignatureValid: true,
		DNSNames: append([]string{}, csr.DNSNames...), IPs: []string{}, Emails: append([]string{}, csr.EmailAddresses...), URIs: []string{},
		RequestedExtensions: []string{}, Problems: []string{}, Warnings: []string{}}
	for _, ip := range csr.IPAddresses {
		out.IPs = append(out.IPs, ip.String())
	}
	for _, u := range csr.URIs {
		out.URIs = append(out.URIs, u.String())
	}
	for _, ext := range csr.Extensions {
		name := extensionName(ext.Id.String())
		if ext.Critical {
			name += " (critical)"
		}
		out.RequestedExtensions = append(out.RequestedExtensions, name)
	}
	if out.KeyAlgorithm, err = keyAlgorithm(csr.PublicKey); err != nil {
		out.KeyAlgorithm = describeKey(csr.PublicKey)
		out.Problems = append(out.Problems, err.Error())
	}
	if len(out.RequestedExtensions) > 0 {
		out.Warnings = append(out.Warnings, "the CSR asks for extensions – they are never copied; the preset decides them")
	}
	return out, nil
}

func extensionName(oid string) string {
	names := map[string]string{
		"2.5.29.17": "subjectAltName", "2.5.29.19": "basicConstraints", "2.5.29.15": "keyUsage",
		"2.5.29.37": "extendedKeyUsage", "2.5.29.30": "nameConstraints", "2.5.29.14": "subjectKeyIdentifier",
		"1.3.6.1.5.5.7.1.24": "tlsFeature", "1.3.6.1.4.1.311.20.2": "certificateTemplateName",
	}
	if n, ok := names[oid]; ok {
		return n
	}
	return oid
}

// ActionImportExternal is the audit action of an external certificate.
const ActionImportExternal = "certificate.import_external"

// ImportExternal stores a certificate of another CA (source external) for
// expiry monitoring; it needs tenant.manage. Nothing is checked against a
// policy – it is a record, not an issuance.
func (e *Engine) ImportExternal(ctx context.Context, certPEM []byte, who keys.Who) (*CertificateInfo, error) {
	now := e.now()
	id, err := e.importExternal(ctx, certPEM, who, now)
	if err != nil {
		if aerr := e.refuse(ctx, now, ActionImportExternal, who, audit.Target{Type: "certificate"}, map[string]any{}, err); aerr != nil {
			return nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
		return nil, err
	}
	return e.Certificate(ctx, who, id)
}

func (e *Engine) importExternal(ctx context.Context, certPEM []byte, who keys.Who, now time.Time) (string, error) {
	if err := e.authorize(who, authz.ManageTenant, "", now); err != nil {
		return "", err
	}
	cert, err := parseOneCertificate(certPEM)
	if err != nil {
		return "", err
	}
	if cert.IsCA {
		return "", deny("this is a CA certificate – import a root with POST /cas/import")
	}
	sum := sha256.Sum256(cert.Raw)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	q := pkidb.New(e.PKI)
	if n, cerr := q.CountFingerprint(ctx, fp); cerr != nil {
		return "", cerr
	} else if n > 0 {
		return "", deny("this certificate is on the server already")
	}
	id, err := ids.New("crt", now, nil)
	if err != nil {
		return "", err
	}
	stamp := now.Format(audit.TimeFormat)
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertCertificate(ctx, pkidb.InsertCertificateParams{
			ID: id, Source: "external", SerialHex: SerialHex(cert.SerialNumber), SubjectDn: cert.Subject.String(),
			CommonName: cert.Subject.CommonName, NotBefore: cert.NotBefore.UTC().Format(dbTime), NotAfter: cert.NotAfter.UTC().Format(dbTime),
			KeyAlgorithm: describeKey(cert.PublicKey), CertDer: cert.Raw, FingerprintSha256: fp, RequestedBy: requestedBy(who), CreatedAt: stamp,
		}); ierr != nil {
			return ierr
		}
		for _, n := range certNames(cert) {
			if serr := q.InsertCertificateSAN(ctx, pkidb.InsertCertificateSANParams{CertificateID: id, Type: n[0], Value: n[1]}); serr != nil {
				return serr
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionImportExternal, Target: audit.Target{Type: "certificate", ID: id},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{
				"subject": short(cert.Subject.String()), "issuer": short(cert.Issuer.String()), "serial": SerialHex(cert.SerialNumber),
				"not_after": cert.NotAfter.UTC().Format(dbTime), "fingerprint": fp,
			},
		})
	})
	return id, err
}
