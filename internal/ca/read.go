package ca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Read paths (PHASE1 step 13): lists and details for the API, with the
// permission checks in the service layer (security.md). Whoever may not read
// a CA doesn't learn that it or its certificates exist: ErrNotFound, the same
// as for an unknown ID (owner 2026-10-17). Whoever may read but lacks the
// role for an action gets the *DeniedError of that action.

// ActionKeyDownload is the audit action of a private key download.
const ActionKeyDownload = "key.download"

// ErrNotFound: no such object, or the caller may not read it.
var ErrNotFound = errors.New("not found")

// ErrNoStoredKey: the certificate was issued from a CSR – its key never was
// on this server.
var ErrNoStoredKey = errors.New("the private key of this certificate is not on the server – it was issued from a CSR")

// Certificate statuses (API).
const (
	CertValid   = "valid"
	CertRevoked = "revoked"
	CertExpired = "expired"
)

// Page sizes of ListCertificates.
const (
	DefaultPageSize = 50
	MaxPageSize     = 100
)

// canRead reports whether who may read CA name.
func (e *Engine) canRead(who keys.Who, name string, now time.Time) bool {
	return e.authorize(who, authz.ReadPKI, name, now) == nil
}

// CAs lists the CAs who may read, with the CRL state of each generation.
func (e *Engine) CAs(ctx context.Context, who keys.Who) ([]CAInfo, error) {
	now := e.now()
	all, err := ListCAs(ctx, e.PKI)
	if err != nil {
		return nil, err
	}
	statuses, err := CRLStatuses(ctx, e.PKI, now)
	if err != nil {
		return nil, err
	}
	AttachCRLStatus(all, statuses)
	out := make([]CAInfo, 0, len(all))
	for _, c := range all {
		if e.canRead(who, c.Name, now) {
			out = append(out, c)
		}
	}
	return out, nil
}

// CA returns one CA by ID.
func (e *Engine) CA(ctx context.Context, who keys.Who, id string) (*CAInfo, error) {
	cas, err := e.CAs(ctx, who)
	if err != nil {
		return nil, err
	}
	for i := range cas {
		if cas[i].ID == id {
			return &cas[i], nil
		}
	}
	return nil, ErrNotFound
}

// CAName returns the name of the CA with this ID, if who may read it.
func (e *Engine) CAName(ctx context.Context, who keys.Who, id string) (string, error) {
	ca, err := pkidb.New(e.PKI).GetCA(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !e.canRead(who, ca.Name, e.now()) {
		return "", ErrNotFound
	}
	return ca.Name, nil
}

// CAChain returns the certificate of the current generation of a CA and its
// issuers up to the root (DER, the CA first).
func (e *Engine) CAChain(ctx context.Context, who keys.Who, id string) ([][]byte, error) {
	if _, err := e.CAName(ctx, who, id); err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	ca, err := q.GetCA(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ca.CurrentGeneration.Valid {
		return nil, ErrNotFound
	}
	return readChain(ctx, q, ca.ID, ca.CurrentGeneration.Int64)
}

// readChain returns the DER certificates from a CA generation up to the
// root. Unlike loadChain it doesn't refuse revoked generations: a download
// shows what is there.
func readChain(ctx context.Context, q *pkidb.Queries, caID string, generation int64) ([][]byte, error) {
	var out [][]byte
	for range maxChainDepth {
		g, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: caID, Generation: generation})
		if err != nil {
			return nil, err
		}
		if g.CertDer == nil {
			return nil, ErrNotFound
		}
		out = append(out, g.CertDer)
		if !g.IssuerCaID.Valid {
			return out, nil
		}
		caID, generation = g.IssuerCaID.String, g.IssuerGeneration.Int64
	}
	return nil, fmt.Errorf("CA %s: chain is longer than %d – issuer references are broken", caID, maxChainDepth)
}

// CertificateInfo describes a stored certificate (read-only).
type CertificateInfo struct {
	ID, Source, Status             string
	CAID, CAName                   string // "" for external certificates
	CAGeneration                   int64
	Preset                         string
	Serial, Subject, CommonName    string
	DNSNames, IPs, Emails, URIs    []string
	NotBefore, NotAfter, CreatedAt time.Time
	KeyAlgorithm, Fingerprint      string
	KeyStored                      bool
	RenewalOf, RequestedBy         string
	RevocationReason               string
	RevokedAt, InvalidityDate      *time.Time
	certDER                        []byte
	keyID                          string
}

// CertificateFilter selects certificates; every field is optional.
type CertificateFilter struct {
	CAID, Preset, Status string
	ExpiresBefore        time.Time
	// Search is a substring of CN, serial or a SAN – no wildcards.
	Search string
	Cursor string // the last ID of the previous page
	Limit  int    // 0 = DefaultPageSize; at most MaxPageSize
}

// CertificatePage is one page of certificates, newest first.
type CertificatePage struct {
	Items      []CertificateInfo
	NextCursor string // "" = last page
}

// Certificates lists the certificates who may read.
func (e *Engine) Certificates(ctx context.Context, who keys.Who, f CertificateFilter) (*CertificatePage, error) {
	now := e.now()
	q := pkidb.New(e.PKI)
	cas, err := q.ListCAs(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	allowed := []string{}
	for _, c := range cas {
		names[c.ID] = c.Name
		if e.canRead(who, c.Name, now) {
			allowed = append(allowed, c.ID)
		}
	}
	// A tenant-wide role also sees certificates without a CA (external).
	tenantWide := e.authorize(who, authz.ReadPKI, "", now) == nil
	if !tenantWide && len(allowed) == 0 {
		return &CertificatePage{Items: []CertificateInfo{}}, nil
	}
	if f.CAID != "" && names[f.CAID] != "" && !e.canRead(who, names[f.CAID], now) {
		return nil, ErrNotFound
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultPageSize
	}
	limit = min(limit, MaxPageSize)
	allowedJSON, _ := json.Marshal(allowed)
	p := pkidb.ListCertificatesParams{
		AllCas: boolInt(tenantWide), AllowedCas: string(allowedJSON), CaID: f.CAID, Preset: f.Preset, Status: f.Status,
		Now: now.Format(dbTime), Search: strings.ToLower(f.Search), Cursor: f.Cursor, PageSize: int64(limit) + 1,
	}
	if !f.ExpiresBefore.IsZero() {
		p.ExpiresBefore = f.ExpiresBefore.UTC().Format(dbTime)
	}
	rows, err := q.ListCertificates(ctx, p)
	if err != nil {
		return nil, err
	}
	page := &CertificatePage{Items: make([]CertificateInfo, 0, min(len(rows), limit))}
	for i, r := range rows {
		if i == limit {
			page.NextCursor = page.Items[limit-1].ID
			break
		}
		info, err := certificateInfo(ctx, q, certRow{r.Certificate, r.RevocationReason, r.RevokedAt, r.InvalidityDate}, names, now)
		if err != nil {
			return nil, err
		}
		page.Items = append(page.Items, *info)
	}
	return page, nil
}

// certRow is a certificate with its revocation, from either query.
type certRow struct {
	c                                 pkidb.Certificate
	reason, revokedAt, invalidityDate sql.NullString
}

// Certificate returns one certificate by ID.
func (e *Engine) Certificate(ctx context.Context, who keys.Who, id string) (*CertificateInfo, error) {
	now := e.now()
	q := pkidb.New(e.PKI)
	c, err := q.GetCertificate(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	name := ""
	if c.CaID.Valid {
		ca, cerr := q.GetCA(ctx, c.CaID.String)
		if cerr != nil {
			return nil, cerr
		}
		name = ca.Name
	}
	if !e.canRead(who, name, now) {
		return nil, ErrNotFound
	}
	row := certRow{c: c}
	if r, rerr := q.GetRevocation(ctx, id); rerr == nil {
		row.reason = sql.NullString{String: r.Reason, Valid: true}
		row.revokedAt = sql.NullString{String: r.RevokedAt, Valid: true}
		row.invalidityDate = r.InvalidityDate
	} else if !errors.Is(rerr, sql.ErrNoRows) {
		return nil, rerr
	}
	return certificateInfo(ctx, q, row, map[string]string{c.CaID.String: name}, now)
}

func certificateInfo(ctx context.Context, q *pkidb.Queries, r certRow, names map[string]string, now time.Time) (*CertificateInfo, error) {
	c := r.c
	info := &CertificateInfo{
		ID: c.ID, Source: c.Source, CAID: c.CaID.String, CAName: names[c.CaID.String], CAGeneration: c.CaGeneration.Int64,
		Preset: c.Preset.String, Serial: c.SerialHex, Subject: c.SubjectDn, CommonName: c.CommonName,
		NotBefore: parseDBTime(c.NotBefore), NotAfter: parseDBTime(c.NotAfter), CreatedAt: parseDBTime(c.CreatedAt),
		KeyAlgorithm: c.KeyAlgorithm, Fingerprint: c.FingerprintSha256, KeyStored: c.KeyID.Valid,
		RenewalOf: c.RenewalOf.String, RequestedBy: c.RequestedBy, certDER: c.CertDer, keyID: c.KeyID.String,
		DNSNames: []string{}, IPs: []string{}, Emails: []string{}, URIs: []string{},
	}
	switch {
	case r.reason.Valid:
		info.Status, info.RevocationReason = CertRevoked, r.reason.String
		t := parseDBTime(r.revokedAt.String)
		info.RevokedAt = &t
		if r.invalidityDate.Valid {
			d := parseDBTime(r.invalidityDate.String)
			info.InvalidityDate = &d
		}
	case !now.Before(info.NotAfter):
		info.Status = CertExpired
	default:
		info.Status = CertValid
	}
	sans, err := q.ListCertificateSANs(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	for _, s := range sans {
		switch s.Type {
		case "dns":
			info.DNSNames = append(info.DNSNames, s.Value)
		case "ip":
			info.IPs = append(info.IPs, s.Value)
		case "email":
			info.Emails = append(info.Emails, s.Value)
		case "uri":
			info.URIs = append(info.URIs, s.Value)
		}
	}
	return info, nil
}

// parseDBTime reads a stored time; certificate times have whole seconds,
// audit-style stamps may have fractions.
func parseDBTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// CertificateChain returns the certificate (DER) and the intermediates up to
// just below the root, issuing CA first – what a server sends. The root is
// the trust anchor the client already has: it doesn't belong into the chain
// (RFC 8446 §4.4.2; SSL Labs "chain contains anchor"); it is downloaded with
// CAChain. A certificate signed by the root itself has an empty chain.
func (e *Engine) CertificateChain(ctx context.Context, who keys.Who, id string) (cert []byte, chain [][]byte, err error) {
	info, err := e.Certificate(ctx, who, id)
	if err != nil {
		return nil, nil, err
	}
	if info.CAID == "" {
		return info.certDER, nil, nil
	}
	chain, err = readChain(ctx, pkidb.New(e.PKI), info.CAID, info.CAGeneration)
	if err != nil {
		return nil, nil, err
	}
	// readChain ends at the root (the generation without an issuer).
	return info.certDER, chain[:len(chain)-1], nil
}

// ExportKey returns the private key of a certificate with a server-generated
// key as unencrypted PKCS#8 PEM (PHASE1 step 13, owner 2026-10-17: PKCS#12
// and "delete the key after the download" follow in step 18). It needs
// key.download – operator on the issuing CA and a fresh second factor – and
// an unsealed server. The download is audited before the key leaves
// (fail-closed); the key stays encrypted on the server.
func (e *Engine) ExportKey(ctx context.Context, who keys.Who, id string) ([]byte, error) {
	now := e.now()
	info, err := e.Certificate(ctx, who, id)
	if err != nil {
		return nil, err
	}
	target := audit.Target{Type: "certificate", ID: info.ID}
	details := map[string]any{"serial": info.Serial, "ca": info.CAName, "format": "pkcs8-pem"}
	if derr := e.authorize(who, authz.DownloadKey, info.CAName, now); derr != nil {
		if aerr := e.refuse(ctx, now, ActionKeyDownload, who, target, details, derr); aerr != nil {
			return nil, errors.Join(derr, fmt.Errorf("audit: %w", aerr))
		}
		return nil, derr
	}
	if !info.KeyStored {
		return nil, ErrNoStoredKey
	}
	if e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	key, err := keys.LoadKey(ctx, e.PKI, info.keyID)
	if err != nil {
		return nil, err
	}
	var out []byte
	err = e.Keys.WithKey(key.ID, key.Purpose, key.Algorithm, key.Envelope, func(pkcs8 []byte) error {
		if _, perr := x509.ParsePKCS8PrivateKey(pkcs8); perr != nil {
			return fmt.Errorf("key %s: not a PKCS#8 private key", key.ID)
		}
		out = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, _, aerr := audit.Append(ctx, e.Audit, e.Scope, audit.Entry{
		Time: now, Actor: who.Actor, Action: ActionKeyDownload, Target: target,
		Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
	}, ""); aerr != nil {
		clear(out)
		return nil, fmt.Errorf("key download refused – the audit entry can't be written: %w", aerr)
	}
	return out, nil
}
