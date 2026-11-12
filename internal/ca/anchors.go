package ca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// TrustAnchors are the CA certificates of this PKI, for judging a chain that
// a TLS endpoint serves (the TLS scan, docs/PHASE3.md §10.2). Only public
// data is read – nothing is decrypted, so it works while the server is
// sealed.
type TrustAnchors struct {
	// Roots are the self-signed certificates of every root CA generation.
	Roots []*x509.Certificate
	// Intermediates are the certificates of every intermediate CA generation.
	Intermediates []*x509.Certificate
}

// TrustAnchors returns the signed, not revoked CA generations of every CA,
// older generations included: a chain may still end in one of them. It needs
// the tenant-wide read role; whoever lacks it gets ErrNotFound, as for the
// other reads (an anchor of a CA the caller may not read would tell that
// the CA exists).
func (e *Engine) TrustAnchors(ctx context.Context, who keys.Who) (*TrustAnchors, error) {
	if err := e.authorize(who, authz.ReadPKI, "", e.now()); err != nil {
		return nil, ErrNotFound
	}
	q := pkidb.New(e.PKI)
	cas, err := q.ListCAs(ctx)
	if err != nil {
		return nil, err
	}
	out := &TrustAnchors{}
	for _, c := range cas {
		gens, err := q.ListCAGenerations(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range gens {
			if g.CertDer == nil {
				continue // pending: not signed yet
			}
			if _, rerr := q.GetCARevocation(ctx, pkidb.GetCARevocationParams{CaID: c.ID, Generation: g.Generation}); rerr == nil {
				continue // a revoked CA is no anchor
			} else if !errors.Is(rerr, sql.ErrNoRows) {
				return nil, rerr
			}
			cert, perr := x509.ParseCertificate(g.CertDer)
			if perr != nil {
				return nil, fmt.Errorf("CA %q generation %d: stored certificate: %w", c.Name, g.Generation, perr)
			}
			if g.IssuerCaID.Valid {
				out.Intermediates = append(out.Intermediates, cert)
			} else {
				out.Roots = append(out.Roots, cert)
			}
		}
	}
	return out, nil
}

// CertificateByFingerprint returns the certificate with this SHA-256
// fingerprint (hex, any case), with the same rule as Certificate: whoever may
// not read it gets ErrNotFound, as for an unknown fingerprint.
func (e *Engine) CertificateByFingerprint(ctx context.Context, who keys.Who, fingerprint string) (*CertificateInfo, error) {
	fp := strings.ToUpper(strings.TrimSpace(fingerprint))
	if raw, err := hex.DecodeString(fp); err != nil || len(raw) != 32 {
		return nil, ErrNotFound
	}
	c, err := pkidb.New(e.PKI).GetCertificateByFingerprint(ctx, fp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return e.Certificate(ctx, who, c.ID)
}
