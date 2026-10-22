package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// revokeCert (RFC 8555 section 7.6, PHASE2 step 10). Three signers may
// revoke a certificate of this PKI:
//
//   - the account whose order issued it,
//   - an account with a valid authorization for every name in it,
//   - the certificate's own key (jwk) – the way to report a leaked key
//     without the account.
//
// keyCompromise blocks the key for every later certificate, so only the
// first and the last may give that reason (like Let's Encrypt): an account
// that merely controls the names can't block a key it may never have held.
// The revocation goes through the engine like one from the UI: final,
// stored also while sealed, published with the next CRL.
func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, either)
	if !ok {
		return
	}
	var p struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := payload(req, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(p.Certificate)
	if err != nil || len(der) == 0 {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "\"certificate\" must be the certificate's DER in base64url without padding"))
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "\"certificate\" is not a certificate: %v", err))
		return
	}
	reason, err := revocationReason(p.Reason)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	q := pkidb.New(s.db)
	sum := sha256.Sum256(der)
	row, err := q.GetCertificateByFingerprint(ctx, strings.ToUpper(hex.EncodeToString(sum[:])))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !row.CaID.Valid) {
		s.fail(w, r, problemErr(http.StatusNotFound, "malformed", "this server did not issue that certificate"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	who, err := s.revoker(ctx, q, req, &row, cert, reason)
	if err != nil {
		var ae *acmeError
		if errors.As(err, &ae) && ae.typ == "unauthorized" {
			s.refuseRevoke(ctx, req, row.ID, reason, ae.detail)
		}
		s.fail(w, r, err)
		return
	}
	if _, rerr := q.GetRevocation(ctx, row.ID); rerr == nil {
		s.fail(w, r, problemErr(http.StatusBadRequest, "alreadyRevoked", "the certificate is revoked already – a revocation is final"))
		return
	} else if !errors.Is(rerr, sql.ErrNoRows) {
		s.fail(w, r, rerr)
		return
	}
	res, err := s.engine.Revoke(ctx, ca.RevokeRequest{CertificateID: row.ID, Reason: reason, Who: who})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, warn := range res.Warnings {
		s.log.Warn("acme revocation", slog.String("certificate", row.ID), slog.String("warning", warn))
	}
	w.WriteHeader(http.StatusOK)
}

// revocationReason maps the RFC 5280 code to the reasons a leaf may have;
// no code is "unspecified".
func revocationReason(code *int) (string, error) {
	if code == nil {
		return ca.ReasonUnspecified, nil
	}
	names := map[int]string{
		0: ca.ReasonUnspecified, 1: ca.ReasonKeyCompromise, 3: ca.ReasonAffiliationChanged,
		4: ca.ReasonSuperseded, 5: ca.ReasonCessationOfOperation, 9: ca.ReasonPrivilegeWithdrawn,
	}
	if n, ok := names[*code]; ok {
		return n, nil
	}
	return "", problemErr(http.StatusBadRequest, "badRevocationReason", "reason %d is not allowed (allowed: 0, 1, 3, 4, 5, 9 – no hold, no CA reasons)", *code)
}

// revoker checks that the signer may revoke the certificate and returns
// who the engine records.
func (s *Server) revoker(ctx context.Context, q *pkidb.Queries, req *request, row *pkidb.Certificate, cert *x509.Certificate, reason string) (keys.Who, error) {
	who := keys.Who{Principal: authz.System("acme"), SourceIP: req.ip}
	if req.account == nil {
		// Signed with a jwk: it must be the certificate's own key.
		pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(req.key.Public()) {
			return who, problemErr(http.StatusForbidden, "unauthorized", "the request is signed neither by an account nor by the certificate's key")
		}
		who.Actor = audit.Actor{Type: audit.ActorACMEAccount, ID: "key:" + req.key.Thumbprint(), Name: "acme:certificate-key"}
		return who, nil
	}
	who.Actor = audit.Actor{Type: audit.ActorACMEAccount, ID: req.account.ID, Name: "acme:" + req.account.ID}
	o, err := q.GetACMEOrderByCertificate(ctx, sql.NullString{String: row.ID, Valid: true})
	if err == nil && o.AccountID == req.account.ID {
		return who, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return who, err
	}
	if reason == ca.ReasonKeyCompromise {
		return who, problemErr(http.StatusForbidden, "unauthorized", "keyCompromise needs the account that ordered the certificate or a request signed with the certificate's key")
	}
	idents, err := certIdentifiers(cert)
	if err != nil {
		return who, err
	}
	now := dbTime(s.now())
	for _, id := range idents {
		value, wildcard := id.Value, int64(0)
		if base, ok := strings.CutPrefix(id.Value, "*."); ok {
			value, wildcard = base, 1
		}
		n, herr := q.HasValidACMEAuthz(ctx, pkidb.HasValidACMEAuthzParams{
			AccountID: req.account.ID, IdentifierType: id.Type, IdentifierValue: value, Wildcard: wildcard, ExpiresAt: now,
		})
		if herr != nil {
			return who, herr
		}
		if n == 0 {
			return who, problemErr(http.StatusForbidden, "unauthorized", "the account holds no valid authorization for %s %q", id.Type, clip(id.Value))
		}
	}
	return who, nil
}

// certIdentifiers lists the names of a certificate as ACME identifiers. A
// certificate with other names (email, URI) or none can't be covered by
// authorizations.
func certIdentifiers(cert *x509.Certificate) ([]identifier, error) {
	if len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 || len(cert.DNSNames)+len(cert.IPAddresses) == 0 {
		return nil, problemErr(http.StatusForbidden, "unauthorized", "the certificate has names no ACME authorization covers – revoke it in the UI")
	}
	var out []identifier
	for _, n := range cert.DNSNames {
		out = append(out, identifier{"dns", strings.ToLower(n)})
	}
	for _, ip := range cert.IPAddresses {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, problemErr(http.StatusForbidden, "unauthorized", "the certificate has an IP address no ACME authorization covers")
		}
		out = append(out, identifier{"ip", a.Unmap().String()})
	}
	return out, nil
}

// refuseRevoke records a refused revocation – someone tried to revoke a
// certificate that isn't theirs.
func (s *Server) refuseRevoke(ctx context.Context, req *request, certID, reason, why string) {
	actor := "key:" + req.key.Thumbprint()
	if req.account != nil {
		actor = req.account.ID
	}
	now := s.now()
	err := s.inTx(ctx, func(_ *pkidb.Queries, tx *sql.Tx) error {
		return enqueue(ctx, tx, now, actor, req.ip, ca.ActionRevoke, audit.Target{Type: "certificate", ID: certID}, audit.ResultDenied,
			map[string]any{"reason": reason, "refusal": why})
	})
	if err != nil {
		s.log.Error("acme audit", slog.String("action", ca.ActionRevoke), slog.Any("error", err))
	}
}
