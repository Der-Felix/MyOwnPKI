package ca

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Revocation (PHASE1 step 9). A revocation is final and is stored at once –
// also while the server is sealed. Clients see it only when a CRL lists it,
// so the CRL of the issuing generation is signed right after; while sealed
// that happens at unseal, and until then the revocation counts as
// "not yet published".

// Audit actions of revocation and CRLs.
const (
	ActionRevoke    = "certificate.revoke"
	ActionCARevoke  = "ca.revoke"
	ActionCRLSign   = "crl.sign"
	ActionCRLUpload = "crl.upload"
)

// Revocation reasons (RFC 5280 §5.3.1) – only final ones: no
// certificateHold/removeFromCRL (reversible, banned by the CA/B Forum).
const (
	ReasonUnspecified          = "unspecified"
	ReasonKeyCompromise        = "keyCompromise"
	ReasonCACompromise         = "cACompromise"
	ReasonAffiliationChanged   = "affiliationChanged"
	ReasonSuperseded           = "superseded"
	ReasonCessationOfOperation = "cessationOfOperation"
	ReasonPrivilegeWithdrawn   = "privilegeWithdrawn"
)

// reasonCodes are the CRLReason values written into CRL entries.
var reasonCodes = map[string]int{
	ReasonUnspecified: 0, ReasonKeyCompromise: 1, ReasonCACompromise: 2, ReasonAffiliationChanged: 3,
	ReasonSuperseded: 4, ReasonCessationOfOperation: 5, ReasonPrivilegeWithdrawn: 9,
}

// LeafReasons and CAReasons are the reasons a request may use.
var (
	LeafReasons = []string{ReasonUnspecified, ReasonKeyCompromise, ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation, ReasonPrivilegeWithdrawn}
	CAReasons   = append(slices.Clone(LeafReasons), ReasonCACompromise)
)

// RevokeRequest revokes an end-entity certificate.
type RevokeRequest struct {
	CertificateID string
	Reason        string
	// InvalidityDate: when the key is known or suspected to be compromised
	// (keyCompromise only); nil = not given.
	InvalidityDate *time.Time
	Who            keys.Who
}

// RevokeCARequest revokes a CA generation signed by an online parent.
type RevokeCARequest struct {
	Name           string
	Generation     int64 // 0 = the current generation
	Reason         string
	InvalidityDate *time.Time
	Who            keys.Who
}

// RevokeResult says whether the revocation is already published.
type RevokeResult struct {
	Serial    string
	CRL       *CRLResult // nil when no CRL could be signed yet
	Published bool       // false: stored, but not on a CRL yet (sealed server)
	Warnings  []string
}

// Revoke revokes an end-entity certificate and signs the new CRL of its
// issuing generation.
func (e *Engine) Revoke(ctx context.Context, req RevokeRequest) (*RevokeResult, error) {
	now := e.now()
	out, err := e.revoke(ctx, req, now)
	if err != nil {
		if aerr := e.refuse(ctx, now, ActionRevoke, req.Who, audit.Target{Type: "certificate", ID: short(req.CertificateID)},
			map[string]any{"reason": short(req.Reason)}, err); aerr != nil {
			return nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
		return nil, err
	}
	return out, nil
}

func (e *Engine) revoke(ctx context.Context, req RevokeRequest, now time.Time) (*RevokeResult, error) {
	q := pkidb.New(e.PKI)
	row, err := q.GetCertificate(ctx, req.CertificateID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if row.Source == "external" || !row.CaID.Valid {
		return nil, deny("certificate %s was not issued by this PKI – only its issuer can revoke it", row.ID)
	}
	issuerCA, err := q.GetCA(ctx, row.CaID.String)
	if err != nil {
		return nil, err
	}
	// No read access: answered like an unknown ID (decision 64).
	if !e.canRead(req.Who, issuerCA.Name, now) {
		return nil, ErrNotFound
	}
	if aerr := e.authorize(req.Who, authz.RevokeCert, issuerCA.Name, now); aerr != nil {
		return nil, aerr
	}
	if _, rerr := q.GetRevocation(ctx, row.ID); rerr == nil {
		return nil, deny("certificate %s is revoked already – a revocation is final", row.ID)
	} else if !errors.Is(rerr, sql.ErrNoRows) {
		return nil, rerr
	}
	if cerr := checkReason(req.Reason, LeafReasons, req.InvalidityDate, now); cerr != nil {
		return nil, cerr
	}
	cert, err := x509.ParseCertificate(row.CertDer)
	if err != nil {
		return nil, fmt.Errorf("certificate %s: stored certificate: %w", row.ID, err)
	}
	var warnings []string
	if now.After(cert.NotAfter) {
		warnings = append(warnings, "the certificate has expired already – the revocation is recorded and published until the CRL drops expired entries")
	}
	blocked, err := spkiHash(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	details := map[string]any{
		"serial": row.SerialHex, "reason": req.Reason, "ca_id": row.CaID.String, "ca_generation": row.CaGeneration.Int64,
		"subject": row.SubjectDn,
	}
	if req.InvalidityDate != nil {
		details["invalidity_date"] = req.InvalidityDate.UTC().Format(time.RFC3339)
	}
	if req.Reason == ReasonKeyCompromise {
		details["blocked_key"] = blocked
	}
	stamp := now.Format(audit.TimeFormat)
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := q.InsertRevocation(ctx, pkidb.InsertRevocationParams{
			CertificateID: row.ID, Reason: req.Reason, RevokedAt: stamp, InvalidityDate: nullTime(req.InvalidityDate), RevokedBy: requestedBy(req.Who),
		}); terr != nil {
			return terr
		}
		if req.Reason == ReasonKeyCompromise {
			if terr := q.BlockKey(ctx, pkidb.BlockKeyParams{
				SpkiSha256: blocked, Reason: req.Reason, SourceType: "certificate", SourceID: row.ID, BlockedAt: stamp, BlockedBy: requestedBy(req.Who),
			}); terr != nil {
				return terr
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: req.Who.Actor, Action: ActionRevoke, Target: audit.Target{Type: "certificate", ID: row.ID},
			Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	out := &RevokeResult{Serial: row.SerialHex, Warnings: warnings}
	e.publishAfterRevocation(ctx, out, row.CaID.String, row.CaGeneration.Int64, req.Who)
	return out, nil
}

// publishAfterRevocation signs the CRL that makes a revocation effective.
// The revocation is stored either way; a CRL that can't be signed now
// (sealed, offline key) is a warning, and the maintainer signs it later.
func (e *Engine) publishAfterRevocation(ctx context.Context, out *RevokeResult, caID string, generation int64, who keys.Who) {
	crl, err := e.signCRLAs(ctx, caID, generation, "revocation", who, authz.RevokeCert)
	switch {
	case err == nil:
		out.CRL, out.Published = crl, true
	case errors.Is(err, keys.ErrSealed):
		out.Warnings = append(out.Warnings, "the server is sealed: the revocation is stored, but takes effect only when the CRL is signed at unseal")
	default:
		out.Warnings = append(out.Warnings, "the revocation is stored, but the CRL could not be signed yet: "+err.Error())
	}
}

// RevokeCA revokes a CA generation below an online parent and signs the
// parent's new CRL. A CA below an offline root is revoked on the root; its
// uploaded CRL then marks the generation (UploadCRL).
func (e *Engine) RevokeCA(ctx context.Context, req RevokeCARequest) (*RevokeResult, error) {
	now := e.now()
	out, err := e.revokeCA(ctx, req, now)
	if err != nil {
		if aerr := e.refuse(ctx, now, ActionCARevoke, req.Who, audit.Target{Type: "ca", ID: short(req.Name)},
			map[string]any{"name": short(req.Name), "generation": req.Generation, "reason": short(req.Reason)}, err); aerr != nil {
			return nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
		return nil, err
	}
	return out, nil
}

func (e *Engine) revokeCA(ctx context.Context, req RevokeCARequest, now time.Time) (*RevokeResult, error) {
	q := pkidb.New(e.PKI)
	ca, err := q.GetCAByName(ctx, req.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, deny("there is no CA named %q", short(req.Name))
	}
	if err != nil {
		return nil, err
	}
	genNo := req.Generation
	if genNo == 0 {
		if !ca.CurrentGeneration.Valid {
			return nil, deny("CA %q has no signed generation", ca.Name)
		}
		genNo = ca.CurrentGeneration.Int64
	}
	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: ca.ID, Generation: genNo})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && gen.CertDer == nil) {
		return nil, deny("CA %q has no signed generation %d", ca.Name, genNo)
	}
	if err != nil {
		return nil, err
	}
	if !gen.IssuerCaID.Valid {
		return nil, deny("CA %q is a root – a root can't be revoked by anyone; remove it from the trust stores and retire it", ca.Name)
	}
	parent, err := q.GetCA(ctx, gen.IssuerCaID.String)
	if err != nil {
		return nil, err
	}
	// Like a leaf, a CA is revoked by whoever manages its issuer.
	if aerr := e.authorize(req.Who, authz.ManageCA, parent.Name, now); aerr != nil {
		return nil, aerr
	}
	if parent.KeyMode == KeyModeOffline {
		return nil, deny("CA %q was signed by the offline root %q – revoke it there and upload the root's new CRL", ca.Name, parent.Name)
	}
	if _, rerr := q.GetCARevocation(ctx, pkidb.GetCARevocationParams{CaID: ca.ID, Generation: genNo}); rerr == nil {
		return nil, deny("CA %q generation %d is revoked already – a revocation is final", ca.Name, genNo)
	} else if !errors.Is(rerr, sql.ErrNoRows) {
		return nil, rerr
	}
	if cerr := checkReason(req.Reason, CAReasons, req.InvalidityDate, now); cerr != nil {
		return nil, cerr
	}
	cert, err := x509.ParseCertificate(gen.CertDer)
	if err != nil {
		return nil, fmt.Errorf("CA %q generation %d: stored certificate: %w", ca.Name, genNo, err)
	}
	blocked, err := spkiHash(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	block := req.Reason == ReasonCACompromise || req.Reason == ReasonKeyCompromise
	details := map[string]any{"name": ca.Name, "generation": genNo, "serial": gen.SerialHex.String, "reason": req.Reason, "parent": parent.Name}
	if block {
		details["blocked_key"] = blocked
	}
	stamp := now.Format(audit.TimeFormat)
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := q.InsertCARevocation(ctx, pkidb.InsertCARevocationParams{
			CaID: ca.ID, Generation: genNo, Reason: req.Reason, RevokedAt: stamp, InvalidityDate: nullTime(req.InvalidityDate),
			RevokedBy: requestedBy(req.Who), Source: "server",
		}); terr != nil {
			return terr
		}
		if block {
			if terr := q.BlockKey(ctx, pkidb.BlockKeyParams{
				SpkiSha256: blocked, Reason: blockReason(req.Reason), SourceType: "ca", SourceID: fmt.Sprintf("%s/%d", ca.ID, genNo),
				BlockedAt: stamp, BlockedBy: requestedBy(req.Who),
			}); terr != nil {
				return terr
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: req.Who.Actor, Action: ActionCARevoke, Target: audit.Target{Type: "ca", ID: ca.ID},
			Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	out := &RevokeResult{Serial: gen.SerialHex.String}
	if ca.CurrentGeneration.Valid && ca.CurrentGeneration.Int64 == genNo {
		out.Warnings = append(out.Warnings, fmt.Sprintf("CA %q can't issue any more – its current generation is revoked; renew it with a new key", ca.Name))
	}
	e.publishAfterRevocation(ctx, out, parent.ID, gen.IssuerGeneration.Int64, req.Who)
	return out, nil
}

func blockReason(reason string) string {
	if reason == ReasonKeyCompromise {
		return ReasonKeyCompromise
	}
	return ReasonCACompromise
}

func checkReason(reason string, allowed []string, invalidity *time.Time, now time.Time) error {
	if !slices.Contains(allowed, reason) {
		return deny("revocation reason %q is not allowed (allowed: %s) – a revocation is always final, there is no certificateHold",
			short(reason), strings.Join(allowed, ", "))
	}
	if invalidity != nil {
		if reason != ReasonKeyCompromise && reason != ReasonCACompromise {
			return deny("an invalidity date only goes with keyCompromise or cACompromise")
		}
		if invalidity.After(now) {
			return deny("the invalidity date is in the future")
		}
	}
	return nil
}

func nullTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339), Valid: true}
}

// spkiHash is the SHA-256 of the SubjectPublicKeyInfo – what blocked_keys
// stores, independent of the certificate the key was in.
func spkiHash(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// checkKeyNotBlocked refuses a key that was reported compromised.
func checkKeyNotBlocked(ctx context.Context, q *pkidb.Queries, pub crypto.PublicKey) error {
	h, err := spkiHash(pub)
	if err != nil {
		return err
	}
	b, err := q.GetBlockedKey(ctx, h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return deny("this key was reported compromised (%s, %s %s on %s) – create a new key", b.Reason, b.SourceType, b.SourceID, dateOf(b.BlockedAt))
}

func dateOf(stamp string) string {
	if len(stamp) >= 10 {
		return stamp[:10]
	}
	return stamp
}

// checkNotRevoked refuses a chain with a revoked CA generation in it.
func checkNotRevoked(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, gen pkidb.CaGeneration) error {
	r, err := q.GetCARevocation(ctx, pkidb.GetCARevocationParams{CaID: ca.ID, Generation: gen.Generation})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return deny("CA %q generation %d is revoked (%s, %s) – renew the CA with a new key", ca.Name, gen.Generation, r.Reason, dateOf(r.RevokedAt))
}
