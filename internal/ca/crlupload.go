package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// MaxCRLSize limits an uploaded CRL.
const MaxCRLSize = 4 << 20

// crlClockSkew: thisUpdate may be this far in the future (clock of the
// offline machine).
const crlClockSkew = 5 * time.Minute

// UploadCRL stores a CRL the offline root signed (owner decision
// 2026-10-14). It must be signed by exactly one generation of that root,
// its number must be higher than every CRL number of the CA so far, it must
// be current and a full CRL. Intermediates of ours that it lists as revoked
// are marked revoked at once – they stop issuing.
func (e *Engine) UploadCRL(ctx context.Context, name string, data []byte, who keys.Who) (*CRLResult, []string, error) {
	now := e.now()
	out, warnings, err := e.uploadCRL(ctx, name, data, who, now)
	if err != nil {
		if aerr := e.refuse(ctx, now, ActionCRLUpload, who, audit.Target{Type: "ca", ID: short(name)}, map[string]any{"name": short(name)}, err); aerr != nil {
			return nil, nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
		return nil, nil, err
	}
	return out, warnings, nil
}

func (e *Engine) uploadCRL(ctx context.Context, name string, data []byte, who keys.Who, now time.Time) (*CRLResult, []string, error) {
	q := pkidb.New(e.PKI)
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, deny("there is no CA named %q", short(name))
	}
	if err != nil {
		return nil, nil, err
	}
	if ca.KeyMode != KeyModeOffline {
		return nil, nil, deny("CA %q signs its CRLs itself – only the CRL of an offline root is uploaded", ca.Name)
	}
	der, err := crlDER(data)
	if err != nil {
		return nil, nil, err
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, nil, deny("the CRL can't be parsed: %v", err)
	}

	gens, err := q.ListCAGenerations(ctx, ca.ID)
	if err != nil {
		return nil, nil, err
	}
	var gen *pkidb.CaGeneration
	for i := range gens {
		if gens[i].CertDer == nil {
			continue
		}
		cert, perr := x509.ParseCertificate(gens[i].CertDer)
		if perr != nil {
			return nil, nil, fmt.Errorf("CA %q generation %d: stored certificate can't be read: %w", ca.Name, gens[i].Generation, perr)
		}
		if crl.CheckSignatureFrom(cert) == nil && bytes.Equal(crl.AuthorityKeyId, cert.SubjectKeyId) {
			gen = &gens[i]
			break
		}
	}
	var reasons []string
	if gen == nil {
		reasons = append(reasons, fmt.Sprintf("the CRL is not signed by any generation of root %q (signature and authority key identifier must match)", ca.Name))
	}
	if !acceptedSignature(crl.SignatureAlgorithm) {
		reasons = append(reasons, fmt.Sprintf("the CRL is signed with %v – only SHA-2 (RSA, ECDSA) and Ed25519 signatures are accepted", crl.SignatureAlgorithm))
	}
	maxNo, err := q.MaxCRLNumber(ctx, ca.ID)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case crl.Number == nil || crl.Number.Sign() <= 0:
		reasons = append(reasons, "the CRL has no CRL number")
	case !crl.Number.IsInt64():
		reasons = append(reasons, "the CRL number is larger than this server can store (63 bits)")
	case crl.Number.Int64() <= max(maxNo, ca.CrlNumber):
		reasons = append(reasons, fmt.Sprintf("CRL number %d is not higher than the newest one (%d) – clients would keep the newer CRL", crl.Number.Int64(), max(maxNo, ca.CrlNumber)))
	}
	if crl.ThisUpdate.After(now.Add(crlClockSkew)) {
		reasons = append(reasons, fmt.Sprintf("thisUpdate %s is in the future – check the clock of the offline machine", crl.ThisUpdate.UTC().Format(time.RFC3339)))
	}
	if crl.NextUpdate.IsZero() || !crl.NextUpdate.After(now) {
		reasons = append(reasons, fmt.Sprintf("nextUpdate %s has passed already – sign a new CRL", crl.NextUpdate.UTC().Format(time.RFC3339)))
	}
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			reasons = append(reasons, "this is a delta CRL – upload the full CRL")
		case ext.Critical && !ext.Id.Equal(oidIssuingDistributionPoint):
			reasons = append(reasons, fmt.Sprintf("unknown critical CRL extension %s", ext.Id))
		}
	}
	if len(reasons) > 0 {
		return nil, nil, &DeniedError{Reasons: reasons}
	}

	// Intermediates of ours that the root revoked: mark them, and block
	// their key for cACompromise/keyCompromise.
	type revoked struct {
		gen    pkidb.CaGeneration
		reason string
		code   int    // the reason code as the root wrote it
		caName string // for the warnings
		at     time.Time
	}
	var newly []revoked
	for _, r := range crl.RevokedCertificateEntries {
		g, ferr := q.FindGenerationBySerial(ctx, pkidb.FindGenerationBySerialParams{
			IssuerCaID: sql.NullString{String: ca.ID, Valid: true}, SerialHex: sql.NullString{String: SerialHex(r.SerialNumber), Valid: true},
		})
		if errors.Is(ferr, sql.ErrNoRows) {
			continue
		}
		if ferr != nil {
			return nil, nil, ferr
		}
		if _, rerr := q.GetCARevocation(ctx, pkidb.GetCARevocationParams{CaID: g.CaID, Generation: g.Generation}); rerr == nil {
			continue
		} else if !errors.Is(rerr, sql.ErrNoRows) {
			return nil, nil, rerr
		}
		sub, gerr := q.GetCA(ctx, g.CaID)
		if gerr != nil {
			return nil, nil, gerr
		}
		newly = append(newly, revoked{gen: g, reason: reasonName(r.ReasonCode), code: r.ReasonCode, caName: sub.Name, at: r.RevocationTime})
	}

	var warnings []string
	out := &CRLResult{CA: ca.Name, Generation: gen.Generation, Number: crl.Number.Int64(), ThisUpdate: crl.ThisUpdate, NextUpdate: crl.NextUpdate,
		Entries: len(crl.RevokedCertificateEntries), DER: der}
	if life := crl.NextUpdate.Sub(crl.ThisUpdate); life > 0 {
		warnings = append(warnings, fmt.Sprintf("renew this CRL on the offline root before %s (half of its lifetime) – the server warns from then on",
			crl.ThisUpdate.Add(life/2).UTC().Format("2006-01-02")))
	}
	stamp := now.Format(audit.TimeFormat)
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := q.InsertCRL(ctx, pkidb.InsertCRLParams{
			CaID: ca.ID, Generation: gen.Generation, Number: out.Number, ThisUpdate: crl.ThisUpdate.UTC().Format(dbTime),
			NextUpdate: crl.NextUpdate.UTC().Format(dbTime), CrlDer: der, Source: "uploaded", CreatedAt: stamp,
		}); terr != nil {
			return terr
		}
		if terr := q.SetCRLNumber(ctx, pkidb.SetCRLNumberParams{CrlNumber: out.Number, UpdatedAt: stamp, ID: ca.ID}); terr != nil {
			return terr
		}
		for _, n := range newly {
			note := unsupportedReasonNote(n.code)
			if terr := e.markRevokedByRoot(ctx, q, tx, n.gen, n.reason, note, n.at, who, now); terr != nil {
				return terr
			}
			warnings = append(warnings, fmt.Sprintf("the root revoked CA %q generation %d (%s) – it can't issue any more", n.caName, n.gen.Generation, n.reason))
			if note != "" {
				warnings = append(warnings, fmt.Sprintf("CA %q generation %d: %s", n.caName, n.gen.Generation, note))
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionCRLUpload, Target: audit.Target{Type: "ca", ID: ca.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{
				"name": ca.Name, "generation": gen.Generation, "number": out.Number, "entries": out.Entries,
				"this_update": crl.ThisUpdate.UTC().Format(dbTime), "next_update": crl.NextUpdate.UTC().Format(dbTime),
				"revoked_cas": len(newly),
			},
		})
	})
	if err != nil {
		return nil, nil, err
	}
	return out, warnings, nil
}

// markRevokedByRoot records a CA generation the offline root revoked.
// note explains a reason code we don't take ("" = none).
func (e *Engine) markRevokedByRoot(ctx context.Context, q *pkidb.Queries, tx *sql.Tx, g pkidb.CaGeneration, reason, note string, at time.Time,
	who keys.Who, now time.Time,
) error {
	stamp := now.Format(audit.TimeFormat)
	if err := q.InsertCARevocation(ctx, pkidb.InsertCARevocationParams{
		CaID: g.CaID, Generation: g.Generation, Reason: reason, RevokedAt: at.UTC().Format(audit.TimeFormat),
		RevokedBy: requestedBy(who), Source: "root_crl",
	}); err != nil {
		return err
	}
	details := map[string]any{"generation": g.Generation, "serial": g.SerialHex.String, "reason": reason, "source": "root_crl"}
	if note != "" {
		details["note"] = note
	}
	if reason == ReasonCACompromise || reason == ReasonKeyCompromise {
		cert, err := x509.ParseCertificate(g.CertDer)
		if err != nil {
			return err
		}
		h, err := spkiHash(cert.PublicKey)
		if err != nil {
			return err
		}
		if err := q.BlockKey(ctx, pkidb.BlockKeyParams{
			SpkiSha256: h, Reason: blockReason(reason), SourceType: "ca", SourceID: fmt.Sprintf("%s/%d", g.CaID, g.Generation),
			BlockedAt: stamp, BlockedBy: requestedBy(who),
		}); err != nil {
			return err
		}
		details["blocked_key"] = h
	}
	return audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: who.Actor, Action: ActionCARevoke, Target: audit.Target{Type: "ca", ID: g.CaID},
		Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
	})
}

// reasonName maps a CRL reason code back; codes we don't take (hold,
// aACompromise) count as unspecified – the revocation itself stands, see
// unsupportedReasonNote.
func reasonName(code int) string {
	for name, c := range reasonCodes {
		if c == code {
			return name
		}
	}
	return ReasonUnspecified
}

// CRL reason codes MyOwnPKI doesn't take (RFC 5280 §5.3.1).
const (
	reasonCodeCertificateHold = 6
	reasonCodeRemoveFromCRL   = 8
)

// unsupportedReasonNote says how a reason code we don't take is recorded.
// A hold is the important case: the root may lift it later, MyOwnPKI never
// does – nobody may wait for the CA to come back.
func unsupportedReasonNote(code int) string {
	switch {
	case code == reasonCodeCertificateHold:
		return "certificateHold is not supported – for MyOwnPKI this CA is revoked for good, even if the root lifts the hold later"
	case code == reasonCodeRemoveFromCRL:
		return "removeFromCRL is not supported – for MyOwnPKI this CA stays revoked"
	case code > 0 && reasonName(code) == ReasonUnspecified:
		return fmt.Sprintf("reason code %d is not used by MyOwnPKI – recorded as unspecified, the revocation is final", code)
	}
	return ""
}

// crlDER accepts a CRL as DER or as one PEM block "X509 CRL".
func crlDER(data []byte) ([]byte, error) {
	if len(data) > MaxCRLSize {
		return nil, deny("the CRL is larger than %d MiB", MaxCRLSize>>20)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		return data, nil
	}
	block, rest := pem.Decode(data)
	switch {
	case block == nil || block.Type != "X509 CRL":
		return nil, deny("expected a PEM block -----BEGIN X509 CRL----- or a DER file")
	case len(bytes.TrimSpace(rest)) > 0:
		return nil, deny("there is data after the CRL – upload exactly one CRL")
	}
	return block.Bytes, nil
}
