package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

type sealedKey struct {
	id, alg string
	env     keys.Envelope
}

// sealKey encrypts a key of the import with the root key (before the
// transaction: no crypto inside it).
func (e *Engine) sealKey(now time.Time, purpose string, s crypto.Signer) (sealedKey, error) {
	id, err := ids.New("key", now, nil)
	if err != nil {
		return sealedKey{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(s)
	if err != nil {
		return sealedKey{}, err
	}
	defer clear(pkcs8)
	alg := describeKey(s.Public())
	env, err := e.Keys.EncryptKey(id, purpose, alg, pkcs8)
	if err != nil {
		return sealedKey{}, fmt.Errorf("encrypt key: %w", err)
	}
	return sealedKey{id: id, alg: alg, env: env}, nil
}

// writeLegacy stores the plan in one pki.db transaction.
func (e *Engine) writeLegacy(ctx context.Context, p *legacyPlan, who keys.Who) error {
	now := p.now
	stamp := now.Format(audit.TimeFormat)

	caKeys := map[*legacyCA]sealedKey{}
	for _, c := range p.cas {
		if c.online {
			k, err := e.sealKey(now, keys.PurposeCA, c.key)
			if err != nil {
				return err
			}
			caKeys[c] = k
			c.gen.KeyID = sql.NullString{String: k.id, Valid: true}
		}
	}
	leafKeys := map[string]sealedKey{}
	for _, h := range slices.Sorted(maps.Keys(p.leafKeys)) {
		k, err := e.sealKey(now, keys.PurposeLeaf, p.leafKeys[h])
		if err != nil {
			return err
		}
		leafKeys[h] = k
	}

	return e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		for _, c := range p.cas {
			if k, ok := caKeys[c]; ok {
				if err := keys.SaveKey(ctx, tx, keys.StoredKey{ID: k.id, Purpose: keys.PurposeCA, Algorithm: k.alg, Envelope: k.env}, stamp); err != nil {
					return err
				}
			}
		}
		for _, h := range slices.Sorted(maps.Keys(leafKeys)) {
			k := leafKeys[h]
			if err := keys.SaveKey(ctx, tx, keys.StoredKey{ID: k.id, Purpose: keys.PurposeLeaf, Algorithm: k.alg, Envelope: k.env}, stamp); err != nil {
				return err
			}
		}
		w := &legacyWriter{q: q, stamp: stamp, now: now, blocked: map[string]bool{}}
		revokedSource := "server"
		if !p.cas[0].online {
			revokedSource = "root_crl"
		}
		for _, c := range p.cas {
			if err := w.ca(ctx, c, p.rep.LegacyURLs, revokedSource); err != nil {
				return fmt.Errorf("CA %q: %w", c.src.Name, err)
			}
		}
		for _, lc := range p.certs {
			if err := w.cert(ctx, lc, leafKeys); err != nil {
				return fmt.Errorf("certificate %s: %w", SerialHex(lc.cert.SerialNumber), err)
			}
		}

		// The next CRL of every online CA, numbered on from pki.sh –
		// intermediates first, then an online root.
		for i := len(p.cas) - 1; i >= 0; i-- {
			c := p.cas[i]
			if !c.online || c.rep.Status != StatusActive {
				continue
			}
			crl, err := e.writeCRL(ctx, q, tx, c.row.ID, 1, c.src.Cert, func(fn func(crypto.Signer) error) error { return fn(c.key) }, ActionCAImportLegacy, who, now)
			if err != nil {
				return fmt.Errorf("CA %q: %w", c.src.Name, err)
			}
			p.rep.CRLs = append(p.rep.CRLs, *crl)
		}

		for _, c := range p.cas {
			details := map[string]any{
				"name": c.src.Name, "kind": c.rep.Kind, "key_mode": c.rep.KeyMode, "status": c.rep.Status,
				"subject": c.rep.Subject, "fingerprint": c.rep.Fingerprint, "certificates": c.rep.Certificates,
				"revoked": c.rep.Revoked, "last_crl_number": c.lastCRL, "history": len(c.history),
			}
			if err := audit.Enqueue(ctx, tx, now, audit.Entry{
				Time: now, Actor: who.Actor, Action: ActionCAImportLegacy, Target: audit.Target{Type: "ca", ID: c.row.ID},
				Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
			}); err != nil {
				return err
			}
		}
		details := map[string]any{
			"cas": len(p.cas), "certificates": p.rep.Certificates, "revoked": p.rep.Revoked, "keys": p.rep.Keys,
			"external": p.rep.External, "base_url": p.rep.BaseURL, "legacy_urls": p.rep.LegacyURLs,
		}
		if len(p.rep.Warnings) > 0 {
			details["warnings"] = capReasons(p.rep.Warnings)
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionImportLegacy, Target: audit.Target{Type: "import", ID: "legacy"},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
		})
	})
}

// legacyWriter writes the rows of one import inside its transaction.
type legacyWriter struct {
	q       *pkidb.Queries
	stamp   string
	now     time.Time
	blocked map[string]bool
}

// block puts a compromised key into blocked_keys (decision 29).
func (w *legacyWriter) block(ctx context.Context, pub crypto.PublicKey, reason, sourceType, sourceID string) error {
	if reason != "keyCompromise" && reason != "cACompromise" {
		return nil
	}
	h, err := spkiHash(pub)
	if err != nil || w.blocked[h] {
		return err
	}
	w.blocked[h] = true
	return w.q.BlockKey(ctx, pkidb.BlockKeyParams{SpkiSha256: h, Reason: reason, SourceType: sourceType, SourceID: sourceID, BlockedAt: w.stamp, BlockedBy: legacyActor})
}

func (w *legacyWriter) ca(ctx context.Context, c *legacyCA, legacyURLs bool, revokedSource string) error {
	q := w.q
	if err := q.InsertCA(ctx, *c.row); err != nil {
		return err
	}
	for _, r := range c.nc.rows {
		if err := q.InsertNameConstraint(ctx, pkidb.InsertNameConstraintParams{CaID: c.row.ID, Kind: r.kind, Value: r.value, Permitted: boolInt(r.permitted)}); err != nil {
			return err
		}
	}
	if err := q.InsertCAGeneration(ctx, c.gen); err != nil {
		return err
	}
	if err := q.SetCurrentGeneration(ctx, pkidb.SetCurrentGenerationParams{CurrentGeneration: sql.NullInt64{Int64: 1, Valid: true}, UpdatedAt: w.stamp, ID: c.row.ID}); err != nil {
		return err
	}
	if legacyURLs {
		if err := q.SetLegacyURLs(ctx, pkidb.SetLegacyURLsParams{UpdatedAt: w.stamp, ID: c.row.ID}); err != nil {
			return err
		}
	}
	if c.lastCRL > 0 {
		if err := q.SetCRLNumber(ctx, pkidb.SetCRLNumberParams{CrlNumber: c.lastCRL, UpdatedAt: w.stamp, ID: c.row.ID}); err != nil {
			return err
		}
	}
	if c.crl != nil {
		if err := q.InsertCRL(ctx, pkidb.InsertCRLParams{
			CaID: c.row.ID, Generation: 1, Number: c.crl.Number.Int64(), ThisUpdate: c.crl.ThisUpdate.UTC().Format(dbTime),
			NextUpdate: c.crl.NextUpdate.UTC().Format(dbTime), CrlDer: c.crl.Raw, Source: "uploaded", CreatedAt: w.stamp,
		}); err != nil {
			return fmt.Errorf("keep the CRL of pki.sh: %w", err)
		}
	}
	for _, h := range c.history {
		if err := q.InsertCAHistory(ctx, pkidb.InsertCAHistoryParams{
			CaID: c.row.ID, Generation: 1, SerialHex: SerialHex(h.SerialNumber), NotBefore: h.NotBefore.UTC().Format(dbTime),
			NotAfter: h.NotAfter.UTC().Format(dbTime), CertDer: h.Raw, FingerprintSha256: fingerprintHex(h.Raw), Source: "legacy", CreatedAt: w.stamp,
		}); err != nil {
			return fmt.Errorf("older certificate: %w", err)
		}
	}
	if r := c.revoked; r != nil {
		if err := q.InsertCARevocation(ctx, pkidb.InsertCARevocationParams{
			CaID: c.row.ID, Generation: 1, Reason: r.reason, RevokedAt: r.at.UTC().Format(audit.TimeFormat),
			InvalidityDate: nullTime(r.invalidity), RevokedBy: legacyActor, Source: revokedSource,
		}); err != nil {
			return err
		}
		if err := w.block(ctx, c.src.Cert.PublicKey, r.reason, "ca", c.row.ID); err != nil {
			return err
		}
	}
	return nil
}

func (w *legacyWriter) cert(ctx context.Context, lc *legacyCert, leafKeys map[string]sealedKey) error {
	id, err := ids.New("crt", w.now, nil)
	if err != nil {
		return err
	}
	cert := lc.cert
	nullable := func(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
	row := pkidb.InsertCertificateParams{
		ID: id, Source: "external", Preset: nullable(lc.preset), SerialHex: SerialHex(cert.SerialNumber),
		SubjectDn: cert.Subject.String(), CommonName: cert.Subject.CommonName,
		NotBefore: cert.NotBefore.UTC().Format(dbTime), NotAfter: cert.NotAfter.UTC().Format(dbTime),
		KeyAlgorithm: describeKey(cert.PublicKey), CertDer: cert.Raw, FingerprintSha256: fingerprintHex(cert.Raw),
		RequestedBy: legacyActor, CreatedAt: w.stamp,
	}
	if lc.ca != nil {
		row.Source = "imported"
		row.CaID = sql.NullString{String: lc.ca.row.ID, Valid: true}
		row.CaGeneration = sql.NullInt64{Int64: 1, Valid: true}
		if k, ok := leafKeys[lc.keyHash]; ok && lc.keyHash != "" {
			row.KeyID = sql.NullString{String: k.id, Valid: true}
		}
		if lc.preset == "custom" {
			row.CustomKu, row.CustomEku = sql.NullString{String: lc.custom[0], Valid: true}, sql.NullString{String: lc.custom[1], Valid: true}
		}
	}
	if err := w.q.InsertCertificate(ctx, row); err != nil {
		return err
	}
	for _, n := range certNames(cert) {
		if err := w.q.InsertCertificateSAN(ctx, pkidb.InsertCertificateSANParams{CertificateID: id, Type: n[0], Value: n[1]}); err != nil {
			return fmt.Errorf("names: %w", err)
		}
	}
	if r := lc.rev; r != nil {
		if err := w.q.InsertRevocation(ctx, pkidb.InsertRevocationParams{
			CertificateID: id, Reason: r.reason, RevokedAt: r.at.UTC().Format(audit.TimeFormat),
			InvalidityDate: nullTime(r.invalidity), RevokedBy: legacyActor,
		}); err != nil {
			return fmt.Errorf("revocation: %w", err)
		}
		if err := w.block(ctx, cert.PublicKey, r.reason, "certificate", id); err != nil {
			return err
		}
	}
	return nil
}
