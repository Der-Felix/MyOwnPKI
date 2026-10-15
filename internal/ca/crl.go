package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// CRLs (PHASE1 step 9). Each CA generation signs the CRL for the
// certificates it issued and publishes it at its own URL. The number rises
// strictly per CA across all generations. A CRL is renewed after a third of
// its lifetime; from half of it on, a warning says the renewal didn't
// happen (sealed server, offline root that wasn't re-signed).

var (
	oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
	// issuingDistributionPoint (RFC 5280 §5.2.5): accepted in uploaded CRLs.
	// The server doesn't write it (yet): OpenSSL then refuses the CRL for
	// certificates without a CRL distribution point ("different CRL scope"),
	// e.g. legacy certificates issued without AIA_BASE_URL (PHASE1 note).
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
)

// SystemActor is who acts in background work (CRL renewal).
var SystemActor = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "crl-maintainer"}, Principal: authz.System("crl-maintainer")}

// CRLResult describes a published CRL.
type CRLResult struct {
	CA                     string
	Generation             int64
	Number                 int64
	ThisUpdate, NextUpdate time.Time
	Entries                int
	DER                    []byte
}

// crlEntry is one revoked serial as it goes into a CRL.
type crlEntry struct {
	serial     string
	reason     string
	revokedAt  string
	invalidity sql.NullString
}

// crlEntries lists what the CRL of a generation must contain. An entry stays
// until it was on a regular CRL after the certificate expired (RFC 5280
// §3.3): it is dropped only from notAfter + crl_days on.
func crlEntries(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, generation int64, now time.Time) ([]crlEntry, error) {
	cutoff := now.Add(-time.Duration(ca.CrlDays) * day).UTC().Format(dbTime)
	leaves, err := q.ListLeafCRLEntries(ctx, pkidb.ListLeafCRLEntriesParams{
		CaID: sql.NullString{String: ca.ID, Valid: true}, CaGeneration: sql.NullInt64{Int64: generation, Valid: true}, NotAfter: cutoff,
	})
	if err != nil {
		return nil, err
	}
	cas, err := q.ListCACRLEntries(ctx, pkidb.ListCACRLEntriesParams{
		IssuerCaID: sql.NullString{String: ca.ID, Valid: true}, IssuerGeneration: sql.NullInt64{Int64: generation, Valid: true},
		NotAfter: sql.NullString{String: cutoff, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	out := make([]crlEntry, 0, len(leaves)+len(cas))
	for _, r := range leaves {
		out = append(out, crlEntry{serial: r.SerialHex, reason: r.Reason, revokedAt: r.RevokedAt, invalidity: r.InvalidityDate})
	}
	for _, r := range cas {
		out = append(out, crlEntry{serial: r.SerialHex.String, reason: r.Reason, revokedAt: r.RevokedAt, invalidity: r.InvalidityDate})
	}
	return out, nil
}

// crlNeededUntil: a generation needs CRLs while it is valid, and until every
// certificate it signed has expired plus crl_days – the last entries must be
// on a regular CRL after their certificates expired (RFC 5280 §3.3).
// Imported legacy certificates may outlive their CA, so this goes by the
// latest notAfter below the generation, not only by its own.
func crlNeededUntil(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, generation int64, cert *x509.Certificate) (time.Time, error) {
	until := cert.NotAfter
	latest, err := q.LatestIssuedNotAfter(ctx, pkidb.LatestIssuedNotAfterParams{
		CaID: sql.NullString{String: ca.ID, Valid: true}, CaGeneration: sql.NullInt64{Int64: generation, Valid: true},
		IssuerCaID: sql.NullString{String: ca.ID, Valid: true}, IssuerGeneration: sql.NullInt64{Int64: generation, Valid: true},
	})
	if err != nil || latest == "" {
		return until, err
	}
	t, err := time.Parse(dbTime, latest)
	if err != nil {
		return until, fmt.Errorf("CA %q generation %d: latest notAfter %q: %w", ca.Name, generation, latest, err)
	}
	if t = t.Add(time.Duration(ca.CrlDays) * day); t.After(until) {
		until = t
	}
	return until, nil
}

// SignCRL signs a new CRL for a CA generation whose key is on the server.
// It needs ca.manage; the CRL renewal runs as the system.
func (e *Engine) SignCRL(ctx context.Context, caID string, generation int64, trigger string, who keys.Who) (*CRLResult, error) {
	return e.signCRLAs(ctx, caID, generation, trigger, who, authz.ManageCA)
}

// signCRLAs signs with the permission perm: a revocation publishes its CRL
// with certificate.revoke – whoever may revoke must be able to make the
// revocation effective, without managing the CA.
func (e *Engine) signCRLAs(ctx context.Context, caID string, generation int64, trigger string, who keys.Who, perm authz.Permission) (*CRLResult, error) {
	now := e.now()
	out, err := e.signCRL(ctx, caID, generation, trigger, who, perm, now)
	if err != nil {
		if aerr := e.refuse(ctx, now, ActionCRLSign, who, audit.Target{Type: "ca", ID: caID},
			map[string]any{"generation": generation, "trigger": trigger}, err); aerr != nil {
			return nil, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
		return nil, err
	}
	return out, nil
}

func (e *Engine) signCRL(ctx context.Context, caID string, generation int64, trigger string, who keys.Who, perm authz.Permission, now time.Time) (*CRLResult, error) {
	q := pkidb.New(e.PKI)
	ca, err := q.GetCA(ctx, caID)
	if err != nil {
		return nil, err
	}
	if aerr := e.authorize(who, perm, ca.Name, now); aerr != nil {
		return nil, aerr
	}
	if e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: caID, Generation: generation})
	if err != nil {
		return nil, err
	}
	switch {
	case gen.CertDer == nil:
		return nil, deny("CA %q generation %d has no certificate yet", ca.Name, generation)
	case ca.KeyMode != KeyModeOnlineEncrypted || !gen.KeyID.Valid:
		return nil, deny("the key of CA %q is not on this server – its CRL is signed offline and uploaded", ca.Name)
	}
	cert, err := x509.ParseCertificate(gen.CertDer)
	if err != nil {
		return nil, fmt.Errorf("CA %q generation %d: stored certificate: %w", ca.Name, generation, err)
	}
	until, err := crlNeededUntil(ctx, q, ca, generation, cert)
	if err != nil {
		return nil, err
	}
	if !now.Before(until) {
		return nil, deny("CA %q generation %d needs no CRL any more – it and every certificate it signed expired more than %d days (crl_days) ago",
			ca.Name, generation, ca.CrlDays)
	}
	entries, err := crlEntries(ctx, q, ca, generation, now)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.RevocationList{
		ThisUpdate: now.Add(-Backdate),
		NextUpdate: now.Add(time.Duration(ca.CrlDays) * day),
	}
	if tmpl.ThisUpdate.Before(cert.NotBefore) {
		tmpl.ThisUpdate = cert.NotBefore
	}
	if tmpl.SignatureAlgorithm, err = signatureAlgorithm(cert.PublicKey); err != nil {
		return nil, err
	}
	for _, en := range entries {
		entry, eerr := revocationEntry(en)
		if eerr != nil {
			return nil, eerr
		}
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, entry)
	}

	key, err := keys.LoadKey(ctx, e.PKI, gen.KeyID.String)
	if err != nil {
		return nil, err
	}
	out := &CRLResult{CA: ca.Name, Generation: generation, ThisUpdate: tmpl.ThisUpdate, NextUpdate: tmpl.NextUpdate, Entries: len(entries)}
	stamp := now.Format(audit.TimeFormat)
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		// The number is taken inside the transaction: the single writer
		// makes it strictly increasing even with concurrent revocations.
		maxNo, terr := q.MaxCRLNumber(ctx, ca.ID)
		if terr != nil {
			return terr
		}
		current, terr := q.GetCA(ctx, ca.ID)
		if terr != nil {
			return terr
		}
		out.Number = max(maxNo, current.CrlNumber) + 1
		tmpl.Number = big.NewInt(out.Number)
		terr = e.Keys.WithSigner(key.ID, key.Purpose, key.Algorithm, key.Envelope, func(s crypto.Signer) error {
			if !publicKeyEqual(s.Public(), cert.PublicKey) {
				return fmt.Errorf("CA %q: key %s doesn't belong to generation %d", ca.Name, key.ID, generation)
			}
			var serr error
			out.DER, serr = x509.CreateRevocationList(e.rand(), tmpl, cert, s)
			return serr
		})
		if terr != nil {
			return fmt.Errorf("sign CRL: %w", terr)
		}
		if _, terr = x509.ParseRevocationList(out.DER); terr != nil {
			return fmt.Errorf("signed CRL doesn't parse: %w", terr)
		}
		if terr = q.InsertCRL(ctx, pkidb.InsertCRLParams{
			CaID: ca.ID, Generation: generation, Number: out.Number, ThisUpdate: tmpl.ThisUpdate.UTC().Format(dbTime),
			NextUpdate: tmpl.NextUpdate.UTC().Format(dbTime), CrlDer: out.DER, Source: "signed", CreatedAt: stamp,
		}); terr != nil {
			return terr
		}
		if terr = q.SetCRLNumber(ctx, pkidb.SetCRLNumberParams{CrlNumber: out.Number, UpdatedAt: stamp, ID: ca.ID}); terr != nil {
			return terr
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionCRLSign, Target: audit.Target{Type: "ca", ID: ca.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{
				"name": ca.Name, "generation": generation, "number": out.Number, "entries": len(entries),
				"next_update": tmpl.NextUpdate.UTC().Format(dbTime), "trigger": trigger,
			},
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func revocationEntry(en crlEntry) (x509.RevocationListEntry, error) {
	serial, ok := new(big.Int).SetString(en.serial, 16)
	if !ok {
		return x509.RevocationListEntry{}, fmt.Errorf("revoked serial %q is not hex", en.serial)
	}
	at, err := time.Parse(audit.TimeFormat, en.revokedAt)
	if err != nil {
		return x509.RevocationListEntry{}, err
	}
	// "unspecified" (0) is written without a reasonCode extension, as the
	// CA/B Forum requires; crypto/x509 omits a zero ReasonCode.
	entry := x509.RevocationListEntry{SerialNumber: serial, RevocationTime: at.Truncate(time.Second), ReasonCode: reasonCodes[en.reason]}
	if en.invalidity.Valid {
		t, err := time.Parse(time.RFC3339, en.invalidity.String)
		if err != nil {
			return entry, err
		}
		v, err := asn1.MarshalWithParams(t.UTC(), "generalized")
		if err != nil {
			return entry, err
		}
		entry.ExtraExtensions = append(entry.ExtraExtensions, pkix.Extension{Id: oidInvalidityDate, Value: v})
	}
	return entry, nil
}

// LegacyCRLURL and LegacyCertURL are the URLs legacy pki.sh wrote into its
// certificates (AIA_BASE_URL/<name>.crl|.crt).
func LegacyCRLURL(baseURL, name string) string  { return baseURL + "/" + name + ".crl" }
func LegacyCertURL(baseURL, name string) string { return baseURL + "/" + name + ".crt" }

// CRL states, worst last.
const (
	CRLOK       = "ok"
	CRLRenewDue = "renew_due" // a third of the lifetime has passed: the maintainer renews it
	CRLWarning  = "warning"   // half has passed: the renewal didn't happen
	CRLExpired  = "expired"   // past nextUpdate: clients that check revocation fail
	CRLMissing  = "missing"   // never published
)

// CRLStatus describes the newest CRL of one CA generation.
type CRLStatus struct {
	CA                     string
	Generation             int64
	KeyMode                string
	Number                 int64
	Source                 string
	ThisUpdate, NextUpdate time.Time
	State                  string
	// Unpublished counts revocations not on the newest CRL yet: they take
	// effect only once a CRL lists them.
	Unpublished int
}

// Message says what an admin should know, "" when all is well.
func (s CRLStatus) Message(sealed bool) string {
	var msg string
	switch s.State {
	case CRLMissing:
		msg = "no CRL published yet"
		if s.KeyMode == KeyModeOffline {
			msg += " – sign it on the offline root and upload it"
		}
	case CRLWarning:
		msg = fmt.Sprintf("CRL #%d expires on %s and was not renewed", s.Number, s.NextUpdate.UTC().Format("2006-01-02 15:04 UTC"))
		if s.KeyMode == KeyModeOffline {
			msg += " – sign a new one on the offline root and upload it"
		}
	case CRLExpired:
		msg = fmt.Sprintf("CRL #%d EXPIRED on %s – clients that check revocation reject certificates below this CA", s.Number, s.NextUpdate.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if s.Unpublished > 0 {
		if msg != "" {
			msg += "; "
		}
		msg += fmt.Sprintf("%d revocation(s) not yet published in a CRL – a revocation takes effect only with the CRL", s.Unpublished)
	}
	if sealed && msg != "" && s.KeyMode == KeyModeOnlineEncrypted {
		msg += " (the server is sealed – unseal it to sign the CRL)"
	}
	return msg
}

// CRLStatuses reports every CA generation that needs a CRL (signed, and see
// crlNeededUntil). q may be a read connection.
func CRLStatuses(ctx context.Context, q pkidb.DBTX, now time.Time) ([]CRLStatus, error) {
	db := pkidb.New(q)
	gens, err := db.ListSignedGenerations(ctx)
	if err != nil {
		return nil, err
	}
	cas := map[string]pkidb.Ca{}
	var out []CRLStatus
	for _, g := range gens {
		ca, ok := cas[g.CaID]
		if !ok {
			if ca, err = db.GetCA(ctx, g.CaID); err != nil {
				return nil, err
			}
			cas[g.CaID] = ca
		}
		cert, err := x509.ParseCertificate(g.CertDer)
		if err != nil {
			return nil, fmt.Errorf("CA %q generation %d: stored certificate: %w", ca.Name, g.Generation, err)
		}
		until, err := crlNeededUntil(ctx, db, ca, g.Generation, cert)
		if err != nil {
			return nil, err
		}
		if !now.Before(until) {
			continue
		}
		st, err := crlStatus(ctx, db, ca, g.Generation, now)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

func crlStatus(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, generation int64, now time.Time) (CRLStatus, error) {
	st := CRLStatus{CA: ca.Name, Generation: generation, KeyMode: ca.KeyMode, State: CRLMissing}
	want, err := crlEntries(ctx, q, ca, generation, now)
	if err != nil {
		return st, err
	}
	latest, err := q.GetLatestCRL(ctx, pkidb.GetLatestCRLParams{CaID: ca.ID, Generation: generation})
	if errors.Is(err, sql.ErrNoRows) {
		st.Unpublished = len(want)
		return st, nil
	}
	if err != nil {
		return st, err
	}
	crl, err := x509.ParseRevocationList(latest.CrlDer)
	if err != nil {
		return st, fmt.Errorf("CA %q generation %d: stored CRL #%d: %w", ca.Name, generation, latest.Number, err)
	}
	listed := map[string]bool{}
	for _, r := range crl.RevokedCertificateEntries {
		listed[SerialHex(r.SerialNumber)] = true
	}
	for _, w := range want {
		if !listed[w.serial] {
			st.Unpublished++
		}
	}
	st.Number, st.Source, st.ThisUpdate, st.NextUpdate = latest.Number, latest.Source, crl.ThisUpdate, crl.NextUpdate
	st.State = crlState(crl.ThisUpdate, crl.NextUpdate, now, ca.KeyMode == KeyModeOnlineEncrypted)
	return st, nil
}

// crlState: renew after a third, warn from half, expired after nextUpdate.
func crlState(this, next, now time.Time, renewable bool) string {
	life := next.Sub(this)
	elapsed := now.Sub(this)
	switch {
	case !now.Before(next):
		return CRLExpired
	case elapsed*2 >= life:
		return CRLWarning
	case renewable && elapsed*3 >= life:
		return CRLRenewDue
	}
	return CRLOK
}

// RenewCRLs signs a new CRL for every generation with an online key whose
// CRL is missing, past a third of its lifetime or lacks a revocation. It
// runs on a timer and at unseal (wired with the server, step 12). While
// sealed it does nothing and returns keys.ErrSealed.
func (e *Engine) RenewCRLs(ctx context.Context, trigger string) ([]CRLResult, error) {
	if e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	now := e.now()
	statuses, err := CRLStatuses(ctx, e.PKI, now)
	if err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	var out []CRLResult
	var errs []error
	for _, st := range statuses {
		if st.KeyMode != KeyModeOnlineEncrypted || (st.State == CRLOK && st.Unpublished == 0) {
			e.logCRL(st)
			continue
		}
		ca, err := q.GetCAByName(ctx, st.CA)
		if err != nil {
			return out, err
		}
		res, err := e.SignCRL(ctx, ca.ID, st.Generation, trigger, SystemActor)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, *res)
		if e.Log != nil {
			e.Log.InfoContext(ctx, "crl signed", slog.String("ca", res.CA), slog.Int64("generation", res.Generation),
				slog.Int64("number", res.Number), slog.Int("entries", res.Entries), slog.Time("next_update", res.NextUpdate), slog.String("trigger", trigger))
		}
	}
	return out, errors.Join(errs...)
}

// logCRL writes a warning for CRLs nobody can renew here (offline roots).
func (e *Engine) logCRL(st CRLStatus) {
	if e.Log == nil {
		return
	}
	if msg := st.Message(false); msg != "" {
		e.Log.Warn("crl attention", slog.String("ca", st.CA), slog.Int64("generation", st.Generation), slog.String("state", st.State), slog.String("detail", msg))
	}
}
