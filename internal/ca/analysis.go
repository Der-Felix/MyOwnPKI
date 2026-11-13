package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Read paths of the analysis (docs/PHASE3.md section 14, step 46). Like the
// report reads they keep the CA scoping of CertificateCounts and leave out
// agent identity certificates.

// Key algorithm families of Traits.
const (
	TraitRSA     = "rsa"
	TraitECDSA   = "ecdsa"
	TraitEd25519 = "ed25519"
	TraitOther   = "other"
)

// Traits are the properties of a certificate that only its DER holds. They
// are read through CertificateTraits, not through CertificateInfo, so list
// pages never parse DER.
type Traits struct {
	// KeyAlgorithm is a Trait* constant. KeyBits is the RSA modulus size or
	// the curve size, 0 for Ed25519 and unknown keys.
	KeyAlgorithm string
	KeyBits      int
	// Signature is how the issuer signed it; UnknownSignatureAlgorithm if
	// Go does not know the algorithm.
	Signature x509.SignatureAlgorithm
}

// TraitsOf parses a DER certificate. It reads, it does not verify: an
// unknown signature algorithm or a weak key is a result, not an error. Go
// refuses to sign with SHA-1 or MD5 and to generate short RSA keys, but it
// parses such certificates, which is what an import brings in.
func TraitsOf(der []byte) (Traits, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Traits{}, fmt.Errorf("parse certificate: %w", err)
	}
	t := Traits{Signature: cert.SignatureAlgorithm, KeyAlgorithm: TraitOther}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		t.KeyAlgorithm, t.KeyBits = TraitRSA, pub.N.BitLen()
	case *ecdsa.PublicKey:
		t.KeyAlgorithm, t.KeyBits = TraitECDSA, pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		t.KeyAlgorithm = TraitEd25519
	}
	return t, nil
}

// CertificateTraits parses the certificates that are valid now (not revoked,
// not expired; agent identity certificates left out) of the CAs who may read
// and returns their traits by certificate ID. A certificate whose DER does
// not parse is missing from the map: the caller says "unknown", not "fine".
// The work grows with the number of valid certificates; the analysis cache
// keeps the result for a minute.
func (e *Engine) CertificateTraits(ctx context.Context, who keys.Who) (map[string]Traits, error) {
	return e.certificateTraits(ctx, who, traitsPageSize)
}

func (e *Engine) certificateTraits(ctx context.Context, who keys.Who, pageSize int64) (map[string]Traits, error) {
	now := e.now()
	q := pkidb.New(e.PKI)
	may, err := e.readableCAs(ctx, q, who, now)
	if err != nil {
		return nil, err
	}
	// The DER is read in pages by ID, so memory holds one page of DER at a
	// time and the map of the small results.
	out := map[string]Traits{}
	after := ""
	for {
		rows, err := q.ListValidCertificateDERs(ctx, pkidb.ListValidCertificateDERsParams{Now: now.Format(dbTime), AfterID: after, PageSize: pageSize})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if !may(r.CaID.String) {
				continue
			}
			if t, perr := TraitsOf(r.CertDer); perr == nil {
				out[r.ID] = t
			}
		}
		if int64(len(rows)) < pageSize {
			return out, nil
		}
		after = rows[len(rows)-1].ID
	}
}

// traitsPageSize is how many certificates CertificateTraits reads at once.
const traitsPageSize int64 = 500

// Origin tells which source issued a certificate (docs/PHASE3.md D6).
type Origin struct {
	// Class is SourceUI, SourceACME or SourceAgent.
	Class string
	// Key identifies the issuing party: "ui" for every UI or API issuance,
	// "acme:<account ID>" or "agent:<agent ID>". IDs are server-made.
	Key string
}

// CertificateOrigins returns the origin of every certificate of source
// "issued" that who may read, by certificate ID. Imported and external
// certificates have none and are not in the map.
func (e *Engine) CertificateOrigins(ctx context.Context, who keys.Who) (map[string]Origin, error) {
	q := pkidb.New(e.PKI)
	may, err := e.readableCAs(ctx, q, who, e.now())
	if err != nil {
		return nil, err
	}
	rows, err := q.CertificateOrigins(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Origin, len(rows))
	for _, r := range rows {
		if !may(r.CaID.String) {
			continue
		}
		switch {
		case r.AgentID != "":
			out[r.ID] = Origin{Class: SourceAgent, Key: "agent:" + r.AgentID}
		case r.AccountID != "":
			out[r.ID] = Origin{Class: SourceACME, Key: "acme:" + r.AccountID}
		default:
			out[r.ID] = Origin{Class: SourceUI, Key: "ui"}
		}
	}
	return out, nil
}

// CertName is a DNS name or an IP a certificate was issued for.
type CertName struct {
	Type  string // "dns" or "ip"
	Value string // as stored: the names of a CSR are attacker input
}

// CertificateNames returns the distinct DNS names and IPs of every
// certificate, whatever its status, that who may read (agent identity
// certificates left out), sorted by type and value.
func (e *Engine) CertificateNames(ctx context.Context, who keys.Who) ([]CertName, error) {
	q := pkidb.New(e.PKI)
	may, err := e.readableCAs(ctx, q, who, e.now())
	if err != nil {
		return nil, err
	}
	rows, err := q.CertificateNames(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[CertName]bool{}
	out := make([]CertName, 0, len(rows))
	for _, r := range rows {
		n := CertName{Type: r.Type, Value: r.Value}
		if !may(r.CaID.String) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// MaxActivityAccounts bounds ACMEAccountActivity: the newest accounts are read.
const MaxActivityAccounts = 5000

// AccountActivity is an ACME account with the time of its newest order. It
// holds no contact and no key: nothing the page would have to escape but IDs.
type AccountActivity struct {
	ID, Status string
	// AgentLinked: the account belongs to an agent.
	AgentLinked bool
	CreatedAt   time.Time
	// LastOrderAt is the creation of the newest order; zero = never ordered.
	LastOrderAt time.Time
}

// ACMEAccountActivity lists the newest ACME accounts (at most
// MaxActivityAccounts) with their last order, for the analysis. truncated is
// true when there are older accounts that were not read: whoever judges
// "no order for 90 days" must then say so for the rest. Accounts belong to no
// CA, so like the ACME pages it needs a tenant-wide role.
func (e *Engine) ACMEAccountActivity(ctx context.Context, who keys.Who) (accounts []AccountActivity, truncated bool, err error) {
	if aerr := e.authorize(who, authz.ReadPKI, "", e.now()); aerr != nil {
		return nil, false, aerr
	}
	// One more than the bound tells whether there are older accounts.
	rows, err := pkidb.New(e.PKI).ListACMEAccountActivity(ctx, MaxActivityAccounts+1)
	if err != nil {
		return nil, false, err
	}
	if len(rows) > MaxActivityAccounts {
		rows, truncated = rows[:MaxActivityAccounts], true
	}
	out := make([]AccountActivity, 0, len(rows))
	for _, r := range rows {
		created, err := time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil {
			return nil, false, fmt.Errorf("ACME account %s created_at %q: %w", r.ID, r.CreatedAt, err)
		}
		a := AccountActivity{ID: r.ID, Status: r.Status, AgentLinked: r.AgentID != "", CreatedAt: created.UTC()}
		if r.LastOrderAt != "" {
			last, err := time.Parse(time.RFC3339, r.LastOrderAt)
			if err != nil {
				return nil, false, fmt.Errorf("ACME account %s order time %q: %w", r.ID, r.LastOrderAt, err)
			}
			a.LastOrderAt = last.UTC()
		}
		out = append(out, a)
	}
	return out, truncated, nil
}
