package ca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Key modes (cas.key_mode, ADR-09).
const (
	KeyModeOffline         = "offline"
	KeyModeOnlineEncrypted = "online_encrypted"
	KeyModeHSM             = "hsm"
)

// CA statuses (cas.status).
const (
	StatusActive           = "active"
	StatusPendingSignature = "pending_signature"
	StatusRetired          = "retired"
)

// maxChainDepth stops a loop in corrupted issuer references.
const maxChainDepth = 8

// issuer is the CA generation that signs, with its chain up to the root.
type issuer struct {
	ca          pkidb.Ca
	gen         pkidb.CaGeneration
	certs       []*x509.Certificate // issuing CA first, root last
	constraints []caConstraints     // same order
}

// CertURL is the AIA "caIssuers" URL of a CA generation.
func CertURL(baseURL, caName string, generation int64) string {
	return strings.TrimRight(baseURL, "/") + "/ca/" + caName + "/" + strconv.FormatInt(generation, 10) + ".crt"
}

// CRLURL is the CRL distribution point of a CA generation.
func CRLURL(baseURL, caName string, generation int64) string {
	return strings.TrimRight(baseURL, "/") + "/crl/" + caName + "/" + strconv.FormatInt(generation, 10) + ".crl"
}

// loadIssuer reads the CA by name, its current generation and every parent
// generation up to the root. Problems an admin can fix are denials.
func loadIssuer(ctx context.Context, q *pkidb.Queries, name string) (*issuer, error) {
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, deny("there is no CA named %q", short(name))
	}
	if err != nil {
		return nil, fmt.Errorf("load CA %q: %w", name, err)
	}
	switch {
	case ca.Status != StatusActive:
		return nil, deny("CA %q is %s, not active", name, ca.Status)
	case ca.KeyMode == KeyModeOffline:
		return nil, deny("the key of CA %q is offline – it can't sign on this server", name)
	case ca.KeyMode != KeyModeOnlineEncrypted:
		return nil, deny("CA %q uses key mode %q, which this build can't use", name, ca.KeyMode)
	case !ca.CurrentGeneration.Valid:
		return nil, deny("CA %q has no signed certificate yet", name)
	}

	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: ca.ID, Generation: ca.CurrentGeneration.Int64})
	if err != nil {
		return nil, fmt.Errorf("load CA %q generation %d: %w", name, ca.CurrentGeneration.Int64, err)
	}
	certs, constraints, err := loadChain(ctx, q, ca, gen)
	if err != nil {
		return nil, err
	}
	return &issuer{ca: ca, gen: gen, certs: certs, constraints: constraints}, nil
}

// loadChain returns certificates and constraints from the signed generation
// gen of ca up to the root: gen first, root last.
func loadChain(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca, gen pkidb.CaGeneration) ([]*x509.Certificate, []caConstraints, error) {
	var certs []*x509.Certificate
	var constraints []caConstraints
	row := ca
	for depth := 0; ; depth++ {
		if depth == maxChainDepth {
			return nil, nil, fmt.Errorf("CA %q: chain is longer than %d – issuer references are broken", ca.Name, maxChainDepth)
		}
		if gen.CertDer == nil {
			return nil, nil, deny("CA %q generation %d has no certificate yet", row.Name, gen.Generation)
		}
		cert, err := x509.ParseCertificate(gen.CertDer)
		if err != nil {
			return nil, nil, fmt.Errorf("CA %q generation %d: stored certificate: %w", row.Name, gen.Generation, err)
		}
		if rerr := checkNotRevoked(ctx, q, row, gen); rerr != nil {
			return nil, nil, rerr
		}
		cc, err := loadConstraints(ctx, q, row)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		constraints = append(constraints, cc)
		if !gen.IssuerCaID.Valid {
			return certs, constraints, nil
		}
		parentGen := gen.IssuerGeneration.Int64
		if row, err = q.GetCA(ctx, gen.IssuerCaID.String); err != nil {
			return nil, nil, fmt.Errorf("load parent CA %s: %w", gen.IssuerCaID.String, err)
		}
		if gen, err = q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: row.ID, Generation: parentGen}); err != nil {
			return nil, nil, fmt.Errorf("load CA %q generation %d: %w", row.Name, parentGen, err)
		}
	}
}

func loadConstraints(ctx context.Context, q *pkidb.Queries, ca pkidb.Ca) (caConstraints, error) {
	cc := caConstraints{ca: ca.Name}
	rows, err := q.ListNameConstraints(ctx, ca.ID)
	if err != nil {
		return cc, fmt.Errorf("load name constraints of CA %q: %w", ca.Name, err)
	}
	for _, r := range rows {
		cc.names = append(cc.names, constraint{kind: r.Kind, value: r.Value, permitted: r.Permitted == 1})
	}
	var limit []string
	if err := json.Unmarshal([]byte(ca.EkuLimit), &limit); err != nil {
		return cc, fmt.Errorf("CA %q: eku_limit: %w", ca.Name, err)
	}
	for _, s := range limit {
		oid, err := parseDottedOID(s)
		if err != nil {
			return cc, fmt.Errorf("CA %q: eku_limit: %w", ca.Name, err)
		}
		cc.ekuLimit = append(cc.ekuLimit, oid)
	}
	return cc, nil
}

func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%q is not a dotted OID", s)
		}
		oid[i] = n
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("%q is not a dotted OID", s)
	}
	return oid, nil
}
