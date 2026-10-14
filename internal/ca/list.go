package ca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// CAInfo describes a CA for lists and detail views (read-only).
type CAInfo struct {
	ID, Name, Kind, Status, KeyMode string
	Parent                          string // name; "" for a root
	BaseURL                         string
	CurrentGeneration               int64 // 0 = none signed yet
	PathLen                         *int64
	CRLDays, MaxValidityDays        int64
	NameConstraints                 []string // "permitted dns homelab.lan"
	NameConstraintsCritical         bool
	EKULimit                        []string // names, or OIDs for unnamed ones
	Generations                     []GenerationInfo
}

// GenerationInfo is one key and certificate of a CA.
type GenerationInfo struct {
	Generation          int64
	Current, Pending    bool
	KeyAlgorithm        string
	Subject             string
	Serial, Fingerprint string
	NotBefore, NotAfter string
	Issuer              string // "root/1"; "" for a root
	CertURL, CRLURL     string // where MyOwnPKI publishes it
	// Warnings are found in the certificate itself, e.g. AIA/CDP URLs that
	// differ from what MyOwnPKI serves (an offline-signed certificate).
	Warnings []string
}

// ListCAs reads every CA of the tenant. q may be a read connection.
func ListCAs(ctx context.Context, q pkidb.DBTX) ([]CAInfo, error) {
	db := pkidb.New(q)
	cas, err := db.ListCAs(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	byID := map[string]pkidb.Ca{}
	for _, c := range cas {
		names[c.ID] = c.Name
		byID[c.ID] = c
	}
	out := make([]CAInfo, 0, len(cas))
	for _, c := range cas {
		info := CAInfo{
			ID: c.ID, Name: c.Name, Kind: c.Kind, Status: c.Status, KeyMode: c.KeyMode, Parent: names[c.ParentID.String],
			BaseURL: c.PublicBaseUrl, CurrentGeneration: c.CurrentGeneration.Int64, CRLDays: c.CrlDays,
			MaxValidityDays: c.MaxValidityDays, NameConstraintsCritical: c.NcCritical == 1,
		}
		if c.PathLen.Valid {
			pl := c.PathLen.Int64
			info.PathLen = &pl
		}
		rows, err := db.ListNameConstraints(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			mode := "excluded"
			if r.Permitted == 1 {
				mode = "permitted"
			}
			info.NameConstraints = append(info.NameConstraints, mode+" "+r.Kind+" "+r.Value)
		}
		var limit []string
		if jerr := json.Unmarshal([]byte(c.EkuLimit), &limit); jerr == nil {
			for _, s := range limit {
				name := s
				if oid, perr := parseDottedOID(s); perr == nil && preset.ExtKeyUsageName(oid) != "" {
					name = preset.ExtKeyUsageName(oid)
				}
				info.EKULimit = append(info.EKULimit, name)
			}
		}
		gens, err := db.ListCAGenerations(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range gens {
			gi := GenerationInfo{
				Generation: g.Generation, Current: c.CurrentGeneration.Valid && g.Generation == c.CurrentGeneration.Int64,
				Pending: g.CertDer == nil, KeyAlgorithm: g.KeyAlgorithm, Subject: g.SubjectDn,
				Serial: g.SerialHex.String, Fingerprint: g.FingerprintSha256.String,
				NotBefore: g.NotBefore.String, NotAfter: g.NotAfter.String,
				CertURL: CertURL(c.PublicBaseUrl, c.Name, g.Generation), CRLURL: CRLURL(c.PublicBaseUrl, c.Name, g.Generation),
			}
			if g.IssuerCaID.Valid {
				gi.Issuer = names[g.IssuerCaID.String] + "/" + itoa(g.IssuerGeneration.Int64)
				if g.CertDer != nil {
					cert, err := x509.ParseCertificate(g.CertDer)
					if err != nil {
						return nil, fmt.Errorf("CA %q generation %d: stored certificate: %w", c.Name, g.Generation, err)
					}
					gi.Warnings = urlWarnings(cert, byID[g.IssuerCaID.String], g.IssuerGeneration.Int64)
				}
			}
			info.Generations = append(info.Generations, gi)
		}
		out = append(out, info)
	}
	return out, nil
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
