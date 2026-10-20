package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// CheckSANIndex compares certificate_sans with the names inside every
// certificate (restore check, PHASE1 step 16). Search, the expiry views and
// later ACME look names up in the index; a row that doesn't match its
// certificate would hide or invent a certificate. It returns one problem per
// certificate that doesn't match (at most limit) and the number checked.
func CheckSANIndex(ctx context.Context, db pkidb.DBTX, limit int) (problems []string, checked int, err error) {
	q := pkidb.New(db)
	after := ""
	for {
		rows, lerr := q.ListCertificateDERs(ctx, pkidb.ListCertificateDERsParams{ID: after, Limit: 500})
		if lerr != nil {
			return problems, checked, fmt.Errorf("SAN index: %w", lerr)
		}
		for _, r := range rows {
			after = r.ID
			checked++
			if p := checkOneSANIndex(ctx, q, r); p != "" && len(problems) < limit {
				problems = append(problems, p)
			}
		}
		if len(rows) < 500 {
			return problems, checked, nil
		}
	}
}

func checkOneSANIndex(ctx context.Context, q *pkidb.Queries, r pkidb.ListCertificateDERsRow) string {
	cert, err := x509.ParseCertificate(r.CertDer)
	if err != nil {
		return fmt.Sprintf("certificate %s (serial %s) can't be parsed: %v", r.ID, r.SerialHex, err)
	}
	rows, err := q.ListCertificateSANs(ctx, r.ID)
	if err != nil {
		return fmt.Sprintf("certificate %s: %v", r.ID, err)
	}
	var stored []string
	for _, s := range rows {
		stored = append(stored, normSAN(s.Type, s.Value))
	}
	var inCert []string
	for _, n := range certNames(cert) {
		inCert = append(inCert, normSAN(n[0], n[1]))
	}
	slices.Sort(stored)
	stored = slices.Compact(stored)
	slices.Sort(inCert)
	inCert = slices.Compact(inCert)
	if !slices.Equal(stored, inCert) {
		return fmt.Sprintf("certificate %s (serial %s): the name index has [%s], the certificate [%s]",
			r.ID, r.SerialHex, capText(strings.Join(stored, " "), 300), capText(strings.Join(inCert, " "), 300))
	}
	return ""
}

// normSAN compares names like clients do: DNS names and e-mail domains
// without case, IP addresses in canonical form.
func normSAN(typ, v string) string {
	switch typ {
	case "dns":
		v = strings.ToLower(v)
	case "ip":
		if a, err := netip.ParseAddr(v); err == nil {
			v = a.Unmap().String()
		}
	case "email":
		if at := strings.LastIndex(v, "@"); at >= 0 {
			v = v[:at] + strings.ToLower(v[at:])
		}
	}
	return typ + ":" + v
}
