package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// ACME Renewal Information (RFC 9773, PHASE2 step 12): a client asks when
// to renew a certificate. The window opens at 2/3 of the lifetime, shifted
// per certificate by up to 1/30 of the lifetime (so certificates issued
// together don't all renew in the same hour), and is 1/10 of the lifetime
// wide – for 90 days: from day 60–63 to day 69–72. The client picks a
// random moment inside. A revoked certificate gets a window in the past:
// renew now.

// ariRetryAfter: how often a client should ask again (RFC 9773 §4.3).
const ariRetryAfter = 6 * time.Hour

// renewalWindow is the suggested window of a certificate.
func renewalWindow(notBefore, notAfter time.Time, serial *big.Int) (time.Time, time.Time) {
	life := notAfter.Sub(notBefore)
	sum := sha256.Sum256(serial.Bytes())
	var shift time.Duration
	if most := life / 30; most > 0 {
		shift = time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(most)) // #nosec G115 -- most > 0
	}
	start := notBefore.Add(life*2/3 + shift).Truncate(time.Second)
	return start, start.Add(life / 10).Truncate(time.Second)
}

// ariID is the certificate identifier of RFC 9773 §4.1: the issuer's key
// ID and the serial's DER bytes, both base64url.
func ariID(cert *x509.Certificate) string {
	b := cert.SerialNumber.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(b)
}

// parseARIID reads a certificate identifier; the serial must be the
// minimal DER encoding of a positive number.
func parseARIID(id string) ([]byte, *big.Int, error) {
	bad := problemErr(http.StatusBadRequest, "malformed", "the certificate identifier must be base64url(authority key ID) \".\" base64url(serial) (RFC 9773 §4.1)")
	aki64, serial64, ok := strings.Cut(id, ".")
	if !ok || strings.Contains(serial64, ".") || len(id) > 200 {
		return nil, nil, bad
	}
	dec := base64.RawURLEncoding.Strict()
	aki, err := dec.DecodeString(aki64)
	if err != nil || len(aki) == 0 {
		return nil, nil, bad
	}
	sb, err := dec.DecodeString(serial64)
	if err != nil || len(sb) == 0 || len(sb) > 21 || sb[0]&0x80 != 0 || (len(sb) > 1 && sb[0] == 0 && sb[1]&0x80 == 0) {
		return nil, nil, bad
	}
	return aki, new(big.Int).SetBytes(sb), nil
}

// certByARIID finds a certificate of this PKI; nil without an error =
// unknown.
func (s *Server) certByARIID(ctx context.Context, id string) (*pkidb.Certificate, *x509.Certificate, error) {
	aki, serial, err := parseARIID(id)
	if err != nil {
		return nil, nil, err
	}
	rows, err := pkidb.New(s.db).ListCertificatesBySerial(ctx, ca.SerialHex(serial))
	if err != nil {
		return nil, nil, err
	}
	for i := range rows {
		if !rows[i].CaID.Valid {
			continue // external certificates: not ours to advise on
		}
		cert, perr := x509.ParseCertificate(rows[i].CertDer)
		if perr == nil && bytes.Equal(cert.AuthorityKeyId, aki) {
			return &rows[i], cert, nil
		}
	}
	return nil, nil, nil
}

// renewalInfo: GET, no signature (RFC 9773 §4.2).
func (s *Server) renewalInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	row, cert, err := s.certByARIID(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if row == nil {
		s.fail(w, r, problemErr(http.StatusNotFound, "malformed", "this server did not issue that certificate"))
		return
	}
	start, end := renewalWindow(cert.NotBefore, cert.NotAfter, cert.SerialNumber)
	if _, rerr := pkidb.New(s.db).GetRevocation(ctx, row.ID); rerr == nil {
		now := s.now()
		start, end = now.Add(-2*time.Hour), now.Add(-time.Hour)
	} else if !errors.Is(rerr, sql.ErrNoRows) {
		s.fail(w, r, rerr)
		return
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(ariRetryAfter/time.Second)))
	s.reply(w, http.StatusOK, map[string]any{"suggestedWindow": map[string]string{
		"start": start.UTC().Format(time.RFC3339), "end": end.UTC().Format(time.RFC3339),
	}})
}

// checkReplaces: the certificate a new order replaces must belong to an
// order of the same account, share a name with the new order and not be
// replaced by another live order (RFC 9773 §5). It returns the
// certificate's ID.
func (s *Server) checkReplaces(ctx context.Context, accountID, id string, idents []identifier) (string, error) {
	row, cert, err := s.certByARIID(ctx, id)
	if err != nil {
		return "", err
	}
	// One answer for unknown and foreign: no probing of other accounts.
	notYours := problemErr(http.StatusBadRequest, "malformed", "\"replaces\" names no certificate of this account")
	if row == nil {
		return "", notYours
	}
	q := pkidb.New(s.db)
	o, err := q.GetACMEOrderByCertificate(ctx, sql.NullString{String: row.ID, Valid: true})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && o.AccountID != accountID) {
		return "", notYours
	}
	if err != nil {
		return "", err
	}
	old := map[string]bool{}
	for _, n := range cert.DNSNames {
		old["dns:"+strings.ToLower(n)] = true
	}
	for _, ip := range cert.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			old["ip:"+a.Unmap().String()] = true
		}
	}
	shared := false
	for _, i := range idents {
		shared = shared || old[i.key()]
	}
	if !shared {
		return "", problemErr(http.StatusBadRequest, "malformed", "the order shares no name with the certificate it replaces")
	}
	n, err := q.CountACMEOrdersReplacing(ctx, sql.NullString{String: row.ID, Valid: true})
	if err != nil {
		return "", err
	}
	if n > 0 {
		return "", problemErr(http.StatusConflict, "alreadyReplaced", "another order replaces this certificate already")
	}
	return row.ID, nil
}
