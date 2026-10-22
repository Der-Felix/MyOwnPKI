package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// finalize (RFC 8555 §7.4): the CSR must name exactly the order's
// identifiers. The CSR is stored and the order becomes "processing"; the
// certificate is issued at once – or, while the server is sealed, at the
// unseal (owner 2026-10-22). The client polls the order either way.
func (s *Server) finalize(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	ctx := r.Context()
	o, err := s.ownOrder(ctx, req, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch o.Status {
	case "processing", "valid":
		s.replyOrder(w, ctx, o) // finalize again: the state as it is
		return
	case "ready":
	default:
		s.fail(w, r, problemErr(http.StatusForbidden, "orderNotReady", "the order is %s – every authorization must be valid first", o.Status))
		return
	}
	var in struct {
		CSR string `json:"csr"`
	}
	if perr := payload(req, &in); perr != nil {
		s.fail(w, r, perr)
		return
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(in.CSR)
	if err != nil {
		s.fail(w, r, problemErr(http.StatusBadRequest, "badCSR", "csr is not base64url DER"))
		return
	}
	if cerr := s.checkCSR(o, der, req.key.Public()); cerr != nil {
		s.invalidate(ctx, o, cerr)
		s.fail(w, r, cerr)
		return
	}
	n, err := pkidb.New(s.db).SetACMEOrderProcessing(ctx, pkidb.SetACMEOrderProcessingParams{CsrDer: der, UpdatedAt: dbTime(s.now()), ID: o.ID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if n == 1 {
		s.issue(ctx, o.ID)
	}
	o, err = s.loadOrder(ctx, o.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.replyOrder(w, ctx, o)
}

func (s *Server) replyOrder(w http.ResponseWriter, ctx context.Context, o *pkidb.AcmeOrder) {
	if o.Status == "processing" {
		w.Header().Set("Retry-After", "30")
	}
	w.Header().Set("Location", s.url("/order/"+o.ID))
	s.reply(w, http.StatusOK, s.orderJSON(ctx, o))
}

// checkCSR: a valid signature, exactly the order's names (DNS names and
// IPs, a CN only if it is one of them), no other names, and not the
// account's own key (RFC 8555 §11.1). Key policy and extensions are the
// engine's: the CSR's extensions are never copied.
func (s *Server) checkCSR(o *pkidb.AcmeOrder, der []byte, accountKey any) error {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return problemErr(http.StatusBadRequest, "badCSR", "the CSR doesn't parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return problemErr(http.StatusBadRequest, "badCSR", "the CSR's signature doesn't verify")
	}
	var idents []identifier
	if err := json.Unmarshal([]byte(o.Identifiers), &idents); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, id := range idents {
		want[id.key()] = true
	}
	got := map[string]bool{}
	for _, d := range csr.DNSNames {
		got["dns:"+strings.ToLower(d)] = true
	}
	for _, ip := range csr.IPAddresses {
		a, _ := netip.AddrFromSlice(ip)
		got["ip:"+a.Unmap().String()] = true
	}
	if len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return problemErr(http.StatusBadRequest, "badCSR", "the CSR names e-mail addresses or URIs – only the order's DNS names and IPs")
	}
	if cn := csr.Subject.CommonName; cn != "" {
		key := "dns:" + strings.ToLower(cn)
		if a, perr := netip.ParseAddr(cn); perr == nil {
			key = "ip:" + a.Unmap().String()
		}
		if !want[key] {
			return problemErr(http.StatusBadRequest, "badCSR", "the CSR's common name %q is not an identifier of the order", clip(cn))
		}
		got[key] = true
	}
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	if len(missing)+len(extra) > 0 {
		slices.Sort(missing)
		slices.Sort(extra)
		return problemErr(http.StatusBadRequest, "badCSR", "the CSR must name exactly the order's identifiers (missing: %s; not ordered: %s)",
			strings.Join(missing, ", "), strings.Join(extra, ", "))
	}
	a, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	b, _ := x509.MarshalPKIXPublicKey(accountKey)
	if bytes.Equal(a, b) {
		return problemErr(http.StatusBadRequest, "badCSR", "the certificate key must not be the account key")
	}
	return nil
}

// invalidate marks an order invalid with the problem that ended it.
func (s *Server) invalidate(ctx context.Context, o *pkidb.AcmeOrder, cause error) {
	var ae *acmeError
	if !errors.As(cause, &ae) {
		ae = problemErr(http.StatusInternalServerError, "serverInternal", "internal error")
	}
	b, _ := json.Marshal(map[string]any{"type": "urn:ietf:params:acme:error:" + ae.typ, "detail": ae.detail, "status": ae.status})
	if err := pkidb.New(s.db).SetACMEOrderStatus(ctx, pkidb.SetACMEOrderStatusParams{Status: "invalid", Error: sql.NullString{String: string(b), Valid: true}, UpdatedAt: dbTime(s.now()), ID: o.ID}); err != nil {
		s.log.Error("acme invalidate order", slog.String("order", o.ID), slog.Any("error", err))
	}
}

// issue issues the certificate of a processing order through the engine
// (ADR-19). While sealed the order stays processing; a refusal by the
// policy makes it invalid. The order becomes valid inside the storing
// transaction, and only from "processing": one certificate per order.
func (s *Server) issue(ctx context.Context, orderID string) {
	s.finalizeMu.Lock()
	defer s.finalizeMu.Unlock()
	q := pkidb.New(s.db)
	o, err := q.GetACMEOrder(ctx, orderID)
	if err != nil || o.Status != "processing" {
		return
	}
	var idents []identifier
	if jerr := json.Unmarshal([]byte(o.Identifiers), &idents); jerr != nil {
		s.invalidate(ctx, &o, jerr)
		return
	}
	req := ca.Request{
		CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: o.CsrDer}),
		Who: keys.Who{Actor: audit.Actor{Type: audit.ActorACMEAccount, ID: o.AccountID, Name: "acme:" + o.AccountID}, Principal: authz.System("acme")},
		ACME: &ca.ACMEOrder{OrderID: o.ID, AccountID: o.AccountID, Stored: func(ctx context.Context, tx *sql.Tx, is *ca.Issued) error {
			n, uerr := pkidb.New(tx).SetACMEOrderValid(ctx, pkidb.SetACMEOrderValidParams{CertificateID: sql.NullString{String: is.ID, Valid: true}, UpdatedAt: dbTime(s.now()), ID: o.ID})
			if uerr != nil {
				return uerr
			}
			if n != 1 {
				return errors.New("the order is no longer processing")
			}
			return nil
		}},
	}
	for _, id := range idents {
		if id.Type == "ip" {
			req.IPAddresses = append(req.IPAddresses, id.Value)
		} else {
			req.DNSNames = append(req.DNSNames, id.Value)
		}
	}
	_, err = s.engine.Issue(ctx, req)
	var denied *ca.DeniedError
	switch {
	case err == nil:
	case errors.Is(err, keys.ErrSealed):
		// Issued at the unseal (ProcessPending).
	case errors.As(err, &denied):
		s.invalidate(ctx, &o, problemErr(http.StatusForbidden, "rejectedIdentifier", "%s", strings.Join(denied.Reasons, "; ")))
	default:
		s.log.Error("acme issue", slog.String("order", o.ID), slog.Any("error", err))
	}
}

// ProcessPending issues the orders that wait – after the unseal and every
// minute (a finalize while sealed, or a crash between finalize and issue).
func (s *Server) ProcessPending(ctx context.Context) error {
	if s.engine.Keys.Status().Sealed {
		return nil
	}
	rows, err := pkidb.New(s.db).ListACMEOrdersProcessing(ctx, 100)
	if err != nil {
		return err
	}
	for _, o := range rows {
		s.issue(ctx, o.ID)
	}
	return nil
}

// Waiting counts the orders that wait for the unseal (dashboard).
func (s *Server) Waiting(ctx context.Context) (int64, error) {
	return pkidb.New(s.db).CountACMEOrdersProcessing(ctx)
}

// certificate: the certificate with its chain up to below the root
// (application/pem-certificate-chain, RFC 8555 §7.4.2), for the account
// whose order it is.
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	ctx := r.Context()
	certID := r.PathValue("id")
	o, err := pkidb.New(s.db).GetACMEOrderByCertificate(ctx, sql.NullString{String: certID, Valid: true})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && o.AccountID != req.account.ID) {
		s.fail(w, r, problemErr(http.StatusNotFound, "malformed", "no such certificate"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	certDER, chain, err := s.engine.CertificateChain(ctx, keys.Who{Principal: authz.System("acme")}, certID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var out bytes.Buffer
	for _, der := range append([][]byte{certDER}, chain...) {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
}

// ExpireStale marks expired orders and authorizations (a job, every few
// minutes); reads bring a single object up to date on their own.
func (s *Server) ExpireStale(ctx context.Context) error {
	now := dbTime(s.now())
	q := pkidb.New(s.db)
	b, _ := json.Marshal(map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "the order expired", "status": http.StatusForbidden})
	if _, err := q.ExpireACMEOrders(ctx, pkidb.ExpireACMEOrdersParams{Error: sql.NullString{String: string(b), Valid: true}, UpdatedAt: now, ExpiresAt: now}); err != nil {
		return err
	}
	_, err := q.ExpireACMEAuthzs(ctx, pkidb.ExpireACMEAuthzsParams{UpdatedAt: now, ExpiresAt: now})
	return err
}
