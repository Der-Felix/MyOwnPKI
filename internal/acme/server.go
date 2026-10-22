// Package acme is the ACME server (RFC 8555) for the internal CAs
// (PHASE2). It runs only behind a reverse proxy that terminates TLS (owner
// Q1): plain HTTP on acme.listen, every URL built from acme.base_url,
// requests only from acme.trusted_proxies.
//
// Every request body is attacker input (security.md): the JWS is read by
// internal/acme/jose, payloads are decoded into fixed structures, sizes are
// limited. Issuance goes through ca.Engine.Issue with the domain policy
// (ADR-19); validation connects only where security.md allows.
package acme

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Limits.
const (
	maxBody         = 64 << 10 // a CSR with 100 names fits easily
	pendingLifetime = 24 * time.Hour
	// ValidAuthzLifetime: how long a passed challenge counts for new orders
	// (owner Q6).
	ValidAuthzLifetime = 7 * 24 * time.Hour
	maxIdentifiers     = 100
	retryAfter         = 30 // seconds, for processing orders and challenges
)

// Options configure the server.
type Options struct {
	Engine *ca.Engine // the tenant's engine; its PKI writer holds the ACME tables
	// BaseURL, TrustedProxies and Resolver as in config.ACME.
	BaseURL, TrustedProxies, Resolver string
	Clock                             clock.Clock
	Log                               *slog.Logger
	// Rand for tokens and IDs; nil = crypto/rand.
	Rand io.Reader
}

// Server is the ACME server of one tenant.
type Server struct {
	opt     Options
	base    string // https://pki.homelab.lan/acme, no trailing slash
	prefix  string // /acme
	trusted []netip.Prefix
	engine  *ca.Engine
	db      *sql.DB
	clk     clock.Clock
	log     *slog.Logger
	rnd     io.Reader
	nonces  *nonceStore
	mux     *http.ServeMux
	valid   *validator
	limits  *limiter

	finalizeMu sync.Mutex // one issuance run at a time (finalize, unseal, job)
}

// New prepares the server; it doesn't listen.
func New(opt Options) (*Server, error) {
	base, err := config.ACMEBaseURL(opt.BaseURL)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(base)
	trusted, err := config.ParseNetworks(opt.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("acme.trusted_proxies: %w", err)
	}
	resolver, err := config.ACMEResolver(opt.Resolver)
	if err != nil {
		return nil, fmt.Errorf("acme.resolver: %w", err)
	}
	if opt.Clock == nil {
		opt.Clock = clock.System{}
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	if opt.Rand == nil {
		opt.Rand = rand.Reader
	}
	s := &Server{
		opt: opt, base: base, prefix: strings.TrimRight(u.EscapedPath(), "/"), trusted: trusted,
		engine: opt.Engine, db: opt.Engine.PKI, clk: opt.Clock, log: opt.Log, rnd: opt.Rand,
		nonces: newNonceStore(opt.Clock, opt.Rand), limits: newLimiter(opt.Clock),
	}
	s.valid = newValidator(s, resolver)
	s.routes()
	return s, nil
}

// BaseURL is the ACME base URL; the directory is BaseURL + "/directory".
func (s *Server) BaseURL() string { return s.base }

func (s *Server) routes() {
	m := http.NewServeMux()
	p := s.prefix
	m.HandleFunc("GET "+p+"/directory", s.directory)
	m.HandleFunc("GET "+p+"/new-nonce", s.newNonce)
	m.HandleFunc("HEAD "+p+"/new-nonce", s.newNonce)
	m.HandleFunc("POST "+p+"/new-account", s.newAccount)
	m.HandleFunc("POST "+p+"/account/{id}", s.account)
	m.HandleFunc("POST "+p+"/account/{id}/orders", s.accountOrders)
	m.HandleFunc("POST "+p+"/key-change", s.keyChange)
	m.HandleFunc("POST "+p+"/new-order", s.newOrder)
	m.HandleFunc("POST "+p+"/order/{id}", s.order)
	m.HandleFunc("POST "+p+"/order/{id}/finalize", s.finalize)
	m.HandleFunc("POST "+p+"/authz/{id}", s.authz)
	m.HandleFunc("POST "+p+"/challenge/{id}", s.challenge)
	m.HandleFunc("POST "+p+"/certificate/{id}", s.certificate)
	m.HandleFunc("POST "+p+"/revoke-cert", s.revokeCert)
	m.HandleFunc("GET "+p+"/renewal-info/{id}", s.renewalInfo)
	s.mux = m
}

// url builds a URL the client sees: base URL plus path.
func (s *Server) url(path string) string { return s.base + path }

// ServeHTTP checks where the request comes from, then dispatches. Every
// answer carries a fresh nonce and the directory link (RFC 8555 §6.5, §7.1).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok || !s.isTrusted(peer) {
		// Not through the proxy: refused before anything is read.
		s.problem(w, http.StatusForbidden, "unauthorized", "the ACME server is reachable only through its reverse proxy", nil)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), clientKey{}, s.clientIP(r, peer)))
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Link", `<`+s.url("/directory")+`>;rel="index"`)
	if n, err := s.nonces.New(); err == nil {
		h.Set("Replay-Nonce", n)
	}
	s.mux.ServeHTTP(w, r)
}

type clientKey struct{}

func clientIP(r *http.Request) string {
	ip, _ := r.Context().Value(clientKey{}).(string)
	return ip
}

func peerAddr(remote string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func (s *Server) isTrusted(a netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP: the last X-Forwarded-For entry that is not a trusted proxy –
// the address the outermost trusted proxy saw. Without one, the peer.
func (s *Server) clientIP(r *http.Request, peer netip.Addr) string {
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for h := range strings.SplitSeq(v, ",") {
			hops = append(hops, strings.TrimSpace(h))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			break // a broken entry: everything left of it is unknown
		}
		a = a.Unmap()
		if !s.isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

// problem writes an RFC 8555 §6.7 problem document.
func (s *Server) problem(w http.ResponseWriter, status int, typ, detail string, extra map[string]any) {
	body := map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// acmeError carries a problem through the handlers.
type acmeError struct {
	status int
	typ    string
	detail string
	extra  map[string]any
}

func (e *acmeError) Error() string { return e.typ + ": " + e.detail }

func problemErr(status int, typ, format string, args ...any) *acmeError {
	return &acmeError{status: status, typ: typ, detail: fmt.Sprintf(format, args...)}
}

// fail writes err: an *acmeError as it is, sealed as 503 with Retry-After,
// a policy refusal as the given type, anything else as serverInternal
// (logged, never shown).
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *acmeError
	var denied *ca.DeniedError
	switch {
	case errors.As(err, &ae):
		if ae.status == http.StatusTooManyRequests || ae.status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		}
		s.problem(w, ae.status, ae.typ, ae.detail, ae.extra)
	case errors.As(err, &denied):
		s.problem(w, http.StatusForbidden, "rejectedIdentifier", strings.Join(denied.Reasons, "; "), nil)
	default:
		s.log.Error("acme", slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Any("error", err))
		s.problem(w, http.StatusInternalServerError, "serverInternal", "internal error – the server log has the details", nil)
	}
}

func (s *Server) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) now() time.Time { return s.clk.Now().UTC().Truncate(time.Second) }

func dbTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func parseDBTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05Z", s)
	return t
}

// inTx runs fn in one pki.db transaction (ACME rows and their audit outbox
// entries together).
func (s *Server) inTx(ctx context.Context, fn func(q *pkidb.Queries, tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(pkidb.New(tx), tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.engine.Wake != nil {
		s.engine.Wake()
	}
	return nil
}

// enqueue writes an audit entry of an ACME account into the outbox.
func enqueue(ctx context.Context, tx *sql.Tx, now time.Time, acct, ip, action string, target audit.Target, result audit.Result, details map[string]any) error {
	return audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: audit.Actor{Type: audit.ActorACMEAccount, ID: acct, Name: "acme:" + acct},
		Action: action, Target: target, Result: result, SourceIP: ip, Details: details,
	})
}

func (s *Server) directory(w http.ResponseWriter, _ *http.Request) {
	s.reply(w, http.StatusOK, map[string]any{
		"newNonce":    s.url("/new-nonce"),
		"newAccount":  s.url("/new-account"),
		"newOrder":    s.url("/new-order"),
		"revokeCert":  s.url("/revoke-cert"),
		"keyChange":   s.url("/key-change"),
		"renewalInfo": s.url("/renewal-info"),
		"meta": map[string]any{
			// EAB is optional: without it an account waits for approval
			// where the domain's level asks for it (owner Q2).
			"externalAccountRequired": false,
		},
	})
}

func (s *Server) newNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// request is a verified signed request.
type request struct {
	jws     *jose.JWS
	account *pkidb.AcmeAccount // nil for jwk requests
	key     *jose.Key          // the key that signed
	ip      string
}

// keyMode says how a resource expects the signing key.
type keyMode int

const (
	byKID  keyMode = iota // an account's request
	byJWK                 // newAccount, and revokeCert with the certificate's key
	either                // revokeCert
)

// read verifies a POST: content type, size, JWS rules, nonce, URL, key.
func (s *Server) read(w http.ResponseWriter, r *http.Request, mode keyMode) (*request, bool) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/jose+json") {
		s.problem(w, http.StatusUnsupportedMediaType, "malformed", "the request must be application/jose+json", nil)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.problem(w, http.StatusRequestEntityTooLarge, "malformed", fmt.Sprintf("the request is larger than %d KiB", maxBody>>10), nil)
		return nil, false
	}
	j, err := jose.Parse(body)
	if err != nil {
		s.joseFail(w, err)
		return nil, false
	}
	if !s.nonces.Use(j.Nonce) {
		s.problem(w, http.StatusBadRequest, "badNonce", "the nonce is unknown, used or expired – take the new one from Replay-Nonce", nil)
		return nil, false
	}
	if want := s.url(strings.TrimPrefix(r.URL.Path, s.prefix)); j.URL != want {
		s.problem(w, http.StatusUnauthorized, "unauthorized", fmt.Sprintf("the JWS url %q is not this request's URL %q", j.URL, want), nil)
		return nil, false
	}
	req := &request{jws: j, ip: clientIP(r)}
	switch {
	case j.JWK != nil && mode == byKID:
		s.problem(w, http.StatusBadRequest, "malformed", "this request is signed by an account: name it with \"kid\"", nil)
		return nil, false
	case j.KID != "" && mode == byJWK:
		s.problem(w, http.StatusBadRequest, "malformed", "this request carries its key in \"jwk\"", nil)
		return nil, false
	case j.JWK != nil:
		req.key = j.JWK
	default:
		acct, aerr := s.accountByKID(r.Context(), j.KID)
		if aerr != nil {
			s.fail(w, r, aerr)
			return nil, false
		}
		k, perr := jose.ParseJWK([]byte(acct.Jwk))
		if perr != nil {
			s.fail(w, r, perr)
			return nil, false
		}
		req.account, req.key = acct, k
	}
	if err := j.Verify(req.key); err != nil {
		s.joseFail(w, err)
		return nil, false
	}
	return req, true
}

func (s *Server) joseFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jose.ErrBadAlgorithm):
		s.problem(w, http.StatusBadRequest, "badSignatureAlgorithm", err.Error(), map[string]any{"algorithms": []string{jose.ES256, jose.ES384, jose.RS256, jose.EdDSA}})
	case errors.Is(err, jose.ErrBadKey):
		s.problem(w, http.StatusBadRequest, "badPublicKey", err.Error(), nil)
	case errors.Is(err, jose.ErrBadSignature):
		s.problem(w, http.StatusUnauthorized, "unauthorized", err.Error(), nil)
	default:
		s.problem(w, http.StatusBadRequest, "malformed", err.Error(), nil)
	}
}

// accountByKID loads the account a "kid" names; it must be valid.
func (s *Server) accountByKID(ctx context.Context, kid string) (*pkidb.AcmeAccount, error) {
	id, ok := strings.CutPrefix(kid, s.url("/account/"))
	if !ok || id == "" || strings.Contains(id, "/") {
		return nil, problemErr(http.StatusBadRequest, "accountDoesNotExist", "\"kid\" is not an account URL of this server")
	}
	acct, err := pkidb.New(s.db).GetACMEAccount(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, problemErr(http.StatusBadRequest, "accountDoesNotExist", "there is no such account")
	}
	if err != nil {
		return nil, err
	}
	if acct.Status != "valid" {
		return nil, problemErr(http.StatusUnauthorized, "unauthorized", "the account is %s", acct.Status)
	}
	return &acct, nil
}

// payload decodes a JSON payload into v; unknown members are allowed (RFC
// 8555 lets clients add fields) but the types must fit.
func payload(r *request, v any) error {
	if len(r.jws.Payload) == 0 {
		return problemErr(http.StatusBadRequest, "malformed", "this request needs a JSON payload")
	}
	if err := json.Unmarshal(r.jws.Payload, v); err != nil {
		return problemErr(http.StatusBadRequest, "malformed", "the payload is not the expected JSON: %v", err)
	}
	return nil
}

// newID makes an ID with prefix.
func (s *Server) newID(prefix string) (string, error) {
	return newID(prefix, s.now(), s.rnd)
}
