// Package server runs MyOwnPKI (PHASE1 step 12): the admin listener with TLS,
// the public listener for CRLs and CA certificates, and the background jobs
// (audit delivery and checkpoints, CRL renewal, clean-ups).
//
// The server starts sealed. It refuses to start before init and without the
// auth key. Shutting down seals the keyring – with a last checkpoint – within
// ShutdownBudget, before a container runtime sends SIGKILL.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/httpapi"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/publish"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// ShutdownBudget: everything – requests, the last checkpoint, the seal – is
// done within this time. Docker and Podman send SIGKILL after 10 s (owner
// 2026-10-16).
const ShutdownBudget = 8 * time.Second

// ErrNotInitialized: serve before myownpki init.
var ErrNotInitialized = errors.New("this instance is not initialized – run myownpki init first")

// Job names and intervals.
const (
	jobDeliver    = "audit-deliver"
	jobCheckpoint = "audit-checkpoint"
	jobHeads      = "audit-heads"
	jobCRL        = "crl-renew"
	jobSessions   = "sessions-prune"
	jobOutbox     = "outbox-cleanup"
	jobRefusals   = "admin-refusals"
	jobACMEIssue  = "acme-issue-waiting"
	jobACMEExpire = "acme-expire"

	tickEvery = 5 * time.Second
)

// systemWho is the server itself (seal at shutdown, jobs).
var systemWho = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "server"}, Principal: authz.System("server")}

// Options configure a server.
type Options struct {
	Config   config.Config
	Log      *slog.Logger
	Clock    clock.Clock // nil = clock.System
	Hostname string      // "" = os.Hostname
	Version  string
}

// Server is one running MyOwnPKI.
type Server struct {
	opt  Options
	log  *slog.Logger
	clk  clock.Clock
	sys  *store.DB
	ia   *store.DB
	pki  *store.DB
	ta   *store.DB
	ring *keys.Keyring

	auth      *auth.Service
	engine    *ca.Engine
	api       *httpapi.API
	ui        http.Handler
	deliverer *audit.Deliverer
	cp        *audit.Checkpointer
	jobs      *scheduler
	wake      chan struct{}

	cert     *tls.Certificate
	CertInfo CertInfo
	refused  *refusalLog
	// Certificates the server issues itself (admin.tls_issuer,
	// acme.tls_issuer); nil when off.
	adminTLS, acmeTLS *issuedTLS

	admin, public     *http.Server
	adminLn, publicLn net.Listener

	// The ACME server (PHASE2): nil while acme.base_url is empty.
	acme   *acme.Server
	acmeHS *http.Server
	acmeLn net.Listener

	closeOnce sync.Once
}

// Open checks the data directory and prepares everything; nothing listens yet.
func Open(ctx context.Context, opt Options) (_ *Server, err error) {
	if opt.Clock == nil {
		opt.Clock = clock.System{}
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	if opt.Hostname == "" {
		opt.Hostname, _ = os.Hostname()
	}
	s := &Server{opt: opt, log: opt.Log, clk: opt.Clock, wake: make(chan struct{}, 1)}
	// Named result err: the databases opened so far are closed on every
	// failure (s itself is returned as nil then).
	defer func() {
		if err != nil {
			s.closeDBs()
		}
	}()
	l := store.Layout{DataDir: opt.Config.DataDir}
	// The server migrates like `db migrate`; a problem stops it here.
	if _, merr := store.Migrate(ctx, l, store.DefaultTenant, s.clk.Now); merr != nil {
		return nil, merr
	}
	if oerr := s.openDBs(ctx, l); oerr != nil {
		return nil, oerr
	}
	inst, err := setup.ReadInstance(ctx, s.sys.Read)
	if err != nil {
		return nil, err
	}
	if !inst.Initialized {
		return nil, ErrNotInitialized
	}
	if inst.Demo {
		s.log.Warn("DEMO instance – all secrets are in one file, do not use in production") // = setup.DemoWarning, checked by a test
	}
	key, warnings, err := auth.LoadKey(opt.Config.AuthKeyFile())
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		s.log.Warn("auth key", slog.String("warning", w))
	}
	if berr := s.build(key); berr != nil {
		return nil, berr
	}
	if aerr := s.buildHTTP(inst.Demo); aerr != nil {
		return nil, aerr
	}
	if s.cert, s.CertInfo, err = adminCertificate(opt.Config, opt.Hostname, s.clk.Now(), nil); err != nil {
		return nil, err
	}
	if terr := s.issuedCertificates(ctx); terr != nil {
		return nil, terr
	}
	s.logStart(ctx, inst)
	return s, nil
}

func (s *Server) openDBs(ctx context.Context, l store.Layout) error {
	paths := []struct {
		db   **store.DB
		path func() (string, error)
	}{
		{&s.sys, func() (string, error) { return l.SystemDB(), nil }},
		{&s.ia, func() (string, error) { return l.InstanceAuditDB(), nil }},
		{&s.pki, func() (string, error) { return l.TenantDB(store.DefaultTenant, store.KindPKI) }},
		{&s.ta, func() (string, error) { return l.TenantDB(store.DefaultTenant, store.KindAudit) }},
	}
	for _, p := range paths {
		path, err := p.path()
		if err != nil {
			return err
		}
		if *p.db, err = store.Open(ctx, path); err != nil {
			return err
		}
	}
	return nil
}

// build wires keyring, engine, auth, audit and the jobs.
func (s *Server) build(key *auth.Key) error {
	tenantScope := store.TenantScope(store.DefaultTenant)
	s.deliverer = &audit.Deliverer{
		Routes: []audit.Route{
			{Source: "system", From: s.sys.Write, To: s.ia.Write, Scope: store.InstanceScope},
			{Source: "pki", From: s.pki.Write, To: s.ta.Write, Scope: tenantScope},
		},
		Clock: s.clk, Log: s.log,
	}
	s.ring = keys.New(s.sys.Write, s.ia.Write, s.clk)
	s.ring.Wake = s.wakeUp
	s.cp = &audit.Checkpointer{
		Logs:   []audit.CheckpointLog{{DB: s.ia.Write, Scope: store.InstanceScope}, {DB: s.ta.Write, Scope: tenantScope}},
		Signer: s.ring, Clock: s.clk, Log: s.log,
	}
	presets, err := preset.Builtin()
	if err != nil {
		return err
	}
	s.engine = &ca.Engine{
		PKI: s.pki.Write, Audit: s.ta.Write, Scope: tenantScope, Keys: s.ring, Presets: presets, Clock: s.clk, Log: s.log,
		Wake: s.wakeUp,
		ServerKeygen: func(ctx context.Context) (bool, error) {
			t, err := systemdb.New(s.sys.Read).GetTenant(ctx, store.DefaultTenant)
			return t.AllowServerKeygen == 1, err
		},
	}
	s.auth = auth.NewService(s.sys.Write, s.ia.Write, key, s.clk)
	s.auth.Wake = s.wakeUp
	origin := s.opt.Config.Auth.PasskeyOrigin
	if rpID, perr := config.PasskeyRPID(origin); perr != nil {
		return perr
	} else if rpID != "" {
		if s.auth.Passkeys, perr = auth.NewPasskeys(rpID, origin); perr != nil {
			return perr
		}
	}
	s.ring.OnUnseal = func(ctx context.Context) {
		s.deliver(ctx)
		if err := s.cp.MakeAll(ctx, "unseal"); err != nil {
			s.log.Error("checkpoint at unseal", slog.Any("error", err))
		}
		if _, err := s.engine.RenewCRLs(ctx, "unseal"); err != nil {
			s.log.Warn("CRL renewal at unseal", slog.Any("error", err))
		}
		if s.acme != nil {
			if err := s.acme.ProcessPending(ctx); err != nil {
				s.log.Warn("ACME orders at unseal", slog.Any("error", err))
			}
		}
		s.renewTLS(ctx)
	}
	s.ring.BeforeSeal = func(ctx context.Context) {
		s.deliver(ctx)
		if err := s.cp.MakeAll(ctx, "seal"); err != nil {
			s.log.Error("checkpoint before seal", slog.Any("error", err))
		}
	}
	s.refused = newRefusalLog(s.log, s.clk)
	s.jobs = &scheduler{clk: s.clk, log: s.log}
	s.jobs.add(jobDeliver, tickEvery, 0, func(ctx context.Context) error { s.deliver(ctx); return nil })
	s.jobs.add(jobCheckpoint, 24*time.Hour, 24*time.Hour, func(ctx context.Context) error { return s.cp.MakeAll(ctx, "daily") })
	s.jobs.add(jobHeads, 24*time.Hour, 24*time.Hour, func(ctx context.Context) error { s.logHeads(ctx); return nil })
	s.jobs.add(jobCRL, 15*time.Minute, 0, func(ctx context.Context) error {
		_, err := s.engine.RenewCRLs(ctx, "timer")
		if errors.Is(err, keys.ErrSealed) {
			return s.warnSealedCRLs(ctx) // renewed at unseal
		}
		return err
	})
	s.jobs.add(jobSessions, time.Hour, time.Hour, func(ctx context.Context) error {
		_, err := s.auth.PruneSessions(ctx)
		return err
	})
	s.jobs.add(jobOutbox, 24*time.Hour, 24*time.Hour, func(ctx context.Context) error {
		_, err := s.deliverer.Cleanup(ctx)
		return err
	})
	s.jobs.add(jobRefusals, time.Minute, time.Minute, func(context.Context) error { s.refused.flush(); return nil })
	if base := s.opt.Config.ACME.BaseURL; base != "" {
		acfg := s.opt.Config.ACME
		var aerr error
		settings := &tenant.Store{DB: s.sys.Read, Clock: s.clk} // only read here
		limits := func(ctx context.Context) (acme.Limits, error) {
			l, lerr := settings.ACMELimits(ctx, store.DefaultTenant)
			return acme.Limits{OrdersPerAccount: l.OrdersPerAccount, FailedPerName: l.FailedPerName, AccountsPerIP: l.AccountsPerIP}, lerr
		}
		if s.acme, aerr = acme.New(acme.Options{Engine: s.engine, BaseURL: base, TrustedProxies: acfg.TrustedProxies, Resolver: acfg.Resolver,
			Direct: acfg.DirectTLS(), Clock: s.clk, Log: s.log, Limits: limits}); aerr != nil {
			return aerr
		}
		s.jobs.add(jobACMEIssue, time.Minute, time.Minute, s.acme.ProcessPending)
		s.jobs.add(jobACMEExpire, 5*time.Minute, 5*time.Minute, s.acme.ExpireStale)
	}
	if s.opt.Config.Admin.TLSIssuer != "" || s.opt.Config.ACME.DirectTLS() {
		s.jobs.add(jobTLS, tlsEvery, 0, func(ctx context.Context) error { s.renewTLS(ctx); return nil })
	}
	return nil
}

// issuedCertificates prepares the certificates the server issues itself;
// each one falls back to a bootstrap certificate (admin: the one already
// loaded; ACME: its own, for the host of acme.base_url).
func (s *Server) issuedCertificates(ctx context.Context) error {
	cfg := s.opt.Config
	dir := filepath.Join(cfg.DataDir, "tls")
	if cfg.Admin.TLSIssuer != "" {
		names, ips, err := config.ParseTLSNames(cfg.Admin.TLSNames)
		if err != nil {
			return err
		}
		names, ips = uniqueNames(names, ips)
		s.adminTLS = newIssuedTLS("admin", "admin.tls_names", "admin.tls_issuer", cfg.Admin.TLSIssuer, names, ips, dir, s.cert, s.engine, s.clk, s.log)
	}
	if cfg.ACME.DirectTLS() {
		boot, in, err := acmeBootstrap(cfg, s.clk.Now(), nil)
		if err != nil {
			return fmt.Errorf("ACME bootstrap certificate: %w", err)
		}
		if in.Created {
			s.log.Info("new ACME bootstrap certificate – served until the server issues the ACME certificate", slog.String("reason", in.Reason))
		}
		names, ips := hostNames(config.ACMEHost(cfg.ACME.BaseURL))
		s.acmeTLS = newIssuedTLS("acme", "the host of acme.base_url", "acme.tls_issuer", cfg.ACME.TLSIssuer, names, ips, dir, boot, s.engine, s.clk, s.log)
	}
	// A root as issuer is named right at the start, not only at the unseal.
	for _, m := range []*issuedTLS{s.adminTLS, s.acmeTLS} {
		if m != nil {
			m.checkIssuer(ctx)
		}
	}
	return nil
}

// renewTLS renews the issued certificates that are due (unsealed only).
func (s *Server) renewTLS(ctx context.Context) {
	for _, m := range []*issuedTLS{s.adminTLS, s.acmeTLS} {
		if m != nil {
			m.renew(ctx)
		}
	}
}

// tlsAttention is what the dashboard shows about the issued certificates.
func (s *Server) tlsAttention(sealed bool) []view.Message {
	var out []view.Message
	for _, m := range []*issuedTLS{s.adminTLS, s.acmeTLS} {
		if m != nil {
			out = append(out, m.attention(sealed)...)
		}
	}
	return out
}

// warnSealedCRLs: while sealed nothing can be signed – CRLs that need
// attention are named with the time since the seal (step 9), every run of
// the CRL job (15 minutes), so the alarm can't be missed.
func (s *Server) warnSealedCRLs(ctx context.Context) error {
	statuses, err := ca.CRLStatuses(ctx, s.pki.Read, s.clk.Now())
	if err != nil {
		return err
	}
	since := s.ring.Status().SealedSince
	for _, st := range statuses {
		if msg := st.Message(true); msg != "" {
			s.log.Warn("crl attention", slog.String("ca", st.CA), slog.Int64("generation", st.Generation), slog.String("state", st.State),
				slog.String("detail", msg), slog.Time("sealed_since", since))
		}
	}
	return nil
}

func (s *Server) wakeUp() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// deliver moves outbox entries into the audit logs. Outbox entries may pile
// up while delivery fails – they are never lost – but the server says so
// loudly, with count and age (owner 2026-10-16).
func (s *Server) deliver(ctx context.Context) {
	_, err := s.deliverer.DeliverPending(ctx)
	if err != nil && ctx.Err() == nil {
		attrs := []any{slog.Any("error", err)}
		if backlog, berr := s.deliverer.Backlog(ctx); berr == nil {
			for _, b := range backlog {
				if b.Pending > 0 {
					attrs = append(attrs, slog.Group(b.Source, slog.Int64("pending", b.Pending),
						slog.String("oldest_age", s.clk.Now().Sub(b.Oldest).Round(time.Second).String())))
				}
			}
		}
		s.log.Error("audit delivery failing – entries wait in the outbox", attrs...)
		return
	}
	if err := s.cp.MaybeEvery(ctx); err != nil {
		s.log.Error("checkpoint", slog.Any("error", err))
	}
}

// logStart writes what an operator needs at every start, including the
// audit heads as anchors outside the database files.
func (s *Server) logStart(ctx context.Context, inst setup.Instance) {
	ci := s.CertInfo
	if ci.Created {
		s.log.Warn("new admin TLS certificate – compare its fingerprint when the browser asks",
			slog.String("reason", ci.Reason), slog.String("fingerprint_sha256", ci.Fingerprint))
	}
	s.log.Info("myownpki starting", slog.String("version", s.opt.Version), slog.String("data_dir", s.opt.Config.DataDir),
		slog.String("initialized", inst.InitializedAt), slog.Bool("sealed", s.ring.Status().Sealed))
	s.log.Info("admin TLS certificate", slog.String("source", ci.Source), slog.String("fingerprint_sha256", ci.Fingerprint),
		slog.Time("not_after", ci.NotAfter), slog.Any("dns_names", ci.DNSNames))
	if ci.Source == "operator" && s.clk.Now().Add(bootstrapRenew).After(ci.NotAfter) {
		s.log.Warn("the admin TLS certificate expires within 30 days – replace admin.tls_cert_file", slog.Time("not_after", ci.NotAfter))
	}
	if s.adminTLS != nil {
		s.log.Info("admin TLS certificate from admin.tls_issuer", s.adminTLS.startInfo()...)
	}
	if s.acmeTLS != nil {
		s.log.Info("ACME TLS certificate from acme.tls_issuer", s.acmeTLS.startInfo()...)
	}
	s.logHeads(ctx)
}

func (s *Server) logHeads(ctx context.Context) {
	for _, l := range []struct {
		scope string
		db    *store.DB
	}{{store.InstanceScope, s.ia}, {store.TenantScope(store.DefaultTenant), s.ta}} {
		h, err := auditdb.New(l.db.Read).GetHead(ctx)
		if err != nil {
			continue // an empty log has no head yet
		}
		s.log.Info("audit head", slog.String("scope", l.scope), slog.Int64("seq", h.Seq), slog.String("hash", h.Hash))
	}
}

// Listen opens both listeners. A warning goes out when the admin listener
// is reachable from other machines without an allowlist.
func (s *Server) Listen(ctx context.Context) error {
	cfg := s.opt.Config
	allowed, err := config.ParseNetworks(cfg.Admin.AllowedNetworks)
	if err != nil {
		return err
	}
	if !loopbackOnly(cfg.Admin.Listen) && len(allowed) == 0 {
		s.log.Warn("the admin listener is reachable from other machines and admin.allowed_networks is empty – " +
			"restrict it to your admin networks, and never expose it to the internet")
	}
	lc := &net.ListenConfig{}
	raw, err := lc.Listen(ctx, "tcp", cfg.Admin.Listen)
	if err != nil {
		return fmt.Errorf("admin listener %s: %w", cfg.Admin.Listen, err)
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if s.adminTLS != nil {
		tlsCfg.GetCertificate = s.adminTLS.GetCertificate // switches without a restart
	} else {
		tlsCfg.Certificates = []tls.Certificate{*s.cert}
	}
	s.adminLn = tls.NewListener(&allowListener{Listener: raw, allowed: allowed, refused: s.refused}, tlsCfg)
	s.admin = &http.Server{
		Handler:           s.adminHandler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	if cfg.Public.Listen != "" {
		if s.publicLn, err = lc.Listen(ctx, "tcp", cfg.Public.Listen); err != nil {
			_ = s.adminLn.Close()
			return fmt.Errorf("public listener %s: %w", cfg.Public.Listen, err)
		}
		s.public = &http.Server{
			Handler:           s.publicHandler(),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 8 << 10, ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		}
	}
	if s.acme != nil {
		if s.acmeLn, err = lc.Listen(ctx, "tcp", cfg.ACME.Listen); err != nil {
			_ = s.adminLn.Close()
			if s.publicLn != nil {
				_ = s.publicLn.Close()
			}
			return fmt.Errorf("acme listener %s: %w", cfg.ACME.Listen, err)
		}
		// Without acme.tls_issuer: plain HTTP for the reverse proxy only; the
		// handler refuses every peer outside acme.trusted_proxies. With it:
		// TLS for every client, with the certificate the server issued.
		scheme := "http://"
		if s.acmeTLS != nil {
			s.acmeLn = tls.NewListener(s.acmeLn, &tls.Config{
				MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: s.acmeTLS.GetCertificate,
			})
			scheme = "https://"
			s.log.Info("ACME speaks TLS itself (acme.tls_issuer): every client may connect, acme.trusted_proxies and X-Forwarded-For are not used")
			if loopbackOnly(cfg.ACME.Listen) {
				s.log.Warn("acme.listen is a loopback address – with acme.tls_issuer, clients on other machines can't reach it (e.g. \":443\")")
			}
		}
		s.acmeHS = &http.Server{
			Handler:           s.acme,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		}
		s.log.Info("ACME listening", slog.String("listen", scheme+s.acmeLn.Addr().String()), slog.String("directory", s.acme.BaseURL()+"/directory"))
	}
	s.log.Info("listening", slog.String("admin", "https://"+s.adminLn.Addr().String()), slog.String("public", s.PublicAddr()))
	return nil
}

// AdminAddr and PublicAddr are the bound addresses (tests use port 0).
func (s *Server) AdminAddr() string { return s.adminLn.Addr().String() }

// ServedAdminCertificate describes the certificate the admin listener
// serves now: with admin.tls_issuer the issued one while it is valid.
func (s *Server) ServedAdminCertificate() CertInfo {
	if s.adminTLS != nil {
		if c, issued := s.adminTLS.serving(s.clk.Now()); issued {
			return info("issued by CA "+s.adminTLS.issuer, c.Leaf)
		}
	}
	return s.CertInfo
}

// ACMEAddr is "" when ACME is off; else the listener's address (tests use port 0).
func (s *Server) ACMEAddr() string {
	if s.acmeLn == nil {
		return ""
	}
	return s.acmeLn.Addr().String()
}

// ACME is the ACME server, nil while ACME is off.
func (s *Server) ACME() *acme.Server { return s.acme }

// PublicAddr is "" when the public listener is off.
func (s *Server) PublicAddr() string {
	if s.publicLn == nil {
		return ""
	}
	return "http://" + s.publicLn.Addr().String()
}

// adminHandler: /healthz, the REST API (step 13) and the web UI (step 14). /healthz says "ok" and nothing about the seal state: that is not
// for strangers.
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle("/", s.ui)
	// The API gets its paths unchanged: the mux would redirect unclean ones
	// ("//") with text/html before the API could answer with a problem.
	return hsts(web.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, httpapi.BasePath+"/") {
			s.api.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})))
}

// hsts: one year, without includeSubDomains and preload – the admin host
// name rarely owns its parent domain.
func hsts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

func loopbackOnly(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Unseal unlocks the keyring (console at start; the API follows in step 13).
// A wrong passphrase leaves the server running sealed.
func (s *Server) Unseal(ctx context.Context, passphrase []byte, who keys.Who) error {
	return s.ring.Unseal(ctx, passphrase, who)
}

// Sealed reports the seal state.
func (s *Server) Sealed() bool { return s.ring.Status().Sealed }

// Serve runs listeners and jobs until ctx ends, then shuts down within
// ShutdownBudget: no new connections, in-flight requests get a few seconds,
// then the seal with its last checkpoint, then the databases close.
func (s *Server) Serve(ctx context.Context) error {
	errc := make(chan error, 3)
	go func() { errc <- serveErr("admin", s.admin.Serve(s.adminLn)) }()
	if s.public != nil {
		go func() { errc <- serveErr("public", s.public.Serve(s.publicLn)) }()
	}
	if s.acmeHS != nil {
		go func() { errc <- serveErr("acme", s.acmeHS.Serve(s.acmeLn)) }()
	}
	jobCtx, stopJobs := context.WithCancel(ctx)
	jobsDone := make(chan struct{})
	go func() { defer close(jobsDone); s.jobs.loop(jobCtx, tickEvery, s.wake) }()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	stopJobs()
	<-jobsDone
	return errors.Join(runErr, s.Shutdown(context.WithoutCancel(ctx)))
}

func serveErr(name string, err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("%s listener: %w", name, err)
}

// Shutdown stops everything within ShutdownBudget.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	s.closeOnce.Do(func() {
		start := s.clk.Now()
		sctx, cancel := context.WithTimeout(ctx, ShutdownBudget)
		defer cancel()
		s.log.Info("shutting down")
		// Requests get at most half of the budget; the seal must fit after.
		reqCtx, reqCancel := context.WithTimeout(sctx, ShutdownBudget/2)
		for _, srv := range []*http.Server{s.admin, s.public, s.acmeHS} {
			if srv == nil {
				continue
			}
			if err := srv.Shutdown(reqCtx); err != nil {
				_ = srv.Close()
			}
		}
		reqCancel()
		if s.acme != nil {
			s.acme.Close() // running validations finish before the databases close
		}
		if err := s.ring.Seal(sctx, systemWho); err != nil {
			errs = append(errs, fmt.Errorf("seal: %w", err))
			s.log.Error("seal at shutdown", slog.Any("error", err))
		}
		s.refused.flush()
		s.closeDBs()
		s.log.Info("stopped", slog.Duration("took", s.clk.Now().Sub(start)))
	})
	return errors.Join(errs...)
}

func (s *Server) closeDBs() {
	for _, db := range []*store.DB{s.sys, s.ia, s.pki, s.ta} {
		if db != nil {
			_ = db.Close()
		}
	}
}

// buildHTTP prepares the REST API (PHASE1 step 13) and the web UI (step 14)
// of the admin listener; both call the same services.
func (s *Server) buildHTTP(demo bool) error {
	trusted, err := config.ParseNetworks(s.opt.Config.Auth.TrustedProxies)
	if err != nil {
		return fmt.Errorf("auth.trusted_proxies: %w", err)
	}
	s.api = httpapi.New(httpapi.Deps{
		Auth: s.auth, Engine: s.engine, Keys: s.ring, Presets: s.engine.Presets, Clock: s.clk, Log: s.log,
		TrustedProxies: trusted, Version: s.opt.Version, Demo: demo,
		Settings: &tenant.Store{DB: s.sys.Write, Clock: s.clk, Wake: s.wakeUp}, Tenant: store.DefaultTenant,
		TenantAudit: s.ta.Read, InstanceAudit: s.ia.Read,
	})
	ui, err := web.NewHandler(web.Options{Logger: s.log, App: &web.AppDeps{
		Auth: s.auth, Engine: s.engine, Keys: s.ring, Presets: s.engine.Presets, Clock: s.clk,
		TrustedProxies: trusted, Demo: demo, Tenant: store.DefaultTenant,
		Settings: &tenant.Store{DB: s.sys.Write, Clock: s.clk, Wake: s.wakeUp}, TenantAudit: s.ta.Read, InstanceAudit: s.ia.Read,
		ACME: s.acmeAdmin(), ACMEDirectory: s.acmeDirectory(), TLSAttention: s.tlsAttention,
	}})
	if err != nil {
		return err
	}
	s.ui = ui
	return nil
}

// acmeAdmin returns the ACME server as the UI's interface – nil (not a
// typed nil) while ACME is off.
func (s *Server) acmeAdmin() web.ACMEAdmin {
	if s.acme == nil {
		return nil
	}
	return s.acme
}

// acmeDirectory is the directory URL clients use; "" while ACME is off.
func (s *Server) acmeDirectory() string {
	if s.acme == nil {
		return ""
	}
	return s.acme.BaseURL() + "/directory"
}

// publicHandler: CA certificates and CRLs, and the trust page at / unless
// the tenant switched it off (asked per request).
func (s *Server) publicHandler() http.Handler {
	settings := &tenant.Store{DB: s.sys.Read, Clock: s.clk} // only read here
	return publish.New(s.pki.Read, s.log).WithTrustPage(publish.TrustPage{
		Enabled: func(ctx context.Context) (bool, error) { return settings.TrustPage(ctx, store.DefaultTenant) },
		Clock:   s.clk,
	})
}
