package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Certificates the server issues itself (v0.2.2, owner 2026-10-24):
// admin.tls_issuer and acme.tls_issuer name a CA of this instance, and the
// server issues the listener's certificate from it – through ca.Engine.Issue
// like every other certificate (ADR-19: same policy, name constraints, audit
// entry), with the preset "server", a new ECDSA P-256 key, 90 days at most
// (never beyond the CA's maximum or its end). It is renewed at 2/3 of its
// lifetime, at once when it was revoked, its names changed or the CA has a
// new certificate.
//
// Signing needs the unsealed keyring, but the listeners must work while
// sealed: the key lies unencrypted in <data_dir>/tls/<listener>.key (0600),
// like the bootstrap key, and the certificate with its chain next to it.
// While sealed nothing is issued; an issued certificate that expires then is
// replaced by the bootstrap certificate (warning in the log and on the
// dashboard) until the next unseal issues a new one. The switch happens per
// handshake (tls.Config.GetCertificate) – no restart.
const (
	issuedMaxDays     = 90
	issuedPreset      = "server"
	issuedRetryDenied = 6 * time.Hour    // a refusal needs an admin – don't fill the audit log
	issuedRetryError  = 15 * time.Minute // anything else may pass soon
	jobTLS            = "tls-renew"
	tlsEvery          = 15 * time.Minute
)

func issuedCertFile(listener string) string { return listener + ".crt" }
func issuedKeyFile(listener string) string  { return listener + ".key" }

// issuedTLS serves the certificate of one listener ("admin" or "acme").
type issuedTLS struct {
	listener  string // "admin", "acme": file names and messages
	setting   string // the config key of the names, for messages
	issuerKey string // the config key of the CA: admin.tls_issuer, acme.tls_issuer
	issuer    string // CA name
	names     []string
	ips       []netip.Addr
	dir       string // <data_dir>/tls
	bootstrap *tls.Certificate
	engine    *ca.Engine
	clk       clock.Clock
	log       *slog.Logger
	rnd       io.Reader // nil = crypto/rand

	cur     atomic.Pointer[tls.Certificate] // the issued certificate; nil = none yet
	blocked atomic.Pointer[string]          // why the CA may not issue it (a root); nil = it may

	mu       sync.Mutex // one renewal at a time
	nextTry  time.Time  // after a failure
	problem  string     // the last failure, for the dashboard; "" = none
	lastWarn time.Time  // the fallback warning, at most once per tlsEvery
}

func newIssuedTLS(listener, setting, issuerKey, issuer string, names []string, ips []netip.Addr, dir string, bootstrap *tls.Certificate,
	engine *ca.Engine, clk clock.Clock, log *slog.Logger) *issuedTLS {
	m := &issuedTLS{listener: listener, setting: setting, issuerKey: issuerKey, issuer: issuer, names: names, ips: ips, dir: dir, bootstrap: bootstrap,
		engine: engine, clk: clk, log: log}
	m.load()
	return m
}

// load reads the stored certificate. A missing pair is normal before the
// first unseal; a broken one is replaced at the next unseal.
func (m *issuedTLS) load() {
	c, err := tls.LoadX509KeyPair(filepath.Join(m.dir, issuedCertFile(m.listener)), filepath.Join(m.dir, issuedKeyFile(m.listener)))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.log.Warn("stored TLS certificate can't be used – it is issued again at the unseal", slog.String("listener", m.listener), slog.Any("error", err))
		}
		return
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			m.log.Warn("stored TLS certificate can't be read – it is issued again at the unseal", slog.String("listener", m.listener), slog.Any("error", err))
			return
		}
	}
	m.cur.Store(&c)
}

// GetCertificate is tls.Config.GetCertificate: the issued certificate while
// it is valid, else the bootstrap certificate.
func (m *issuedTLS) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, _ := m.serving(m.clk.Now())
	return c, nil
}

// serving returns what a handshake gets now, and whether it is the issued one.
// While the setting names a root CA it is the bootstrap certificate, even
// when an older issued one is still valid: the config says it must not be
// used, and the admin sees why on the dashboard.
func (m *issuedTLS) serving(now time.Time) (*tls.Certificate, bool) {
	if m.blocked.Load() != nil {
		return m.bootstrap, false
	}
	if c := m.cur.Load(); c != nil && !now.Before(c.Leaf.NotBefore) && !now.After(c.Leaf.NotAfter) {
		return c, true
	}
	return m.bootstrap, false
}

// renewAt is 2/3 of the lifetime (the ACME servers' ARI window, PHASE2 step 12).
func renewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
}

// renew issues a new certificate if one is due and the keyring is unsealed.
// It runs at the unseal and every tlsEvery; while sealed it only warns
// when the listener had to fall back to the bootstrap certificate.
func (m *issuedTLS) renew(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.checkIssuer(ctx) {
		return // nothing to issue from a root – and no refusal per run in the audit log
	}
	now := m.clk.Now()
	c := m.cur.Load()
	if m.engine.Keys.Status().Sealed {
		if c != nil && now.After(c.Leaf.NotAfter) && now.Sub(m.lastWarn) >= tlsEvery {
			m.lastWarn = now
			m.log.Warn("TLS certificate expired while sealed – the listener serves the bootstrap certificate until the unseal", slog.String("listener", m.listener),
				slog.String("ca", m.issuer), slog.Time("expired", c.Leaf.NotAfter), slog.String("bootstrap_sha256", Fingerprint(m.bootstrap.Leaf.Raw)))
		}
		return
	}
	why, err := m.due(ctx, c, now)
	if err != nil {
		m.log.Error("TLS certificate renewal check", slog.String("listener", m.listener), slog.Any("error", err))
		return
	}
	if why == "" || now.Before(m.nextTry) {
		return
	}
	issued, err := m.issue(ctx, now)
	if err != nil {
		var denied *ca.DeniedError
		wait := issuedRetryError
		if errors.As(err, &denied) {
			wait = issuedRetryDenied
		}
		m.nextTry, m.problem = now.Add(wait), err.Error()
		m.log.Error("TLS certificate can't be issued", slog.String("listener", m.listener), slog.String("ca", m.issuer), slog.String("reason", why),
			slog.Any("error", err), slog.Time("next_try", m.nextTry))
		return
	}
	m.nextTry, m.problem = time.Time{}, ""
	m.cur.Store(issued)
	m.log.Info("TLS certificate issued", slog.String("listener", m.listener), slog.String("ca", m.issuer), slog.String("reason", why),
		slog.String("fingerprint_sha256", Fingerprint(issued.Leaf.Raw)), slog.String("serial", issued.Leaf.SerialNumber.Text(16)),
		slog.Time("not_after", issued.Leaf.NotAfter), slog.Time("renew_at", renewAt(issued.Leaf)))
}

// checkIssuer looks up whether the configured CA is a root and remembers it;
// true = blocked. It logs when the state changes (at the start, or when a
// CA of that name appears later), not every run. A database error keeps
// the last state.
func (m *issuedTLS) checkIssuer(ctx context.Context) bool {
	problem, err := IssuerProblem(ctx, m.engine.PKI, m.issuer, m.issuerKey)
	if err != nil {
		m.log.Error("TLS certificate: can't read the CA from the database", slog.String("listener", m.listener), slog.String("ca", m.issuer), slog.Any("error", err))
		return m.blocked.Load() != nil
	}
	old := m.blocked.Load()
	switch {
	case problem != "" && (old == nil || *old != problem):
		m.blocked.Store(&problem)
		m.log.Error("TLS certificate can't come from a root CA – the listener serves the bootstrap certificate", slog.String("listener", m.listener),
			slog.String("ca", m.issuer), slog.String("problem", problem), slog.String("bootstrap_sha256", Fingerprint(m.bootstrap.Leaf.Raw)))
	case problem == "" && old != nil:
		m.blocked.Store(nil)
		m.log.Info("TLS certificate: the CA is no longer a root – issued at the next renewal check", slog.String("listener", m.listener), slog.String("ca", m.issuer))
	}
	return problem != ""
}

// IssuerProblem says why the CA named in admin.tls_issuer or acme.tls_issuer
// (setting) must not issue a listener certificate; "" = it may, or there is
// no CA of that name (the engine names that problem when it refuses).
//
// A root CA is refused (owner 2026-10-24): a root usually carries no name
// constraints, so a listener certificate straight from it would bypass the
// ones of the intermediate. The engine signs no end-entity certificate with
// a root anyway (CA/B BR §6.1.7); this check names the fix before the
// first refusal, at the start and in `config check`.
func IssuerProblem(ctx context.Context, db pkidb.DBTX, issuer, setting string) (string, error) {
	q := pkidb.New(db)
	row, err := q.GetCAByName(ctx, issuer)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", err
	case row.Kind != ca.KindRoot:
		return "", nil
	}
	cas, err := q.ListCAs(ctx)
	if err != nil {
		return "", err
	}
	var subs []string
	for _, c := range cas {
		if c.ParentID.Valid && c.ParentID.String == row.ID && c.Status == ca.StatusActive {
			subs = append(subs, c.Name)
		}
	}
	hint := "create an intermediate under it first"
	if len(subs) > 0 {
		hint = "intermediates of " + issuer + ": " + strings.Join(subs, ", ")
	}
	return fmt.Sprintf("CA %s is a root – name the issuing intermediate in %s (%s)", issuer, setting, hint), nil
}

// TLSIssuerProblems is IssuerProblem for both settings of cfg, read from the
// CA database without changing it (`config check`). An error means the
// database couldn't be read (not there yet, no permission, an older
// schema) – the check is then skipped, not failed.
func TLSIssuerProblems(ctx context.Context, cfg config.Config) ([]string, error) {
	type setting struct{ key, issuer string }
	var check []setting
	if cfg.Admin.TLSIssuer != "" {
		check = append(check, setting{"admin.tls_issuer", cfg.Admin.TLSIssuer})
	}
	if cfg.ACME.DirectTLS() {
		check = append(check, setting{"acme.tls_issuer", cfg.ACME.TLSIssuer})
	}
	if len(check) == 0 {
		return nil, nil
	}
	file, err := store.Layout{DataDir: cfg.DataDir}.TenantDB(store.DefaultTenant, store.KindPKI)
	if err != nil {
		return nil, err
	}
	db, err := store.OpenReadOnly(ctx, file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	var out []string
	for _, s := range check {
		p, perr := IssuerProblem(ctx, db.Read, s.issuer, s.key)
		if perr != nil {
			return nil, perr
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// due says why a new certificate is needed now; "" = it isn't.
func (m *issuedTLS) due(ctx context.Context, c *tls.Certificate, now time.Time) (string, error) {
	if c == nil {
		return "no certificate yet", nil
	}
	leaf := c.Leaf
	switch {
	case !now.Before(renewAt(leaf)):
		return "2/3 of its lifetime passed", nil
	case !sameNames(leaf, m.names, m.ips):
		return "the names changed (" + m.setting + ")", nil
	}
	q := pkidb.New(m.engine.PKI)
	row, err := q.GetCAByName(ctx, m.issuer)
	if errors.Is(err, sql.ErrNoRows) {
		return "CA " + m.issuer + " is not there (" + m.setting + " changed?)", nil
	} else if err != nil {
		return "", err
	}
	if !row.CurrentGeneration.Valid {
		return "", nil // the engine refuses anyway; keep what works
	}
	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: row.ID, Generation: row.CurrentGeneration.Int64})
	if err != nil {
		return "", err
	}
	caCert, err := x509.ParseCertificate(gen.CertDer)
	if err != nil {
		return "", fmt.Errorf("the certificate of CA %s: %w", m.issuer, err)
	}
	if !signedBy(leaf, caCert) {
		return "it is not signed by the current certificate of CA " + m.issuer, nil
	}
	sum := sha256.Sum256(leaf.Raw)
	stored, err := q.GetCertificateByFingerprint(ctx, strings.ToUpper(hex.EncodeToString(sum[:])))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil // e.g. a restored backup older than the certificate: it still verifies
	case err != nil:
		return "", err
	}
	if _, rerr := q.GetRevocation(ctx, stored.ID); rerr == nil {
		return "it was revoked", nil
	} else if !errors.Is(rerr, sql.ErrNoRows) {
		return "", rerr
	}
	return "", nil
}

// signedBy: the CA's current key signed leaf (after a CA renewal with a new
// key it didn't).
func signedBy(leaf, caCert *x509.Certificate) bool { return leaf.CheckSignatureFrom(caCert) == nil }

// sameNames: exactly the configured names – a removed name must leave the
// certificate too.
func sameNames(leaf *x509.Certificate, names []string, ips []netip.Addr) bool {
	if len(leaf.DNSNames) != len(names) || len(leaf.IPAddresses) != len(ips) {
		return false
	}
	return covers(leaf, names, ips)
}

// issue makes a key and a CSR, has the engine sign it and stores key and
// chain. The validity is 90 days, capped by the CA's maximum and its end, so
// a CA that ends soon still gets its listener a certificate.
func (m *issuedTLS) issue(ctx context.Context, now time.Time) (*tls.Certificate, error) {
	days, err := m.validityDays(ctx, now)
	if err != nil {
		return nil, err
	}
	rnd := m.rnd
	if rnd == nil {
		rnd = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
	if err != nil {
		return nil, err
	}
	cn := m.commonName()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: m.names}
	ips := make([]string, 0, len(m.ips))
	for _, ip := range m.ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
		ips = append(ips, ip.String())
	}
	csr, err := x509.CreateCertificateRequest(rnd, tmpl, key)
	if err != nil {
		return nil, err
	}
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "server"}, Principal: authz.System("tls-" + m.listener)}
	out, err := m.engine.Issue(ctx, ca.Request{
		CA: m.issuer, Preset: issuedPreset, CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
		DNSNames: m.names, IPAddresses: ips, IgnoreCSRNames: true, Subject: ca.Subject{CommonName: cn},
		ValidityDays: days, Who: who,
	})
	if err != nil {
		return nil, err
	}
	// fullchain: the certificate and the intermediates; the root is the
	// client's trust anchor and stays out (like certbot's fullchain.pem).
	var certPEM []byte
	for _, der := range append([][]byte{out.CertDER}, out.Chain[:max(len(out.Chain)-1, 0)]...) {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	clear(pkcs8)
	defer clear(keyPEM)
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(out.CertDER); err != nil {
			return nil, err
		}
	}
	// The key first: a crash between the two leaves a pair that doesn't
	// match, which load refuses – the next unseal issues again.
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(m.dir, issuedKeyFile(m.listener)), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("store the key: %w", err)
	}
	if err := writeAtomic(filepath.Join(m.dir, issuedCertFile(m.listener)), certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("store the certificate: %w", err)
	}
	return &c, nil
}

// validityDays: 90, or less when the CA allows less or ends earlier.
func (m *issuedTLS) validityDays(ctx context.Context, now time.Time) (int, error) {
	days := issuedMaxDays
	q := pkidb.New(m.engine.PKI)
	row, err := q.GetCAByName(ctx, m.issuer)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return days, nil // the engine refuses the request and names the problem
	case err != nil:
		return 0, err
	case !row.CurrentGeneration.Valid:
		return days, nil // the same
	}
	if row.MaxValidityDays > 0 && int(row.MaxValidityDays) < days {
		days = int(row.MaxValidityDays)
	}
	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: row.ID, Generation: row.CurrentGeneration.Int64})
	if err != nil {
		return 0, err
	}
	caCert, err := x509.ParseCertificate(gen.CertDer)
	if err != nil {
		return 0, fmt.Errorf("the certificate of CA %s: %w", m.issuer, err)
	}
	if left := int(caCert.NotAfter.Sub(now) / (24 * time.Hour)); left < days {
		if left < 1 {
			return 0, &ca.DeniedError{Reasons: []string{fmt.Sprintf("CA %s ends on %s – renew the CA first", m.issuer, caCert.NotAfter.Format(time.DateOnly))}}
		}
		days = left
	}
	return days, nil
}

func (m *issuedTLS) commonName() string {
	if len(m.names) > 0 {
		return m.names[0]
	}
	if len(m.ips) > 0 {
		return m.ips[0].String()
	}
	return "MyOwnPKI " + m.listener
}

// attention is what the dashboard shows about this listener's certificate.
func (m *issuedTLS) attention(sealed bool) []view.Message {
	m.mu.Lock()
	problem := m.problem
	m.mu.Unlock()
	now := m.clk.Now()
	label := m.label()
	if b := m.blocked.Load(); b != nil {
		return []view.Message{{Kind: view.MessageError, Text: label + ": " + *b + ". Until then the listener serves the bootstrap certificate."}}
	}
	c := m.cur.Load()
	var out []view.Message
	if problem != "" {
		out = append(out, view.Message{Kind: view.MessageError, Text: label + " can't be issued by CA " + m.issuer + ": " + problem})
	}
	switch {
	case c == nil && sealed:
		out = append(out, view.Message{Kind: view.MessageInfo, Text: label + " is issued by CA " + m.issuer + " at the unseal; until then the listener serves the bootstrap certificate.", Href: "/unseal", LinkText: "Unseal"})
	case c != nil && now.After(c.Leaf.NotAfter):
		text := label + " expired on " + view.Date(c.Leaf.NotAfter) + " – the listener serves the bootstrap certificate"
		if sealed {
			out = append(out, view.Message{Kind: view.MessageWarning, Text: text + " until the unseal renews it.", Href: "/unseal", LinkText: "Unseal"})
		} else {
			out = append(out, view.Message{Kind: view.MessageWarning, Text: text + "."})
		}
	case c != nil && sealed && !now.Before(renewAt(c.Leaf)):
		out = append(out, view.Message{Kind: view.MessageWarning, Text: label + " is due for renewal (ends " + view.Date(c.Leaf.NotAfter) + ") – it is renewed at the unseal.", Href: "/unseal", LinkText: "Unseal"})
	}
	return out
}

func (m *issuedTLS) label() string {
	if m.listener == "acme" {
		return "The TLS certificate of the ACME listener"
	}
	return "The admin TLS certificate"
}

// startInfo is the log line at start: what the listener serves now.
func (m *issuedTLS) startInfo() []any {
	c, issued := m.serving(m.clk.Now())
	attrs := []any{slog.String("ca", m.issuer), slog.String("fingerprint_sha256", Fingerprint(c.Leaf.Raw)), slog.Time("not_after", c.Leaf.NotAfter)}
	if issued {
		return append(attrs, slog.String("source", "issued"), slog.Time("renew_at", renewAt(c.Leaf)))
	}
	if b := m.blocked.Load(); b != nil {
		return append(attrs, slog.String("source", "bootstrap"), slog.String("note", *b))
	}
	return append(attrs, slog.String("source", "bootstrap"), slog.String("note", "issued from the CA at the unseal"))
}

// names of an issued certificate for one listener, in the order of the
// config, without duplicates.
func uniqueNames(names []string, ips []netip.Addr) ([]string, []netip.Addr) {
	var n []string
	var a []netip.Addr
	for _, v := range names {
		if !slices.Contains(n, v) {
			n = append(n, v)
		}
	}
	for _, v := range ips {
		if !slices.Contains(a, v) {
			a = append(a, v)
		}
	}
	return n, a
}
