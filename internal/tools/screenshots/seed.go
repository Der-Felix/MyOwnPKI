package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/analysis"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/report"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// The inventory seeds (docs/PHASE3.md step 50) fill what the README demo
// leaves empty, so that every page of the UI shows data: agents, alerts, TLS
// endpoints, certificates over several weeks and a few findings for the
// analysis. Everything goes through the services the server uses; only what
// has no public way in (the age of a row) is set with one UPDATE. Names stay
// neutral (homelab.example, 192.0.2.0/24).

// demoVersion is the server version of the demo: the analysis compares the
// agents' versions with it, and "dev" would leave that rule unassessed.
const demoVersion = "0.3.8"

// passAll is the http-01 check of the demo: it never connects anywhere.
type passAll struct{}

func (passAll) Check(context.Context, string, string, string, string) error { return nil }

// demoNotifier is the notification test button without a channel behind it.
type demoNotifier struct{}

func (demoNotifier) Names() []string { return []string{"email", "webhook"} }
func (demoNotifier) Send(context.Context, keys.Who) ([]notify.Result, error) {
	return []notify.Result{{Channel: "email", OK: true}, {Channel: "webhook", OK: true}}, nil
}

// seedInventory runs once, before the first sign-in, while the instance is
// sealed; it unseals for the issuances and seals again.
func (in *instance) seedInventory(ctx context.Context, clk clock.Clock) error {
	if err := in.ring.Unseal(ctx, []byte(in.passphrase), console); err != nil {
		return err
	}
	defer func() { _ = in.ring.Seal(ctx, console) }()
	e := in.engine
	pq := pkidb.New(e.PKI)
	now := clk.Now().UTC()

	dist, err := in.seedPackages()
	if err != nil {
		return fmt.Errorf("agent packages: %w", err)
	}
	in.dist = dist
	if err = in.seedCertificates(ctx, pq, now); err != nil {
		return fmt.Errorf("certificates: %w", err)
	}
	svc, err := in.seedAgents(ctx, clk, now)
	if err != nil {
		return fmt.Errorf("agents: %w", err)
	}
	scan, err := in.seedEndpoints(ctx, clk, pq, now)
	if err != nil {
		return fmt.Errorf("endpoints: %w", err)
	}
	cas, err := e.CAs(ctx, console)
	if err != nil {
		return fmt.Errorf("authorities: %w", err)
	}
	for _, c := range cas {
		if c.Name == "issuing" {
			in.issuingID = c.ID
		}
	}
	// The instance was set up in the past: its first CRLs ran out since.
	if _, err = e.RenewCRLs(ctx, "inventory"); err != nil {
		return fmt.Errorf("CRLs: %w", err)
	}
	rules := monitor.DefaultRules()
	eval := &monitor.Evaluator{Engine: e, Agents: svc, Seal: in.ring.Status, Rules: rules, Scan: scan,
		Who: keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "monitor"}, Principal: authz.System("monitor")}}
	alerts := &monitor.Store{DB: in.sys.Write, Tenant: store.DefaultTenant}
	if err = seedAlerts(ctx, alerts, eval, now); err != nil {
		return fmt.Errorf("alerts: %w", err)
	}

	users, err := in.deps.Auth.ListUsers(ctx, console)
	if err != nil {
		return fmt.Errorf("users: %w", err)
	}
	for _, u := range users {
		if u.Username == "alex" {
			in.userID = u.ID
		}
	}

	in.deps.Agents = svc
	in.deps.AgentDist = in.dist
	in.deps.AgentBaseURL = "https://pki.homelab.example:8444"
	in.deps.AgentTLSIssuer = "issuing" // the CA that signs the agent listener certificate
	in.deps.ServerVersion = demoVersion
	in.deps.Alerts = alerts
	in.deps.Notifier = demoNotifier{}
	in.deps.Endpoints = &monitor.Endpoints{Service: scan, Eval: eval, Clock: clk}
	in.deps.Reports = report.NewService(report.Deps{Tenant: store.DefaultTenant, Engine: e, Agents: svc, Alerts: alerts,
		Rules: rules, ServerVersion: demoVersion, Clock: clk})
	in.deps.Analysis = analysis.NewService(analysis.Deps{Tenant: store.DefaultTenant, Engine: e, Agents: svc, Scan: scan,
		ServerVersion: demoVersion, Clock: clk})
	return nil
}

func dbStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// historyCert is one certificate of the back-dated history: it is created
// ago in the past and ends endsIn days from now (negative: it ended).
type historyCert struct {
	name   string
	ago    time.Duration
	endsIn int
}

const week = 7 * 24 * time.Hour

// seedHistory issues the certificates that give the report charts their
// weeks: a wave of fourteen that end in the same week, nine with other
// lifetimes and some that ended already. It runs first, in the order of the
// time, with the clock moved back (the instance was set up fourteen weeks
// ago, see newInstanceWith), so that created_at and the audit log are
// consistent. A certificate has no created_at to update afterwards.
func (in *instance) seedHistory(ctx context.Context) error {
	if err := in.ring.Unseal(ctx, []byte(in.passphrase), console); err != nil {
		return err
	}
	defer func() { _ = in.ring.Seal(ctx, console) }()
	var plan []historyCert
	for i := 1; i <= 14; i++ { // the wave: created over three weeks, all end in 45 days
		plan = append(plan, historyCert{fmt.Sprintf("app%02d.homelab.example", i), time.Duration(i%4)*week + time.Duration(i)*time.Hour, 45})
	}
	for i, endsIn := range []int{9, 16, 23, 30, 58, 65, 72, 79, 86} { // the other weeks of the timeline
		plan = append(plan, historyCert{fmt.Sprintf("svc%02d.homelab.example", i+1), time.Duration(i+1)*week - 3*time.Hour, endsIn})
	}
	// Earlier issuances: six ended more than 30 days ago (the monitor no longer
	// reports those), two are still valid.
	for i, endsIn := range []int{-32, -34, -36, -40, -45, -50} {
		plan = append(plan, historyCert{fmt.Sprintf("old%02d.homelab.example", i+1), time.Duration(i+6)*week + 5*time.Hour, endsIn})
	}
	for i, endsIn := range []int{4, 12} {
		plan = append(plan, historyCert{fmt.Sprintf("old%02d.homelab.example", i+7), time.Duration(i+3)*week + 5*time.Hour, endsIn})
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].ago > plan[j].ago })
	in.history = map[string]string{}
	for _, c := range plan {
		days := c.endsIn + int((c.ago+24*time.Hour-1)/(24*time.Hour)) // ends endsIn days from now, give or take a day
		in.shift.set(c.ago)
		out, err := in.engine.Issue(ctx, ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{c.name}, ValidityDays: days, Who: console})
		in.shift.set(0)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		in.history[c.name] = out.ID
		time.Sleep(2 * time.Millisecond) // IDs sort by time
	}
	return nil
}

// seedCertificates adds what the analysis rules need on top of the history:
// one renewal loop, two sources for one name, a weak key, an unused ACME
// account and domain, and ACME orders and an agent account for part of the
// wave (the source classes of the issuance chart).
func (in *instance) seedCertificates(ctx context.Context, q *pkidb.Queries, now time.Time) error {
	e := in.engine
	issue := func(name string) (*ca.Issued, error) {
		out, err := e.Issue(ctx, ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{name}, Who: console})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		time.Sleep(2 * time.Millisecond) // IDs sort by time
		return out, nil
	}
	// A renewal loop: the same name three times within a day.
	for range 3 {
		if _, err := issue("ci-runner.homelab.example"); err != nil {
			return err
		}
	}
	// Two sources for one name: one issued in the UI, one through ACME.
	if _, err := issue("wiki.homelab.example"); err != nil {
		return err
	}
	wiki, err := issue("wiki.homelab.example")
	if err != nil {
		return err
	}

	// ACME accounts: the approved one of the ACME sample (found by its
	// contact), a retired one and one that belongs to an agent (set later).
	accounts, err := q.ListACMEAccounts(ctx, 20)
	if err != nil {
		return err
	}
	for _, a := range accounts {
		if a.ApprovedAt.Valid {
			in.accountID = a.ID
		}
	}
	if in.accountID == "" {
		return errors.New("the approved ACME account of the sample is missing")
	}
	newAccount := func(thumb string, ago time.Duration) (string, error) {
		id, _ := ids.New("acc", now.Add(-ago), rand.Reader)
		ierr := q.InsertACMEAccount(ctx, pkidb.InsertACMEAccountParams{ID: id, KeyThumbprint: thumb, Jwk: `{}`, Status: "valid",
			Contact: `["mailto:old-backup@homelab.example"]`, ApprovedAt: sql.NullString{String: dbStamp(now.Add(-ago)), Valid: true},
			ApprovedBy: sql.NullString{String: "demo", Valid: true}, CreatedAt: dbStamp(now.Add(-ago)), CreatedIp: "192.0.2.30",
			UpdatedAt: dbStamp(now.Add(-ago))})
		return id, ierr
	}
	if _, err = newAccount("Zr4kT7mQe1VbX9nC0pLsJ3wYd8uFa2hGoKi5NcBqE6A", 45*24*time.Hour); err != nil {
		return err
	}
	agentAccount, err := newAccount("b7Kd3Wn9QxT1mLc5Vr0Ye8uHfJ2oGsZp4NaBiE6CqXw", 30*24*time.Hour)
	if err != nil {
		return err
	}
	orderFor := func(account, certID, name string, ago time.Duration) error {
		id, _ := ids.New("ord", now.Add(-ago), rand.Reader)
		if ierr := q.InsertACMEOrder(ctx, pkidb.InsertACMEOrderParams{ID: id, AccountID: account, Status: "pending",
			Identifiers: `[{"type":"dns","value":"` + name + `"}]`, ExpiresAt: dbStamp(now.Add(-ago + 24*time.Hour)),
			CreatedAt: dbStamp(now.Add(-ago)), UpdatedAt: dbStamp(now.Add(-ago))}); ierr != nil {
			return ierr
		}
		_, xerr := e.PKI.ExecContext(ctx, `UPDATE acme_orders SET status = 'valid', certificate_id = ? WHERE id = ?`, certID, id)
		return xerr
	}
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("app%02d.homelab.example", i)
		if err = orderFor(in.accountID, in.history[name], name, time.Duration(i%4)*week); err != nil {
			return err
		}
	}
	if err = orderFor(in.accountID, wiki.ID, "wiki.homelab.example", time.Hour); err != nil {
		return err
	}
	for i := 5; i <= 6; i++ {
		name := fmt.Sprintf("app%02d.homelab.example", i)
		if err = orderFor(agentAccount, in.history[name], name, time.Duration(i%4)*week); err != nil {
			return err
		}
	}
	in.agentAccountID = agentAccount // linked to an agent by seedAgents

	// An unused domain.
	issuing, wild := "issuing", false
	d, err := e.CreateDomain(ctx, ca.DomainRequest{Name: "corp.example", DomainSettings: ca.DomainSettings{CA: &issuing, Wildcards: &wild}, Who: console})
	if err != nil {
		return err
	}
	in.domainID = d.ID
	if _, err = e.PKI.ExecContext(ctx, `UPDATE domains SET created_at = ? WHERE id = ?`, dbStamp(now.Add(-60*24*time.Hour)), d.ID); err != nil {
		return err
	}

	// A certificate of another CA with a short RSA key, as an import from an
	// old tool would leave it: self-signed, RSA 1024.
	weak, err := weakCertificate()
	if err != nil {
		return err
	}
	if _, err := e.ImportExternal(ctx, weak, console); err != nil {
		return err
	}
	return nil
}

// weakCertificate is a self-signed end-entity certificate with an RSA key of
// 1024 bits, for the weak_key finding. The key is thrown away.
func weakCertificate() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- the point of the sample: a weak key to be found
	if err != nil {
		return nil, err
	}
	now := time.Now() //nolint:forbidigo // the dev tool runs on the wall clock
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4711), Subject: pkix.Name{CommonName: "vpn-old.homelab.example", Organization: []string{"Homelab"}},
		DNSNames: []string{"vpn-old.homelab.example"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(0, 8, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// seedAgents enrolls three agents through the real enrollment (the check
// always passes), lets them report deployments, and leaves a fourth
// enrollment waiting for approval. One agent is made silent, one runs an
// older version.
func (in *instance) seedAgents(ctx context.Context, clk clock.Clock, now time.Time) (*agents.Service, error) {
	e := in.engine
	if _, err := e.CreateIntermediate(ctx, ca.IntermediateRequest{CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.example"},
		Parent: "root", Subject: ca.Subject{CommonName: "Homelab Agent CA", Organization: "Homelab"}, EKULimit: []string{"clientAuth"}, Who: console}); err != nil {
		return nil, err
	}
	mode := tenant.EnrollAuto
	svc := &agents.Service{
		PKI: e.PKI, Tenant: store.DefaultTenant, Engine: e, CA: "agent-ca", Checker: passAll{}, Clock: clk, Log: slog.New(slog.DiscardHandler),
		Mode: func(context.Context) (string, error) { return mode, nil },
		Install: &agents.InstallSource{Dist: in.dist, BaseURL: "https://pki.homelab.example:8444", TLSIssuer: "issuing",
			ACMEDirectory: func() string { return in.deps.ACMEDirectory }, Clock: clk},
	}
	enroll := func(host, version string) (*agents.Status, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, key)
		if err != nil {
			return nil, err
		}
		out, err := svc.Enroll(ctx, agents.EnrollInput{Hostname: host, Method: agents.MethodWebroot, OS: "linux", Arch: "amd64", Version: version,
			SourceIP: "192.0.2.20", CSRDER: der})
		if err != nil {
			return nil, fmt.Errorf("enroll %s: %w", host, err)
		}
		return svc.EnrollStatus(ctx, agents.StatusInput{ID: out.ID, Handle: out.Handle, CheckReady: true, SourceIP: "192.0.2.20"})
	}
	serialOf := func(name string) (serial, fingerprint, notAfter string, err error) {
		page, err := e.Certificates(ctx, console, ca.CertificateFilter{Search: name})
		if err != nil {
			return "", "", "", err
		}
		if len(page.Items) == 0 {
			return "", "", "", fmt.Errorf("no certificate for %s", name)
		}
		c := page.Items[0]
		return c.Serial, c.Fingerprint, c.NotAfter.UTC().Format(time.RFC3339), nil
	}

	type agentPlan struct {
		host, version, state, lastError string
		silentFor                       time.Duration
	}
	var first string
	for i, p := range []agentPlan{
		{host: "proxy-01.homelab.example", version: demoVersion, state: "deployed"},
		{host: "proxy-02.homelab.example", version: "0.3.2", state: "failed", lastError: "reload failed: nginx: configuration file test failed"},
		{host: "nas.homelab.example", version: demoVersion, state: "deployed", silentFor: 50 * time.Hour},
	} {
		st, err := enroll(p.host, p.version)
		if err != nil {
			return nil, err
		}
		if st.State != agents.StateAdmitted {
			return nil, fmt.Errorf("%s was not admitted: %s", p.host, st.State)
		}
		cert, err := x509.ParseCertificate(st.CertDER)
		if err != nil {
			return nil, err
		}
		caller, err := svc.Identify(ctx, cert, "192.0.2.20")
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("app%02d.homelab.example", i+1)
		serial, fp, notAfter, err := serialOf(name)
		if err != nil {
			return nil, err
		}
		dep := agents.DeploymentReport{Name: "web", Profile: "nginx", Names: []string{name}, Challenge: "http-01", State: p.state, Serial: serial,
			NotAfter: notAfter, Fingerprint: fp, DeployedAt: now.Add(-2 * 24 * time.Hour).Format(time.RFC3339), LastError: p.lastError}
		if err := svc.Report(ctx, caller, agents.ReportInput{Version: p.version, OS: "linux", Arch: "amd64", PackageFormat: "deb",
			Deployments: []agents.DeploymentReport{dep}}); err != nil {
			return nil, fmt.Errorf("report %s: %w", p.host, err)
		}
		if p.silentFor > 0 {
			if _, err := e.PKI.ExecContext(ctx, `UPDATE agents SET last_seen_at = ? WHERE id = ?`, dbStamp(now.Add(-p.silentFor)), caller.Agent.ID); err != nil {
				return nil, err
			}
		}
		if first == "" {
			first = caller.Agent.ID
		}
		if p.version != demoVersion {
			in.agentOldID = caller.Agent.ID
		}
	}
	in.agentID = first
	// The agent-owned ACME account of seedCertificates.
	if _, err := e.PKI.ExecContext(ctx, `UPDATE acme_accounts SET agent_id = ? WHERE id = ?`, first, in.agentAccountID); err != nil {
		return nil, err
	}

	// A host that waits for approval (manual mode for this one).
	mode = tenant.EnrollManual
	st, err := enroll("printer.homelab.example", "0.3.8")
	if err != nil {
		return nil, err
	}
	if st.State != agents.StatePending {
		return nil, fmt.Errorf("printer.homelab.example should wait for approval, state: %s", st.State)
	}
	in.enrollHost = "printer.homelab.example"
	return svc, nil
}

// seedEndpoints adds five TLS endpoints and writes what a scan would have
// stored: one that serves its current certificate, one that serves an older
// one, one that is unreachable, one with a certificate of another CA and one
// that was never scanned.
func (in *instance) seedEndpoints(ctx context.Context, clk clock.Clock, q *pkidb.Queries, now time.Time) (*tlsscan.Service, error) {
	e := in.engine
	svc := &tlsscan.Service{PKI: e.PKI, Tenant: store.DefaultTenant, Engine: e, Clock: clk,
		Settings: tlsscan.Settings{Interval: time.Hour, Timeout: 5 * time.Second, Ports: []int{443, 8443}, MaxEndpoints: 50}}
	cert := func(name string, newest bool) (*ca.CertificateInfo, error) {
		page, err := e.Certificates(ctx, console, ca.CertificateFilter{Search: name})
		if err != nil {
			return nil, err
		}
		if len(page.Items) == 0 {
			return nil, fmt.Errorf("no certificate for %s", name)
		}
		c := page.Items[0] // newest first
		if !newest {
			c = page.Items[len(page.Items)-1]
		}
		return &c, nil
	}
	add := func(host string, port int) (string, error) {
		ep, err := svc.Create(ctx, console, tlsscan.Request{Host: host, Port: port})
		if err != nil {
			return "", fmt.Errorf("endpoint %s: %w", host, err)
		}
		return ep.ID, nil
	}
	next := dbStamp(now.Add(40 * time.Minute))
	good := func(id string, c *ca.CertificateInfo, since time.Time, same int64) error {
		return q.RecordScanSuccess(ctx, pkidb.RecordScanSuccessParams{
			LastScanAt: sql.NullString{String: dbStamp(now.Add(-20 * time.Minute)), Valid: true}, LastOkAt: sql.NullString{String: dbStamp(now.Add(-20 * time.Minute)), Valid: true},
			Fingerprint: sql.NullString{String: c.Fingerprint, Valid: true}, Serial: sql.NullString{String: c.Serial, Valid: true},
			Subject: sql.NullString{String: c.Subject, Valid: true}, Issuer: sql.NullString{String: "CN=Homelab Issuing CA,O=Homelab", Valid: true},
			NotBefore: sql.NullString{String: dbStamp(c.NotBefore), Valid: true}, NotAfter: sql.NullString{String: dbStamp(c.NotAfter), Valid: true},
			ChainLen: sql.NullInt64{Int64: 2, Valid: true}, ChainState: sql.NullString{String: tlsscan.ChainTrusted, Valid: true},
			TlsVersion: sql.NullString{String: "TLS 1.3", Valid: true}, SameCount: same,
			FingerprintSince: sql.NullString{String: dbStamp(since), Valid: true}, NextScanAt: next, ID: id})
	}

	web, err := cert("web.homelab.example", true)
	if err != nil {
		return nil, err
	}
	id, err := add("web.homelab.example", 443)
	if err != nil {
		return nil, err
	}
	if err = good(id, web, now.Add(-30*24*time.Hour), 400); err != nil {
		return nil, err
	}

	// Serves the oldest of three certificates for its name: a mismatch.
	old, err := cert("ci-runner.homelab.example", false)
	if err != nil {
		return nil, err
	}
	if id, err = add("ci-runner.homelab.example", 443); err != nil {
		return nil, err
	}
	if err = good(id, old, now.Add(-6*time.Hour), 12); err != nil {
		return nil, err
	}

	// Unreachable: five failed scans in a row.
	if id, err = add("nas.homelab.example", 8443); err != nil {
		return nil, err
	}
	if _, err = e.PKI.ExecContext(ctx, `UPDATE endpoints SET last_scan_at = ?, last_error_kind = ?, last_error = ?, fail_streak = 5, next_scan_at = ? WHERE id = ?`,
		dbStamp(now.Add(-10*time.Minute)), tlsscan.KindTimeout, "no answer within 5 seconds", next, id); err != nil {
		return nil, err
	}

	// A certificate of another CA (not in this PKI).
	if id, err = add("printer.homelab.example", 443); err != nil {
		return nil, err
	}
	if _, err = e.PKI.ExecContext(ctx, `UPDATE endpoints SET last_scan_at = ?, last_ok_at = ?, fail_streak = 0, fingerprint = ?, serial = ?, subject = ?, issuer = ?,
		not_before = ?, not_after = ?, chain_len = 1, chain_state = ?, tls_version = ?, same_count = 30, fingerprint_since = ?, next_scan_at = ? WHERE id = ?`,
		dbStamp(now.Add(-15*time.Minute)), dbStamp(now.Add(-15*time.Minute)), "9F8E7D6C5B4A39281716059E8D7C6B5A49382716F5E4D3C2B1A09F8E7D6C5B4A", "0A1B2C3D",
		"CN=printer.homelab.example", "CN=Printer Vendor CA", dbStamp(now.Add(-300*24*time.Hour)), dbStamp(now.Add(65*24*time.Hour)),
		tlsscan.ChainUntrusted, "TLS 1.2", dbStamp(now.Add(-300*24*time.Hour)), next, id); err != nil {
		return nil, err
	}

	// Never scanned (just added).
	if _, err = add("router.homelab.example", 443); err != nil {
		return nil, err
	}
	return svc, nil
}

// seedAlerts writes an alert history of five weeks (some opened and resolved,
// by Sync at past times) and ends with the real evaluation of the seeded
// instance: what is open now is what the monitor would find.
func seedAlerts(ctx context.Context, s *monitor.Store, eval *monitor.Evaluator, now time.Time) error {
	f := func(key, kind, subject, severity, detail, href string) monitor.Finding {
		return monitor.Finding{Key: key, Kind: kind, Subject: subject, Severity: severity, Detail: detail, Href: href}
	}
	a := f("cert_expiry:old-1", monitor.KindCertExpiry, "mail.homelab.example", monitor.Warning, "ends in 13 days", "/certificates")
	b := f("agent_silent:old-1", monitor.KindAgentSilent, "backup.homelab.example", monitor.Critical, "no report for 26 hours", "/agents")
	c := f("scan_unreachable:old-1", monitor.KindScanUnreachable, "router.homelab.example:443", monitor.Warning, "3 scans failed", "/endpoints")
	d := f("deploy_failed:old-1", monitor.KindDeployFailed, "proxy-02 / web", monitor.Critical, "reload failed", "/agents")
	day := 24 * time.Hour
	for _, step := range []struct {
		ago      time.Duration
		findings []monitor.Finding
	}{
		{27 * day, []monitor.Finding{a, b}},
		{20 * day, []monitor.Finding{a, b, c}},
		{13 * day, []monitor.Finding{a, c}},
		{6 * day, []monitor.Finding{c, d}},
		{3 * day, []monitor.Finding{d}},
	} {
		if _, err := s.Sync(ctx, now.Add(-step.ago), step.findings); err != nil {
			return err
		}
	}
	found, err := eval.Evaluate(ctx, now)
	if err != nil {
		return err
	}
	_, err = s.Sync(ctx, now, found)
	return err
}

// seedPackages writes placeholder files with the names of the agent packages, so
// that the install and update pages find their artifacts. They are not
// installable and live in the temporary directory of the instance.
func (in *instance) seedPackages() (*agentdist.Store, error) {
	if err := os.MkdirAll(in.packageDir, 0o750); err != nil {
		return nil, err
	}
	dist := agentdist.New(in.packageDir, demoVersion)
	names := []string{agentdist.Checksums}
	for _, arch := range agentdist.Arches {
		for _, format := range agentdist.Formats {
			name, _ := dist.Name(format, arch)
			names = append(names, name)
		}
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(in.packageDir, name), []byte("demo placeholder, not an installable package\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return dist, nil
}

// shiftClock is the real clock, moved back by a settable span. It is set only
// while the seeds issue certificates in the past (an immutable certificate
// has no created_at to update); every other call sees the real time.
type shiftClock struct {
	mu   sync.Mutex
	back time.Duration
}

func (c *shiftClock) set(back time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.back = back
}

func (c *shiftClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().UTC().Add(-c.back) //nolint:forbidigo // the dev tool runs on the wall clock
}
