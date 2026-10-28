// Package testinstance builds an initialized instance for tests of the HTTP
// layers (API, web UI): init --demo with the test CA, the services wired like
// the server does, a fake clock and helpers for users and TOTP codes. It is
// imported by tests only.
package testinstance

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) is HMAC-SHA1 by design; test helper only
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Console is the console operator of the tests.
var Console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console:test"}, Principal: authz.Console()}

// Password is the password of every user made with User.
const Password = "a long password for the HTTP tests"

// BrowserOrigin is where the tests' browser runs (passkeys, step 17).
const BrowserOrigin = "https://pki.homelab.lan:9443"

// Options shape the instance.
type Options struct {
	// Hostname is O of the test CA; "" = "pki01".
	Hostname string
	// BaseURL of the test CA; "" = http://pki.homelab.lan.
	BaseURL string
	// NoPasskeys leaves passkeys off (default: on for BrowserOrigin).
	NoPasskeys bool
}

// Instance is an initialized instance, sealed.
type Instance struct {
	Auth    *auth.Service
	Engine  *ca.Engine
	Ring    *keys.Keyring
	Presets *preset.Set
	Clock   *clock.Fake
	// SystemDB, InstanceAudit, TenantAudit and PKIDB are open for checks.
	SystemDB, InstanceAudit, TenantAudit, PKIDB *store.DB
	// Config is the configuration init ran with (data directory, auth key).
	Config config.Config

	Passphrase   string // unseal passphrase
	DemoPassword string // password of the init user "demo"
	CAIDs        map[string]string
	secrets      map[string][]byte // TOTP secrets by user name
}

// New runs init --demo with the test CA and wires the services. The clock is
// not on a whole second: the engine works in seconds, sessions in
// milliseconds, and the tests must see both.
func New(t *testing.T, o Options) *Instance {
	t.Helper()
	if o.Hostname == "" {
		o.Hostname = "pki01"
	}
	if o.BaseURL == "" {
		o.BaseURL = "http://pki.homelab.lan"
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	v := &Instance{
		Clock:   clock.NewFake(clock.System{}.Now().UTC().Truncate(time.Second).Add(700 * time.Millisecond)),
		secrets: map[string][]byte{}, CAIDs: map[string]string{},
	}
	res, err := setup.Run(t.Context(), setup.Options{
		Config: cfg, Mode: setup.Demo, WithCA: true, CABaseURL: o.BaseURL, Hostname: o.Hostname, Clock: v.Clock, Who: Console, TestKDF: true,
	}, setup.NewLineInput(strings.NewReader(""), io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return v.open(t, cfg, res.DemoSecretsFile, o)
}

// OpenExisting opens a data directory made elsewhere – an older release, a
// restored backup – with the secrets file of its `init --demo`. Like
// server.Open it first applies the migrations of this build (the upgrade
// test, PHASE2 step 15).
func OpenExisting(t *testing.T, dataDir, demoSecretsFile string) *Instance {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = dataDir
	v := &Instance{
		Clock:   clock.NewFake(clock.System{}.Now().UTC().Truncate(time.Second).Add(700 * time.Millisecond)),
		secrets: map[string][]byte{}, CAIDs: map[string]string{},
	}
	if _, err := store.Migrate(t.Context(), store.Layout{DataDir: dataDir}, store.DefaultTenant, v.Clock.Now); err != nil {
		t.Fatalf("migrate %s: %v", dataDir, err)
	}
	return v.open(t, cfg, demoSecretsFile, Options{})
}

// open reads the demo secrets and wires the services to the databases.
func (v *Instance) open(t *testing.T, cfg config.Config, demoSecretsFile string, o Options) *Instance {
	t.Helper()
	demo, err := os.ReadFile(demoSecretsFile) // #nosec G304 -- test: the instance's own secrets file
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(demo), "\n") {
		line = strings.TrimRight(line, "\r")
		if p, ok := strings.CutPrefix(line, "unseal passphrase: "); ok {
			v.Passphrase = p
		}
		if p, ok := strings.CutPrefix(line, "admin password: "); ok {
			v.DemoPassword = p
		}
		if s, ok := strings.CutPrefix(line, "secret:"); ok {
			v.secrets["demo"] = decodeSecret(t, s)
		}
	}

	l := store.Layout{DataDir: cfg.DataDir}
	open := func(path string) *store.DB {
		db, oerr := store.Open(t.Context(), path)
		if oerr != nil {
			t.Fatal(oerr)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	pkiPath, _ := l.TenantDB(store.DefaultTenant, store.KindPKI)
	taPath, _ := l.TenantDB(store.DefaultTenant, store.KindAudit)
	v.SystemDB = open(l.SystemDB())
	v.InstanceAudit = open(l.InstanceAuditDB())
	pki := open(pkiPath)
	v.PKIDB, v.Config = pki, cfg
	v.TenantAudit = open(taPath)

	key, _, err := auth.LoadKey(cfg.AuthKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	v.Ring = keys.New(v.SystemDB.Write, v.InstanceAudit.Write, v.Clock, keys.TestKDF())
	if v.Presets, err = preset.Builtin(); err != nil {
		t.Fatal(err)
	}
	v.Engine = &ca.Engine{
		PKI: pki.Write, Audit: v.TenantAudit.Write, Scope: store.TenantScope(store.DefaultTenant), Keys: v.Ring, Presets: v.Presets,
		Clock: v.Clock, ServerKeygen: func(context.Context) (bool, error) { return true, nil },
		OtherPredecessor: func(ctx context.Context) (predecessor.Policy, error) {
			settings, settingsErr := systemdb.New(v.SystemDB.Read).GetTenantSettings(ctx, store.DefaultTenant)
			if settingsErr != nil {
				return predecessor.Policy{}, settingsErr
			}
			return predecessor.Policy{Choice: settings.OtherPredecessorChoice, Days: int(settings.OtherPredecessorDays)}, nil
		},
	}
	v.Auth = auth.NewService(v.SystemDB.Write, v.InstanceAudit.Write, key, v.Clock)
	v.Auth.Hasher = auth.NewHasher(auth.TestParams(), 4, time.Second)
	if !o.NoPasskeys {
		if v.Auth.Passkeys, err = auth.NewPasskeys("pki.homelab.lan", BrowserOrigin); err != nil {
			t.Fatal(err)
		}
	}
	cas, err := ca.ListCAs(t.Context(), pki.Read)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		v.CAIDs[c.Name] = c.ID
	}
	return v
}

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", "")))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// User creates a user with Password and roles in the default tenant.
func (v *Instance) User(t *testing.T, name string, instanceAdmin bool, roles ...authz.Binding) {
	t.Helper()
	for i := range roles {
		roles[i].Tenant = store.DefaultTenant
	}
	enr, err := v.Auth.CreateUser(t.Context(), auth.NewUserRequest{Username: name, Password: Password, InstanceAdmin: instanceAdmin, Roles: roles, Who: Console})
	if err != nil {
		t.Fatal(err)
	}
	v.secrets[name] = decodeSecret(t, enr.Secret)
}

// Code is the TOTP code of name now (RFC 6238: HMAC-SHA1, 30 s, 6 digits).
func (v *Instance) Code(name string) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(v.Clock.Now().Unix()/30)) // #nosec G115 -- a time after 1970
	mac := hmac.New(sha1.New, v.secrets[name])
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

// Unseal unlocks the keyring as the console.
func (v *Instance) Unseal(t *testing.T) {
	t.Helper()
	if err := v.Ring.Unseal(t.Context(), []byte(v.Passphrase), Console); err != nil {
		t.Fatal(err)
	}
}

// Audit lists "action/result" of an audit log (direct entries are there at
// once; outbox entries need a delivery, which these tests don't run).
func Audit(t *testing.T, db *store.DB) []string {
	t.Helper()
	rows, err := db.Read.QueryContext(t.Context(), `SELECT action, result FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a, r string
		if err := rows.Scan(&a, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+"/"+r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// AuditIPs lists "action/result ip" of an audit log.
func AuditIPs(t *testing.T, db *store.DB) []string {
	t.Helper()
	rows, err := db.Read.QueryContext(t.Context(), `SELECT action, result, coalesce(source_ip, '') FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a, r, ip string
		if err := rows.Scan(&a, &r, &ip); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+"/"+r+" "+ip)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Deliver moves the outbox entries of system.db and pki.db into their audit
// logs, as the server's deliverer does.
func (v *Instance) Deliver(t *testing.T) {
	t.Helper()
	d := &audit.Deliverer{
		Routes: []audit.Route{
			{Source: "system", From: v.SystemDB.Write, To: v.InstanceAudit.Write, Scope: store.InstanceScope},
			{Source: "pki", From: v.PKIDB.Write, To: v.TenantAudit.Write, Scope: store.TenantScope(store.DefaultTenant)},
		},
		Clock: v.Clock, Log: slog.New(slog.DiscardHandler),
	}
	if _, err := d.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// UserID is the ID of the user name.
func (v *Instance) UserID(t *testing.T, name string) string {
	t.Helper()
	var id string
	if err := v.SystemDB.Read.QueryRowContext(t.Context(), `SELECT id FROM users WHERE username = ?`, name).Scan(&id); err != nil {
		t.Fatalf("user %s: %v", name, err)
	}
	return id
}

// TOTP is the RFC 6238 code of a Base32 secret (as shown at enrollment) at t.
func TOTP(secret string, at time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30)) // #nosec G115 -- a time after 1970
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}
