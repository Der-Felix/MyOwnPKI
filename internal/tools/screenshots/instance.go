package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) is HMAC-SHA1 by design
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/web"
)

// The screenshots show the real UI of a throwaway demo instance with neutral
// names (owner 2026-10-17): O=Homelab, the test CA's CN without a host name,
// example names under homelab.example. No page shows a secret: no TOTP QR
// code, no recovery codes, no passphrase.

var console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console:screenshots"}, Principal: authz.Console()}

// instance is the demo instance and what the screenshots need of it.
type instance struct {
	deps       web.AppDeps
	ring       *keys.Keyring
	passphrase string // a copy per unseal: the keyring clears what it gets
	session    string // cookie value of a signed-in "demo" user
	detailID   string // the certificate shown on the detail page
	close      func()
}

func newInstance(ctx context.Context, dir string) (*instance, error) {
	cfg := config.Default()
	cfg.DataDir = dir
	res, err := setup.Run(ctx, setup.Options{
		Config: cfg, Mode: setup.Demo, WithCA: true, CABaseURL: "http://pki.homelab.example", Hostname: "Homelab", Who: console,
	}, setup.NewLineInput(strings.NewReader(""), io.Discard))
	if err != nil {
		return nil, fmt.Errorf("init --demo: %w", err)
	}
	demo, err := os.ReadFile(res.DemoSecretsFile)
	if err != nil {
		return nil, err
	}
	in := &instance{}
	var password, secret string
	for line := range strings.SplitSeq(string(demo), "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, "unseal passphrase: "); ok {
			in.passphrase = v
		}
		if v, ok := strings.CutPrefix(line, "admin password: "); ok {
			password = v
		}
		if v, ok := strings.CutPrefix(line, "secret:"); ok {
			secret = strings.ReplaceAll(strings.TrimSpace(v), " ", "")
		}
	}
	if in.passphrase == "" || password == "" || secret == "" {
		return nil, errors.New("the demo secrets file lacks passphrase, password or TOTP secret")
	}

	l := store.Layout{DataDir: dir}
	var dbs []*store.DB
	in.close = func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	}
	open := func(path string, perr error) *store.DB {
		if err != nil || perr != nil {
			err = errors.Join(err, perr)
			return nil
		}
		db, oerr := store.Open(ctx, path)
		if oerr != nil {
			err = oerr
			return nil
		}
		dbs = append(dbs, db)
		return db
	}
	sys := open(l.SystemDB(), nil)
	ia := open(l.InstanceAuditDB(), nil)
	pki := open(l.TenantDB(store.DefaultTenant, store.KindPKI))
	ta := open(l.TenantDB(store.DefaultTenant, store.KindAudit))
	if err != nil {
		in.close()
		return nil, err
	}
	key, _, err := auth.LoadKey(cfg.AuthKeyFile())
	if err != nil {
		in.close()
		return nil, err
	}
	presets, err := preset.Builtin()
	if err != nil {
		in.close()
		return nil, err
	}
	clk := clock.System{}
	in.ring = keys.New(sys.Write, ia.Write, clk)
	engine := &ca.Engine{
		PKI: pki.Write, Audit: ta.Write, Scope: store.TenantScope(store.DefaultTenant), Keys: in.ring, Presets: presets, Clock: clk,
		ServerKeygen: func(context.Context) (bool, error) { return true, nil },
	}
	authSvc := auth.NewService(sys.Write, ia.Write, key, clk)
	in.deps = web.AppDeps{Auth: authSvc, Engine: engine, Keys: in.ring, Presets: presets, Clock: clk, Demo: true, Tenant: store.DefaultTenant}

	if serr := in.sampleCertificates(ctx, engine); serr != nil {
		in.close()
		return nil, serr
	}
	if in.session, err = signIn(ctx, authSvc, password, secret); err != nil {
		in.close()
		return nil, err
	}
	return in, nil
}

// sampleCertificates issues a few certificates under homelab.example: CSR
// and server keys, one that expires soon and one revoked.
func (in *instance) sampleCertificates(ctx context.Context, e *ca.Engine) error {
	if err := in.ring.Unseal(ctx, []byte(in.passphrase), console); err != nil {
		return err
	}
	defer func() { _ = in.ring.Seal(ctx, console) }()
	issue := func(r ca.Request) (*ca.Issued, error) {
		r.CA, r.Who = "issuing", console
		return e.Issue(ctx, r)
	}
	csr, err := sampleCSR("web.homelab.example")
	if err != nil {
		return err
	}
	for _, r := range []ca.Request{
		{Preset: "server", DNSNames: []string{"web.homelab.example"}, CSR: csr},
		{Preset: "server", DNSNames: []string{"git.homelab.example"}, ValidityDays: 20},
		{Preset: "client", Subject: ca.Subject{CommonName: "Backup job"}, EmailAddresses: []string{"backup@homelab.example"}},
		{Preset: "server", DNSNames: []string{"old.homelab.example"}},
		{Preset: "server", DNSNames: []string{"nas.homelab.example", "files.homelab.example"}, IPAddresses: []string{"192.0.2.10"}},
	} {
		out, err := issue(r)
		if err != nil {
			return fmt.Errorf("sample %v: %w", r.DNSNames, err)
		}
		if r.DNSNames != nil && r.DNSNames[0] == "old.homelab.example" {
			if _, err := e.Revoke(ctx, ca.RevokeRequest{CertificateID: out.ID, Reason: ca.ReasonSuperseded, Who: console}); err != nil {
				return err
			}
		}
		in.detailID = out.ID             // the last one: nas, with a server key
		time.Sleep(2 * time.Millisecond) // IDs sort by time
	}
	return nil
}

func sampleCSR(cn string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// signIn signs the demo user in with password and the current TOTP code.
func signIn(ctx context.Context, s *auth.Service, password, secret string) (string, error) {
	res, err := s.Login(ctx, "demo", password, "127.0.0.1")
	if err != nil {
		return "", err
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	full, err := s.LoginTOTP(ctx, res.Token, totp(raw, time.Now()), "127.0.0.1") //nolint:forbidigo // the dev tool runs on the wall clock
	if err != nil {
		return "", err
	}
	return full.Token, nil
}

func totp(secret []byte, now time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/30)) // #nosec G115 -- a time after 1970
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

// tempDir is a fresh data directory for the instance.
func tempDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "myownpki-screenshots-")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "data"), func() { _ = os.RemoveAll(dir) }, nil
}
