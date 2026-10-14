package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

func rootPEM(t *testing.T, cn string, notBefore time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCAListAndShow(t *testing.T) {
	t.Parallel()
	cfg, dataDir := dbConfig(t)
	// No environment: the test must not depend on MYOWNPKI_* variables of
	// the machine it runs on (the configuration refuses unknown ones).
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		cmd, rest := runCAList, slices.Concat(args[1:], []string{"--config", cfg})
		if args[0] == "show" {
			cmd = runCAShow
		}
		code := cmd(t.Context(), rest, nil, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, out, _ := run("list"); code != exitPending || !strings.Contains(out, "db migrate") {
		t.Errorf("before migrate: exit %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &buf, &buf); code != exitOK {
		t.Fatal(buf.String())
	}
	if code, out, _ := run("list"); code != exitOK || !strings.Contains(out, "No CAs yet") {
		t.Errorf("empty: exit %d\n%s", code, out)
	}

	// An imported offline root needs no unsealed keyring.
	t0 := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	l := store.Layout{DataDir: dataDir}
	open := func(kind store.Kind) *store.DB {
		p, _ := l.TenantDB(store.DefaultTenant, kind)
		db, err := store.Open(t.Context(), p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	presets, _ := preset.Builtin()
	clk := clock.NewFake(t0)
	e := &ca.Engine{
		PKI: open(store.KindPKI).Write, Audit: open(store.KindAudit).Write, Scope: store.TenantScope(store.DefaultTenant),
		Keys: keys.New(nil, nil, clk), Presets: presets, Clock: clk,
	}
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "it-admin"}}
	for _, cn := range []string{"Homelab Root", "Homelab Root"} {
		if _, err := e.ImportRoot(t.Context(), ca.ImportRootRequest{
			CASettings: ca.CASettings{Name: "root", BaseURL: "http://pki.homelab.lan"}, CertPEM: rootPEM(t, cn, t0.Add(-time.Hour)), Who: who,
		}); err != nil {
			t.Fatal(err)
		}
	}

	code, out, _ := run("list")
	if code != exitOK || !strings.Contains(out, "root  root  active  offline  2           2046-10-13   -") {
		t.Errorf("list: exit %d\n%s", code, out)
	}
	code, out, _ = run("show", "root")
	for _, want := range []string{"CA root (root, active)", "Key mode:            offline", "1  previous, ecdsa-p384, CN=Homelab Root",
		"2  current", "published at http://pki.homelab.lan/ca/root/2.crt and http://pki.homelab.lan/crl/root/2.crl", "CRL validity:        180 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q (exit %d):\n%s", want, code, out)
		}
	}
	if !strings.Contains(out, "CRL: none yet") || !strings.Contains(out, "WARNING: no CRL published yet – sign it on the offline root and upload it") {
		t.Errorf("ca show without a root CRL:\n%s", out)
	}
	var status bytes.Buffer
	runDBStatus(t.Context(), []string{"--config", cfg}, nil, &status, &status)
	if !strings.Contains(status.String(), "CRLs (newest per CA generation):") || !strings.Contains(status.String(), "root/2") ||
		!strings.Contains(status.String(), "WARNING: no CRL published yet") {
		t.Errorf("db status:\n%s", status.String())
	}
	if code, _, errOut := run("show", "nope"); code != exitProblem || !strings.Contains(errOut, "no CA named") {
		t.Errorf("unknown CA: exit %d %s", code, errOut)
	}
	if code, _, _ := run("show"); code != exitUsage {
		t.Errorf("show without name: exit %d", code)
	}
	if code := runCA(t.Context(), []string{"delete"}, &buf, &buf); code != exitUsage {
		t.Errorf("unknown subcommand: exit %d", code)
	}
}

func TestCAShowKeepsURLWarningsVisible(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	showCA(&out, ca.CAInfo{
		Name: "issuing", Kind: "intermediate", Status: "active", Parent: "root",
		Generations: []ca.GenerationInfo{{
			Generation: 1, Current: true, Issuer: "root/1",
			Warnings: []string{"CRL distribution point is [http://old-server.lan/root.crl], MyOwnPKI serves http://pki.homelab.lan/crl/root/1.crl"},
		}},
	})
	if !strings.Contains(out.String(), "WARNING: CRL distribution point is [http://old-server.lan/root.crl]") {
		t.Errorf("ca show:\n%s", out.String())
	}
}
