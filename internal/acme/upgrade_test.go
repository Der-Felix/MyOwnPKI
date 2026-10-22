package acme

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/backup"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// TestUpgradeFromV01 (PHASE2 step 15): the released v0.1.0 makes an
// instance and a backup; this build restores it, applies its migrations
// (pki.db 0008–0010, system.db 0009) and issues by ACME with the CA made
// by v0.1.0. `task upgrade:test` installs v0.1.0 (pinned, checked against
// the Go checksum database) and sets UPGRADE_FROM_BIN.
func TestUpgradeFromV01(t *testing.T) {
	old := os.Getenv("UPGRADE_FROM_BIN")
	if old == "" {
		t.Skip("UPGRADE_FROM_BIN is not set – run `task upgrade:test`")
	}
	ctx := t.Context()

	// v0.1.0: init with the test CA, then a backup.
	oldData := filepath.Join(t.TempDir(), "v01")
	cfgFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("data_dir: \""+strings.ReplaceAll(oldData, `\`, `\\`)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runOld := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, old, args...) // #nosec G204 G702 -- test: the pinned v0.1.0 binary
		cmd.Stdin = strings.NewReader("")
		// v0.1.0 refuses unknown MYOWNPKI_* variables (MYOWNPKI_ACME_* are new).
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(kv), "MYOWNPKI_") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("v0.1.0 %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	runOld("init", "--demo", "--with-ca", "--ca-base-url", "http://pki.homelab.lan", "--config", cfgFile)
	backupDir := filepath.Join(t.TempDir(), "backup")
	runOld("backup", backupDir, "--config", cfgFile)

	// This build: restore, migrate, open.
	newData := filepath.Join(t.TempDir(), "restored")
	cfg := config.Default()
	cfg.DataDir = newData
	console := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console"}, Principal: authz.Console()}
	if _, err := backup.Restore(ctx, backupDir, "", backup.Options{Layout: store.Layout{DataDir: newData}, AuthKeyFile: cfg.AuthKeyFile(),
		Clock: clock.System{}, Who: console}); err != nil {
		t.Fatalf("restore of the v0.1.0 backup: %v", err)
	}
	inst := testinstance.OpenExisting(t, newData, filepath.Join(oldData, "init-demo-secrets.txt"))
	if inst.CAIDs["root"] == "" || inst.CAIDs["issuing"] == "" {
		t.Fatalf("CAs after the restore: %v", inst.CAIDs)
	}
	limits, err := (&tenant.Store{DB: inst.SystemDB.Read, Clock: inst.Clock}).ACMELimits(ctx, store.DefaultTenant)
	if err != nil || limits != tenant.DefaultACMELimits {
		t.Errorf("ACME limits after the migration: %+v %v", limits, err)
	}
	inst.Unseal(t)

	// ACME issues with the CA of v0.1.0.
	v := newEnvOn(t, inst, ca.ApprovalOpen)
	c := v.client(t)
	if a := c.register(); a.code != 201 {
		t.Fatalf("register: %d %s", a.code, a.body)
	}
	der, _ := c.issue("nas.homelab.lan")
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := inst.Engine.CAChain(ctx, testinstance.Console, inst.CAIDs["issuing"])
	if err != nil {
		t.Fatal(err)
	}
	root, err := inst.Engine.CAChain(ctx, testinstance.Console, inst.CAIDs["root"])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, ders ...[]byte) string {
		var b []byte
		for _, d := range ders {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
		}
		p := filepath.Join(dir, name)
		if werr := os.WriteFile(p, b, 0o600); werr != nil { // #nosec G703 -- the test's temp dir
			t.Fatal(werr)
		}
		return p
	}
	// #nosec G204 -- test: the openssl binary and temp files
	out, err := exec.CommandContext(ctx, testutil.OpenSSL(t), "verify", "-purpose", "sslserver", "-CAfile", write("root.pem", root[0]),
		"-untrusted", write("inter.pem", chain[0]), write("leaf.pem", leaf.Raw)).CombinedOutput()
	if err != nil || !strings.Contains(string(out), ": OK") {
		t.Fatalf("openssl verify of the ACME certificate from the v0.1.0 CA: %v\n%s", err, out)
	}
}
