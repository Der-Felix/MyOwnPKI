package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// TestImportLegacyCommand: dry run without a passphrase, then the import
// with it; the CAs show up in `ca list` and a second run is refused.
func TestImportLegacyCommand(t *testing.T) {
	t.Parallel()
	cfg, dataDir := dbConfig(t)
	var buf bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &buf, &buf); code != exitOK {
		t.Fatal(buf.String())
	}
	l := store.Layout{DataDir: dataDir}
	sys, err := store.Open(t.Context(), l.SystemDB())
	if err != nil {
		t.Fatal(err)
	}
	ia, err := store.Open(t.Context(), l.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := keys.NewRecoveryKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	console := keys.Who{Actor: consoleWho().Actor, Principal: authz.Console()}
	if ierr := keys.New(sys.Write, ia.Write, clock.System{}, keys.TestKDF()).Init(t.Context(), []byte(testPassphrase), recovery, console); ierr != nil {
		t.Fatal(ierr)
	}
	_ = sys.Close()
	_ = ia.Close()

	fx := legacytest.Write(t, filepath.Join(t.TempDir(), "pki"), clock.System{}.Now())
	run := func(stdin string, args ...string) (int, string) {
		var out bytes.Buffer
		uio := userIO{stdin: strings.NewReader(stdin), stdout: &out, stderr: &out}
		return runImportLegacy(t.Context(), append(args, "--config", cfg), nil, uio), out.String()
	}

	code, out := run("", fx.Dir, "--dry-run")
	if code != exitOK || !strings.Contains(out, "Dry run: nothing was written") || !strings.Contains(out, "issuing") ||
		!strings.Contains(out, "Certificates: 2 (1 revoked), private keys: 1") {
		t.Fatalf("dry run: %d\n%s", code, out)
	}
	if code, out = run("not the passphrase\n", fx.Dir); code != exitProblem || strings.Contains(out, "Imported.") {
		t.Fatalf("wrong passphrase: %d\n%s", code, out)
	}
	code, out = run(testPassphrase+"\n", fx.Dir)
	if code != exitOK || !strings.Contains(out, "Imported.") || !strings.Contains(out, "CRL signed: issuing number 4099") {
		t.Fatalf("import: %d\n%s", code, out)
	}
	var list bytes.Buffer
	if c := runCAList(t.Context(), []string{"--config", cfg}, nil, &list, &list); c != exitOK || !strings.Contains(list.String(), "issuing") {
		t.Errorf("ca list after the import: %d\n%s", c, list.String())
	}
	if code, out = run(testPassphrase+"\n", fx.Dir); code != exitProblem || !strings.Contains(out, "exists already") {
		t.Errorf("second import: %d\n%s", code, out)
	}
	if code, out = run("", filepath.Dir(fx.Dir), "--dry-run"); code != exitProblem || !strings.Contains(out, "--dir") {
		t.Errorf("the directory above: %d\n%s", code, out)
	}
	if code, _ = run("", fx.Dir, "--root-key", "maybe"); code != exitUsage {
		t.Errorf("bad --root-key: %d", code)
	}
	if _, err := os.Stat(fx.Dir); err != nil {
		t.Error("the pki.sh directory must stay")
	}
}
