package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// TestPassphraseCommands: change with the current passphrase, reset with
// the recovery key; a wrong proof or a weak passphrase changes nothing.
func TestPassphraseCommands(t *testing.T) {
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
	t.Cleanup(func() { _ = sys.Close() })
	ia, err := store.Open(t.Context(), l.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ia.Close() })
	console := keys.Who{Actor: consoleWho().Actor, Principal: authz.Console()}
	recovery, err := keys.NewRecoveryKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ring := keys.New(sys.Write, ia.Write, clock.System{})
	if ierr := ring.Init(t.Context(), []byte(testPassphrase), recovery, console); ierr != nil {
		t.Fatal(ierr)
	}
	run := func(mode, stdin string) (int, string) {
		var out bytes.Buffer
		uio := userIO{stdin: strings.NewReader(stdin), stdout: &out, stderr: &out}
		return runPassphraseWith(t.Context(), mode, []string{"--config", cfg}, nil, uio), out.String()
	}
	works := func(p string) bool {
		t.Helper()
		verr := keys.New(sys.Write, ia.Write, clock.System{}).VerifyPassphrase(t.Context(), []byte(p), console)
		if verr != nil && !errors.Is(verr, keys.ErrWrongSecret) {
			t.Fatal(verr)
		}
		return verr == nil
	}

	const second = "a second unseal passphrase, long"
	const third = "a third unseal passphrase, longer"
	if code, out := run("change", "not the passphrase at all\n"+second+"\n"); code != exitProblem || works(second) {
		t.Errorf("change with a wrong passphrase: %d %s", code, out)
	}
	if code, out := run("change", testPassphrase+"\nshort\n"); code != exitUsage || !strings.Contains(out, "16 characters") {
		t.Errorf("weak new passphrase: %d %s", code, out)
	}
	if code, out := run("change", testPassphrase+"\n"); code != exitUsage {
		t.Errorf("one line only: %d %s", code, out)
	}
	if code, out := run("change", testPassphrase+"\n"+second+"\n"); code != exitOK || !works(second) || works(testPassphrase) {
		t.Fatalf("change: %d %s", code, out)
	}
	other, err := keys.NewRecoveryKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := run("reset", other.Reveal()+"\n"+third+"\n"); code != exitProblem || works(third) {
		t.Errorf("reset with another recovery key: %d %s", code, out)
	}
	if code, out := run("reset", recovery.Reveal()+"\n"+third+"\n"); code != exitOK || !works(third) || works(second) {
		t.Fatalf("reset: %d %s", code, out)
	}
	// Both are in the instance audit log.
	got := strings.Join(auditActions(t, ia), " ")
	for _, want := range []string{"system.passphrase_change/success", "system.passphrase_reset/success"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %s: %s", want, got)
		}
	}
}

func auditActions(t *testing.T, db *store.DB) []string {
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
