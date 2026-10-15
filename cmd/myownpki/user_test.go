package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

const testPassphrase = "correct horse battery staple, unseal"

// TestUserConsoleCommands: unlock, and reset-2fa only with the passphrase or
// the recovery key as proof.
func TestUserConsoleCommands(t *testing.T) {
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
	if ierr := keys.New(sys.Write, ia.Write, clock.System{}).Init(t.Context(), []byte(testPassphrase), recovery, console); ierr != nil {
		t.Fatal(ierr)
	}
	keyFile := filepath.Join(dataDir, "auth.key")
	if cerr := auth.CreateKeyFile(keyFile, nil); cerr != nil {
		t.Fatal(cerr)
	}
	key, _, err := auth.LoadKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(sys.Write, ia.Write, key, clock.System{})
	if _, uerr := svc.CreateUser(t.Context(), auth.NewUserRequest{Username: "alice", Password: "a long password for the test", InstanceAdmin: true, Who: console}); uerr != nil {
		t.Fatal(uerr)
	}

	run := func(cmd string, stdin string, stdinTerminal, stdoutTerminal bool, args ...string) (int, string) {
		var out bytes.Buffer
		uio := userIO{stdin: strings.NewReader(stdin), stdinTerminal: stdinTerminal, stdoutTerminal: stdoutTerminal, stdout: &out, stderr: &out}
		args = append(args, "--config", cfg)
		if cmd == "unlock" {
			return runUserUnlock(t.Context(), args, nil, uio), out.String()
		}
		return runUserReset2FA(t.Context(), args, nil, uio), out.String()
	}

	if code, out := run("unlock", "", false, false, "alice"); code != exitOK || !strings.Contains(out, `User "alice" unlocked`) {
		t.Errorf("unlock: %d %s", code, out)
	}
	if code, out := run("unlock", "", false, false, "nobody"); code != exitProblem || !strings.Contains(out, "no user") {
		t.Errorf("unlock unknown: %d %s", code, out)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "alice.txt")
	cases := []struct {
		name               string
		stdin              string
		stdinTerm, outTerm bool
		args               []string
		code               int
		msg                string
	}{
		{"passphrase typed on a terminal", testPassphrase, true, true, []string{"alice"}, exitUsage, "not from a terminal"},
		{"secret to a log", testPassphrase, false, false, []string{"alice"}, exitUsage, "--otpauth-file"},
		{"no proof", "", false, true, []string{"alice"}, exitUsage, "no passphrase"},
		{"wrong passphrase", "wrong passphrase, long enough", false, true, []string{"alice"}, exitProblem, "wrong passphrase"},
		{"new key over an existing one", testPassphrase, false, true, []string{"alice", "--new-auth-key"}, exitProblem, "never overwritten"},
		{"unknown user", testPassphrase, false, true, []string{"nobody"}, exitProblem, "no user"},
		{"passphrase", testPassphrase, false, true, []string{"alice"}, exitOK, "otpauth://totp/MyOwnPKI:alice?"},
		{"recovery key, to a file", recovery.Reveal(), false, false, []string{"alice", "--recovery-key", "--otpauth-file", file}, exitOK, file},
		{"file exists", testPassphrase, false, false, []string{"alice", "--otpauth-file", file}, exitUsage, "never overwritten"},
	}
	for _, c := range cases {
		code, out := run("reset", c.stdin, c.stdinTerm, c.outTerm, c.args...)
		if code != c.code || !strings.Contains(out, c.msg) {
			t.Errorf("%s: exit %d, want %d with %q:\n%s", c.name, code, c.code, c.msg, out)
		}
		if strings.Contains(out, testPassphrase) {
			t.Errorf("%s: the passphrase is printed", c.name)
		}
	}
	data, err := os.ReadFile(file)
	if err != nil || !bytes.Contains(data, []byte("otpauth://")) || bytes.Count(data, []byte("recovery code: ")) != auth.RecoveryCodeCount {
		t.Errorf("enrollment file: %v\n%s", err, data)
	}

	// Lost auth key: a new one only with --new-auth-key, then reset-2fa works.
	if rerr := os.Remove(keyFile); rerr != nil {
		t.Fatal(rerr)
	}
	if code, out := run("reset", testPassphrase, false, true, "alice"); code != exitProblem || !strings.Contains(out, "--new-auth-key") {
		t.Errorf("without a key file: %d %s", code, out)
	}
	if code, out := run("reset", testPassphrase, false, true, "alice", "--new-auth-key"); code != exitOK || !strings.Contains(out, "New auth key written") {
		t.Errorf("new key: %d %s", code, out)
	}
	if _, _, lerr := auth.LoadKey(keyFile); lerr != nil {
		t.Errorf("new key file: %v", lerr)
	}

	rows, err := ia.Read.QueryContext(t.Context(), `SELECT action || '/' || result FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var actions []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	got := strings.Join(actions, " ")
	for _, want := range []string{"user.unlock/success", "system.secret_verify/failure", "system.secret_verify/success", "user.totp_reset/success"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %s: %s", want, got)
		}
	}
	if strings.Count(got, "user.totp_reset/success") != 3 {
		t.Errorf("three resets expected: %s", got)
	}
}
