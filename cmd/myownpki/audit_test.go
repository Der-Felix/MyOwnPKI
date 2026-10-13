package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// auditData migrates a data dir and appends n entries to the tenant log.
func auditData(t *testing.T, n int) (configFile string, tenantLog store.AuditLog) {
	t.Helper()
	cfg, dataDir := dbConfig(t)
	var out bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &out, &out); code != exitOK {
		t.Fatal(out.String())
	}
	logs, err := store.Layout{DataDir: dataDir}.AuditLogs(store.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), logs[1].Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for i := range n {
		e := audit.Entry{
			Time: time.Date(2026, 10, 13, 8, i, 0, 0, time.UTC), Actor: audit.Actor{Type: audit.ActorSystem, Name: "system"},
			Action: "test.event", Result: audit.ResultSuccess,
		}
		if _, _, err := audit.Append(context.Background(), db.Write, logs[1].Scope, e, ""); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, logs[1]
}

var headInOutput = regexp.MustCompile(`head (\d+:[0-9a-f]{64})`)

func TestAuditVerify(t *testing.T) {
	t.Parallel()
	cfg, log := auditData(t, 5)
	var stdout, stderr bytes.Buffer
	if code := runAuditVerify(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "instance") || !strings.Contains(out, "OK – 0 entries") || !strings.Contains(out, "OK – 5 entries, head 5:") {
		t.Errorf("output:\n%s", out)
	}

	// The printed head is accepted as --expect-head for its log.
	// The tenant log is printed last; the empty instance log has head 0.
	all := headInOutput.FindAllStringSubmatch(out, -1)
	if len(all) != 2 {
		t.Fatalf("want two heads in output:\n%s", out)
	}
	stdout.Reset()
	args := []string{"--config", cfg, "--scope", log.Scope, "--expect-head", all[1][1]}
	if code := runAuditVerify(t.Context(), args, nil, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), "contains expected head 5") {
		t.Errorf("--expect-head: exit %d\n%s", code, stdout.String())
	}

	stdout.Reset()
	args = []string{"--config", cfg, "--scope", log.Scope, "--expect-head", "9:" + strings.Repeat("a", 12)}
	if code := runAuditVerify(t.Context(), args, nil, &stdout, &stderr); code != exitProblem || !strings.Contains(stdout.String(), "cut off") {
		t.Errorf("head beyond the end: exit %d\n%s", code, stdout.String())
	}
}

func TestAuditVerifyFindsTampering(t *testing.T) {
	t.Parallel()
	cfg, log := auditData(t, 6)
	db, err := store.Open(t.Context(), log.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`DROP TRIGGER audit_entries_no_update`, `UPDATE audit_entries SET result = 'denied' WHERE seq = 4`} {
		if _, err := db.Write.ExecContext(t.Context(), s); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	var stdout, stderr bytes.Buffer
	if code := runAuditVerify(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitProblem {
		t.Errorf("exit %d, want %d", code, exitProblem)
	}
	if !strings.Contains(stdout.String(), "BROKEN at seq 4 – entry modified") {
		t.Errorf("output:\n%s", stdout.String())
	}
}

func TestAuditVerifyUsage(t *testing.T) {
	t.Parallel()
	cfg, _ := dbConfig(t)
	tests := []struct {
		args       []string
		wantStderr string
	}{
		{[]string{"--config", cfg, "--expect-head", "5:aaaaaaaaaaaa"}, "needs --scope"},
		{[]string{"--config", cfg, "--scope", "instance", "--expect-head", "5:abc"}, "at least 12 hex digits"},
		{[]string{"--config", cfg, "--scope", "tenant:nope"}, "no audit log with scope"},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		if code := runAuditVerify(t.Context(), tt.args, nil, &stdout, &stderr); code != exitUsage || !strings.Contains(stderr.String(), tt.wantStderr) {
			t.Errorf("%v: exit %d\n%s", tt.args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"audit", "check"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("unknown subcommand: exit %d", code)
	}
	stdout.Reset()
	if code := runAuditVerify(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitPending ||
		!strings.Contains(stdout.String(), "not created yet") {
		t.Errorf("before migrate: exit %d\n%s", code, stdout.String())
	}
}

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) SignCheckpoint(msg []byte) ([]byte, ed25519.PublicKey, error) {
	return ed25519.Sign(s.priv, msg), ed25519.PublicKey(s.priv[ed25519.SeedSize:]), nil
}

func TestAuditVerifyCheckpoints(t *testing.T) {
	t.Parallel()
	cfg, log := auditData(t, 3)
	db, err := store.Open(t.Context(), log.Path)
	if err != nil {
		t.Fatal(err)
	}
	s := edSigner{ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
	res, err := audit.Checkpoint(t.Context(), db.Write, log.Scope, s, time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC))
	_ = db.Close()
	if err != nil || !res.Made {
		t.Fatal(res, err)
	}

	run := func(extra ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := runAuditVerify(t.Context(), append([]string{"--config", cfg}, extra...), nil, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, out, _ := run(); code != exitOK || !strings.Contains(out, "1 signed checkpoint(s), newest at seq 4") || !strings.Contains(out, "key "+res.Key) {
		t.Errorf("exit %d\n%s", code, out)
	}
	if code, out, _ := run("--checkpoint-key", res.Key[:16]); code != exitOK {
		t.Errorf("pinned right key: exit %d\n%s", code, out)
	}
	if code, out, _ := run("--checkpoint-key", strings.Repeat("0", 16)); code != exitProblem || !strings.Contains(out, "not the expected key") {
		t.Errorf("pinned wrong key: exit %d\n%s", code, out)
	}
	if code, _, errOut := run("--checkpoint-key", "abc"); code != exitUsage || !strings.Contains(errOut, "16 hex digits") {
		t.Errorf("short key: exit %d\n%s", code, errOut)
	}
}
