package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/setup"
)

func TestInitFlags(t *testing.T) {
	t.Parallel()
	cfg, _ := dbConfig(t)
	var stderr bytes.Buffer
	for args, code := range map[string]int{
		"--stdin --demo": exitUsage,
		"extra":          exitUsage,
		"--nope":         exitUsage,
	} {
		stderr.Reset()
		if _, got := parseInit(append(strings.Fields(args), "--config", cfg), nil, &stderr); got != code {
			t.Errorf("%s: exit %d, want %d: %s", args, got, code, stderr.String())
		}
	}
	for args, mode := range map[string]setup.Mode{"": setup.Interactive, "--stdin": setup.Stdin, "--demo": setup.Demo} {
		opt, code := parseInit(append(strings.Fields(args), "--config", cfg), nil, &stderr)
		if code >= 0 || opt.Mode != mode || opt.Who.Principal == nil {
			t.Errorf("%q: mode %v, exit %d", args, opt.Mode, code)
		}
	}
}

// TestInitDemo: the demo runs without any input and is marked for good;
// db status warns about it.
func TestInitDemo(t *testing.T) {
	t.Parallel()
	cfg, _ := dbConfig(t)
	var stderr bytes.Buffer
	opt, code := parseInit([]string{"--config", cfg, "--demo", "--with-ca", "--ca-base-url", "http://pki.homelab.lan"}, nil, &stderr)
	if code >= 0 {
		t.Fatal(stderr.String())
	}
	var out bytes.Buffer
	if code := finishInit(t.Context(), opt, setup.NewLineInput(strings.NewReader(""), &out), &out, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s%s", code, out.String(), stderr.String())
	}
	for _, want := range []string{"DEMO instance – all secrets are in one file", "init-demo-secrets.txt", "Checkpoint key fingerprint", "Test CA created: root, issuing"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	var status bytes.Buffer
	runDBStatus(t.Context(), []string{"--config", cfg}, nil, &status, &status)
	if !strings.Contains(status.String(), "WARNING: DEMO instance") {
		t.Errorf("db status:\n%s", status.String())
	}
	stderr.Reset()
	if code := finishInit(t.Context(), opt, setup.NewLineInput(strings.NewReader(""), &out), &out, &stderr); code != exitProblem ||
		!strings.Contains(stderr.String(), "initialized already") {
		t.Errorf("second init: exit %d %s", code, stderr.String())
	}
}

// TestInitAuditIsSigned: `audit verify --checkpoint-key` right after init
// covers system.init; only system.seal is newer than the last checkpoint.
func TestInitAuditIsSigned(t *testing.T) {
	t.Parallel()
	cfg, _ := dbConfig(t)
	var stderr bytes.Buffer
	opt, code := parseInit([]string{"--config", cfg, "--demo"}, nil, &stderr)
	if code >= 0 {
		t.Fatal(stderr.String())
	}
	var out bytes.Buffer
	if code := finishInit(t.Context(), opt, setup.NewLineInput(strings.NewReader(""), &out), &out, &stderr); code != exitOK {
		t.Fatalf("init: %s", stderr.String())
	}
	_, after, _ := strings.Cut(out.String(), "checks the audit log against it:\n")
	fp := strings.TrimSpace(strings.SplitN(after, "\n", 2)[0])
	var verify bytes.Buffer
	if code := runAuditVerify(t.Context(), []string{"--config", cfg, "--checkpoint-key", fp}, nil, &verify, &verify); code != exitOK {
		t.Fatalf("audit verify: exit %d\n%s", code, verify.String())
	}
	instance, _, _ := strings.Cut(verify.String(), "tenant:default")
	if !strings.Contains(instance, "1 newer entr") {
		t.Errorf("instance log: want exactly one entry (system.seal) after the last checkpoint:\n%s", verify.String())
	}
}
