//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// POSIX modes exist only here; Windows has no mode to check.

func TestConfigCheckNamesTheModeNotTheContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	creds := dnsCredentialsFile(t, dir, "api_token: "+dnsSentinel+"\n")
	cfg := filepath.Join(dir, "agent.yaml")
	writeFile(t, cfg, dnsAgentYAML(dir, creds, true))
	for mode, want := range map[os.FileMode]string{
		0o640: creds + ": wrong mode: is 0640, want 0600 or 0400",
		0o644: creds + ": wrong mode: is 0644, want 0600 or 0400",
		0o660: creds + ": wrong mode: is 0660, want 0600 or 0400",
		0o400: creds + ": ok",
		0o600: creds + ": ok",
	} {
		if err := os.Chmod(creds, mode); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr)
		wantCode := 1
		if strings.HasSuffix(want, ": ok") {
			wantCode = 0
		}
		if code != wantCode || !strings.Contains(stdout.String(), want) || strings.Contains(stdout.String()+stderr.String(), "SENTINEL") {
			t.Errorf("mode %04o: exit code %d, want %d\nstdout: %s\nstderr: %s", mode, code, wantCode, stdout.String(), stderr.String())
		}
	}
}

func TestConfigCheckRefusesASymlinkedCredentialsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	real := dnsCredentialsFile(t, dir, "api_token: "+dnsSentinel+"\n")
	link := filepath.Join(filepath.Dir(real), "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg := filepath.Join(dir, "agent.yaml")
	writeFile(t, cfg, dnsAgentYAML(dir, link, true))
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), link+": symbolic link") {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}
