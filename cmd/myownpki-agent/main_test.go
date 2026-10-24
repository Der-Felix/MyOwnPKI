package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	state := filepath.Join(dir, "state")
	writeFile(t, good, "server: https://pki.homelab.lan:8444\nca_bundle: "+yamlPath(filepath.Join(dir, "root.pem"))+
		"\nhostname: proxy1.homelab.lan\nstate_dir: "+yamlPath(state)+"\n")
	writeFile(t, bad, "server: http://pki.homelab.lan:8444\nhostname: proxy1\nbogus: 1\n")
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // prefix
		wantStderr string // substring
	}{
		{name: "version", args: []string{"--version"}, wantCode: 0, wantStdout: binary + " "},
		{name: "help", args: []string{"--help"}, wantCode: 0},
		{name: "no arguments", args: nil, wantCode: 2},
		{name: "unknown flag", args: []string{"--bogus"}, wantCode: 2},
		{name: "unknown command", args: []string{"deploy"}, wantCode: 2},
		{name: "config check", args: []string{"config", "check", "--config", good}, wantCode: 0, wantStdout: "Config file: "},
		{name: "config check of a bad file", args: []string{"config", "check", "--config", bad}, wantCode: 1, wantStderr: "field bogus not found"},
		{name: "missing file", args: []string{"status", "--config", filepath.Join(dir, "nope.yaml")}, wantCode: 1},
		{name: "enroll with extra arguments", args: []string{"enroll", "--config", good, "extra"}, wantCode: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.HasPrefix(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want prefix %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// yamlPath quotes a path for YAML (Windows paths have backslashes).
func yamlPath(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }
