package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCheck(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.yaml")
	invalid := filepath.Join(dir, "invalid.yaml")
	quoted := strings.ReplaceAll(dir, `\`, `\\`)
	for file, content := range map[string]string{
		valid:   "data_dir: \"" + quoted + "\"\n",
		invalid: "data_dir: relative\nlog:\n  level: loud\n",
	} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name       string
		args, env  []string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{name: "valid file", args: []string{"--config", valid}, wantCode: 0,
			wantStdout: []string{"Config file: " + valid, "127.0.0.1:9443", "self-signed bootstrap certificate", "Configuration is valid."}},
		{name: "file from MYOWNPKI_CONFIG", env: []string{"MYOWNPKI_CONFIG=" + valid}, wantCode: 0,
			wantStdout: []string{"Config file: " + valid}},
		{name: "override is marked", args: []string{"--config", valid}, env: []string{"MYOWNPKI_PUBLIC_LISTEN="}, wantCode: 0,
			wantStdout: []string{"disabled   (from MYOWNPKI_PUBLIC_LISTEN)"}},
		{name: "invalid file names every problem", args: []string{"--config", invalid}, wantCode: 1,
			wantStderr: []string{"data_dir: must be an absolute path", "log.level"}},
		{name: "typo in variable", args: []string{"--config", valid}, env: []string{"MYOWNPKI_ADMIN_LISTN=:1"}, wantCode: 1,
			wantStderr: []string{"unknown environment variable MYOWNPKI_ADMIN_LISTN"}},
		{name: "missing file", args: []string{"--config", filepath.Join(dir, "nope.yaml")}, wantCode: 1,
			wantStderr: []string{"does not exist"}},
		{name: "extra argument", args: []string{"--config", valid, "now"}, wantCode: 2,
			wantStderr: []string{"unexpected argument"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := runConfigCheck(tt.args, tt.env, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tt.wantCode, stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout.String())
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
				}
			}
		})
	}
}

func TestConfigCommandUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"config"}, {"config", "show"}} {
		var stdout, stderr bytes.Buffer
		if code := run(t.Context(), args, &stdout, &stderr); code != 2 {
			t.Errorf("%v: exit code %d, want 2", args, code)
		}
		if !strings.Contains(stderr.String(), "config check") {
			t.Errorf("%v: usage missing: %s", args, stderr.String())
		}
	}
}
