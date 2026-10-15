package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // prefix
		wantStderr string // substring
	}{
		{name: "version", args: []string{"--version"}, wantCode: 0, wantStdout: binary + " "},
		{name: "help", args: []string{"--help"}, wantCode: 0},
		{name: "no arguments", args: nil, wantCode: 2, wantStderr: "no command given"},
		{name: "unknown flag", args: []string{"--bogus"}, wantCode: 2},
		{name: "unknown command", args: []string{"frobnicate"}, wantCode: 2, wantStderr: "unknown command"},
		{name: "serve without a config file", args: []string{"serve", "--config", "does-not-exist.yaml"}, wantCode: 1, wantStderr: "does not exist"},
		{name: "serve --listen without --dev", args: []string{"serve", "--listen", "127.0.0.1:9443"}, wantCode: 2, wantStderr: "--listen is for --dev only"},
		{name: "serve --dev with --config", args: []string{"serve", "--dev", "--config", "x.yaml"}, wantCode: 2, wantStderr: "no --config or --unseal"},
		{name: "serve on all interfaces", args: []string{"serve", "--dev", "--listen", "0.0.0.0:9443"}, wantCode: 2, wantStderr: "not allowed"},
		{name: "serve on localhost name", args: []string{"serve", "--dev", "--listen", "localhost:9443"}, wantCode: 2, wantStderr: "not a host name"},
		{name: "serve extra argument", args: []string{"serve", "--dev", "now"}, wantCode: 2, wantStderr: "unexpected argument"},
		{name: "serve help", args: []string{"serve", "--help"}, wantCode: 0},
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
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestValidateDevListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:9443", true},
		{"[::1]:9443", true},
		{"127.0.0.1:1", true},
		{"localhost:9443", false},    // name, may resolve elsewhere
		{"0.0.0.0:9443", false},      // all interfaces
		{"[::]:9443", false},         // all interfaces
		{"192.168.1.10:9443", false}, // LAN
		{"127.0.0.2:9443", false},    // only the exact loopback addresses
		{"[::1%lo]:9443", false},     // zone
		{"127.0.0.1", false},         // no port
		{"127.0.0.1:0", false},       // random port
		{"127.0.0.1:65536", false},
		{"127.0.0.1:http", false},
		{":9443", false}, // empty host = all interfaces
	}
	for _, tt := range tests {
		err := validateDevListen(tt.addr)
		if (err == nil) != tt.ok {
			t.Errorf("validateDevListen(%q) = %v, want ok=%v", tt.addr, err, tt.ok)
		}
	}
}
