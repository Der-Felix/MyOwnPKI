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

// TestUsageNamesOnlyKnownFlags: every flag the main help shows for a command
// is accepted by that command (`backup verify` was listed with --config,
// which it refuses). Each flag is passed in its --flag=VALUE form, then
// --help: a known flag ends in the help (0), an unknown one in a usage error.
func TestUsageNamesOnlyKnownFlags(t *testing.T) {
	t.Parallel()
	var help bytes.Buffer
	if code := run(t.Context(), []string{"--help"}, &help, &help); code != 0 {
		t.Fatalf("--help: %d", code)
	}
	checked := 0
	for line := range strings.SplitSeq(help.String(), "\n") {
		rest, ok := strings.CutPrefix(line, "  "+binary+" ")
		if !ok {
			continue
		}
		fields := strings.Fields(strings.NewReplacer("[", " ", "]", " ").Replace(rest))
		var words []string
		var flags [][]string
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			switch {
			case strings.HasPrefix(f, "--"):
				for alt := range strings.SplitSeq(f, "|") { // --stdin|--demo
					arg := alt
					// A value follows when the next token is a placeholder or a value.
					if i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") && fields[i+1] != "..." && !strings.Contains(f, "|") {
						arg += "=" + fields[i+1]
						i++
					}
					flags = append(flags, []string{arg})
				}
			case len(flags) == 0 && strings.ToLower(f) == f && f != "...":
				words = append(words, f)
			}
		}
		if len(words) == 0 {
			continue // --version
		}
		// "db status|migrate": each alternative is a command of its own.
		last := words[len(words)-1]
		for alt := range strings.SplitSeq(last, "|") {
			cmd := append(append([]string{}, words[:len(words)-1]...), alt)
			for _, fl := range flags {
				args := append(append(append([]string{}, cmd...), fl...), "--help")
				var out bytes.Buffer
				if code := run(t.Context(), args, &out, &out); code != 0 {
					t.Errorf("help line %q: %v exits %d\n%s", strings.TrimSpace(line), args, code, out.String())
				}
				checked++
			}
		}
	}
	if checked < 20 {
		t.Errorf("only %d flags checked – does the help still look like `  myownpki cmd [--flag VALUE]`?", checked)
	}
}
