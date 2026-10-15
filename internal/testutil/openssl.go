// Package testutil holds helpers that tests of several packages share. It is
// imported by tests only.
package testutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// findOpenSSL looks the binary up once per test process.
var findOpenSSL = sync.OnceValues(func() (string, error) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		return "", fmt.Errorf("openssl is not on PATH")
	}
	// #nosec G204 -- test helper: runs the openssl found on PATH
	out, err := exec.CommandContext(context.Background(), bin, "version").Output()
	if err != nil {
		return "", fmt.Errorf("%s version: %w", bin, err)
	}
	version := strings.TrimSpace(string(out))
	if !isOpenSSL3(version) {
		return "", fmt.Errorf("%s is %q, the tests need OpenSSL 3.0 or newer – macOS ships LibreSSL, there: brew install openssl@3 and put it first on PATH",
			bin, version)
	}
	return bin, nil
})

// isOpenSSL3 accepts "OpenSSL 3.x" and later majors; LibreSSL and OpenSSL
// 1.x lack options the tests and the offline instructions use (x509 -req
// -copy_extensions, x509 -subj).
func isOpenSSL3(version string) bool {
	rest, ok := strings.CutPrefix(version, "OpenSSL ")
	if !ok {
		return false
	}
	major, _, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(major)
	return err == nil && n >= 3
}

// OpenSSL returns the openssl binary for cross-checks. Missing or too old:
// skipped locally, fatal in CI – the cross-check must not disappear silently.
func OpenSSL(tb testing.TB) string {
	tb.Helper()
	bin, err := findOpenSSL()
	if err == nil {
		return bin
	}
	if os.Getenv("CI") != "" {
		tb.Fatalf("%v – the OpenSSL cross-check is required in CI", err)
	}
	tb.Skipf("%v – skipping cross-check", err)
	return ""
}
