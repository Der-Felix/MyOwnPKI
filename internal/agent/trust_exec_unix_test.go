//go:build unix

package agent

import (
	"context"
	"strings"
	"testing"
)

// The real runner starts the fixed argument vector with exactly the
// environment it is given: no proxy variable and no SSL_CERT_* of the caller.
func TestTrustExecRunnerUsesOnlyTheGivenEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://canary.homelab.lan:3128")
	t.Setenv("SSL_CERT_FILE", "/canary/ca.pem")
	out, err := trustExecRunner{}.Run(context.Background(), []string{"/usr/bin/env"}, []string{"PATH=" + trustHookPATH, "LC_ALL=C"})
	if err != nil {
		t.Skipf("/usr/bin/env is not usable here: %v", err)
	}
	lines := strings.Fields(out)
	if len(lines) != 2 || strings.Contains(out, "canary") {
		t.Fatalf("environment of the hook = %q", out)
	}
}

func TestTrustExecRunnerReportsAFailureAndItsOutput(t *testing.T) {
	out, err := trustExecRunner{}.Run(context.Background(), []string{"/bin/sh", "-c", "echo broken >&2; exit 3"}, []string{"PATH=" + trustHookPATH})
	if err == nil || !strings.Contains(out, "broken") {
		t.Fatalf("err = %v, output = %q", err, out)
	}
}
