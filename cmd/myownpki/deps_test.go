package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// dnsOnlyModules are what dns-01 in the agent needs and the server must not
// carry (docs/PHASE3.md §13.3): the ACME client library with its DNS
// providers, and the DNS library. A second guard sits in .golangci.yml
// (depguard, rule "agent-only-dns"); this one also sees indirect imports.
var dnsOnlyModules = []string{"github.com/go-acme/lego/", "github.com/miekg/dns"}

// goListDeps is `go list -deps` of the given packages, run from the module
// root with the default build tags and without CGO, like the release build.
func goListDeps(t *testing.T, pkgs ...string) []string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("the go tool is not on PATH: %v", err)
	}
	args := append([]string{"list", "-deps", "-f", "{{.ImportPath}}"}, pkgs...)
	cmd := exec.CommandContext(t.Context(), goTool, args...) // #nosec G204 G702 -- test: the go tool with fixed arguments
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.Fields(string(out))
}

func importsDNSModule(deps []string) []string {
	var found []string
	for _, p := range deps {
		for _, m := range dnsOnlyModules {
			if strings.HasPrefix(p, m) {
				found = append(found, p)
				break
			}
		}
	}
	return found
}

// The server and myownpki-ctl never answer a DNS challenge, so neither
// binary may contain lego or miekg/dns. The agent (the control below) does.
func TestServerBinariesHaveNoDNSLibraries(t *testing.T) {
	t.Parallel()
	agent := importsDNSModule(goListDeps(t, "./cmd/myownpki-agent"))
	if len(agent) == 0 {
		t.Fatal("control failed: myownpki-agent no longer imports lego, so this test checks nothing; update dnsOnlyModules")
	}
	for _, pkg := range []string{"./cmd/myownpki", "./cmd/myownpki-ctl"} {
		if found := importsDNSModule(goListDeps(t, pkg)); len(found) > 0 {
			t.Errorf("%s imports packages that belong to the agent only (docs/PHASE3.md §13.3): %v", pkg, found)
		}
	}
}
