package agent

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Tests of the dns-01 flags of "deployment add" (docs/PHASE3.md §13.1, step 42).

const dnsSecretSentinel = "SENTINEL-must-never-be-printed"

func dnsFixture(t *testing.T) *editFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "edit", "commented.in.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return newEditFixture(t, string(raw))
}

// dnsSpec is the deployment of the live test of the plan: a wildcard and its
// apex through RFC 2136, behind an nginx that already has hooks.
func (f *editFixture) dnsSpec() DeploymentSpec {
	return DeploymentSpec{Name: "wild", Dir: f.p("ssl", "wild"), Names: []string{"*.homelab.lan", "homelab.lan"},
		Challenge: ChallengeDNS01, TestHook: "nginx-test", ReloadHook: "nginx-reload", Check: "127.0.0.1:443", CheckName: "www.homelab.lan",
		DNSProvider: "homelab-dns", DNSType: DNSTypeRFC2136, DNSCredentials: f.p("etc", "dns", "homelab.yaml"), DNSNameserver: "192.0.2.53"}
}

func (f *editFixture) addSpec(spec DeploymentSpec, dry bool) error {
	opts := f.edit()
	opts.DryRun = dry
	return AddDeployment(context.Background(), AddOptions{EditOptions: opts, Spec: spec})
}

// writeCreds places a credentials file with the given mode.
func (f *editFixture) writeCreds(mode os.FileMode, content string) {
	f.t.Helper()
	path := f.p("etc", "dns", "homelab.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- test directory.
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		f.t.Fatal(err)
	}
}

const goodTSIGFile = "tsig_key_name: acme-agent\ntsig_algorithm: hmac-sha256\ntsig_secret: c2VjcmV0LXNlY3JldC1zZWNyZXQ=\n"

func TestAddDNS01WritesProviderAndDeployment(t *testing.T) {
	f := dnsFixture(t)
	f.writeCreds(0o600, goodTSIGFile)
	before := f.tree()
	if err := f.addSpec(f.dnsSpec(), true); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	// The dry run shows the diff of agent.yaml with the new entry, and writes nothing.
	out := f.normalize(f.stdout.String())
	for _, want := range []string{"Dry run: nothing was written.", "+dns_providers:", "+  homelab-dns:", "+    type: \"rfc2136\"", "+    nameserver: \"192.0.2.53\"",
		"+    dns_provider: \"homelab-dns\"", "+    check_name: \"www.homelab.lan\"", "\"*.homelab.lan\""} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if !sameTree(before, f.tree()) {
		t.Error("the dry run changed the host")
	}
	if strings.Contains(f.stderr.String(), "warning: DNS credentials") {
		t.Errorf("a good credentials file gave a warning: %s", f.stderr.String())
	}

	if err := f.addSpec(f.dnsSpec(), false); err != nil {
		t.Fatal(err)
	}
	golden(t, "dns01.out.yaml", f.normalize(f.read(f.config)))
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Deployments[len(cfg.Deployments)-1]
	if d.Name != "wild" || d.Challenge != ChallengeDNS01 || d.DNSProvider != "homelab-dns" || d.Webroot != "" || d.CheckName != "www.homelab.lan" ||
		!slices.Equal(d.Names, []string{"*.homelab.lan", "homelab.lan"}) {
		t.Errorf("deployment: %+v", d)
	}
	if p := cfg.DNSProviders["homelab-dns"]; p.Type != DNSTypeRFC2136 || p.Nameserver != "192.0.2.53" || filepath.Clean(p.CredentialsFile) != f.p("etc", "dns", "homelab.yaml") {
		t.Errorf("provider: %+v", p)
	}
	// dns-01 binds no port and writes no file: paths did not grow, and the
	// drop-ins hold neither a low-ports file nor a new directory.
	if len(cfg.Paths) != 2 || filepath.Clean(cfg.Paths[0]) != f.p("www") || filepath.Clean(cfg.Paths[1]) != f.p("ssl") {
		t.Errorf("paths: %v", cfg.Paths)
	}
	if _, err = os.Stat(filepath.Join(f.dropins, dropinLowPortsName)); !os.IsNotExist(err) {
		t.Errorf("a dns-01 deployment wrote %s (%v)", dropinLowPortsName, err)
	}
	if strings.Contains(f.read(filepath.Join(f.dropins, dropinPathsName)), "homelab") {
		t.Error("10-paths.conf mentions the DNS provider")
	}
	// The drop-ins match agent.yaml: a sync has nothing to do.
	if err = SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.stdout.String(), "nothing to do") {
		t.Errorf("sync: %s", f.stdout.String())
	}
}

// No check, no path change: the drop-ins still ask for nothing.
func TestAddDNS01NeedsNoLowPortsEvenWithoutAnyPathChange(t *testing.T) {
	f := dnsFixture(t)
	f.writeCreds(0o600, goodTSIGFile)
	spec := f.dnsSpec()
	spec.Check, spec.CheckName = "", ""
	if err := f.addSpec(spec, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dropins, dropinLowPortsName)); !os.IsNotExist(err) {
		t.Errorf("low-ports drop-in: %v", err)
	}
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if lowPortsWanted(cfg, false) != lowPortsDontCare {
		t.Error("a dns-01 deployment makes the drop-ins ask for low ports")
	}
}

// A plain file gets plain scalars, and the wildcard is quoted: an unquoted
// "*" starts an alias.
func TestAddDNS01QuotesAWildcardInAPlainFile(t *testing.T) {
	f := newEditFixture(t, "server: https://pki.homelab.lan:8444\nca_bundle: \"@ROOT@/etc/root.pem\"\nhostname: proxy1.homelab.lan\nacme_directory: https://pki.homelab.lan/acme/directory\nstate_dir: \"@ROOT@/state\"\nlog_level: info\npaths: [\"@ROOT@/ssl\"]\nhooks: {}\ndeployments: []\n")
	spec := f.dnsSpec()
	spec.TestHook, spec.ReloadHook, spec.Check, spec.CheckName = "", "", "", ""
	spec.DNSType, spec.DNSCredentials = DNSTypeRFC2136, f.p("etc", "dns", "homelab.yaml")
	if err := f.addSpec(spec, false); err != nil {
		t.Fatal(err)
	}
	got := f.normalize(f.read(f.config))
	for _, want := range []string{"names: [\"*.homelab.lan\", homelab.lan]", "\n  homelab-dns:\n    type: rfc2136\n", "dns_provider: homelab-dns"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if _, err := LoadConfig(f.config); err != nil {
		t.Fatal(err)
	}
}

// A second deployment names the provider, with or without repeating the flags
// (a Salt run repeats them); the entry is written once.
func TestAddDNS01SharesAnExistingProvider(t *testing.T) {
	f := dnsFixture(t)
	if err := f.addSpec(f.dnsSpec(), false); err != nil {
		t.Fatal(err)
	}
	for i, spec := range []DeploymentSpec{
		f.dnsSpec(), // the flags again, identical
		{DNSProvider: "homelab-dns"},
		{DNSProvider: "homelab-dns", DNSType: DNSTypeRFC2136, DNSNameserver: "192.0.2.53"},
	} {
		next := f.dnsSpec()
		next.Name = "wild" + string(rune('b'+i))
		next.Dir = f.p("ssl", next.Name)
		next.DNSType, next.DNSCredentials, next.DNSNameserver, next.DNSProvider = spec.DNSType, spec.DNSCredentials, spec.DNSNameserver, spec.DNSProvider
		if err := f.addSpec(next, false); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	got := f.read(f.config)
	if n := strings.Count(got, "homelab-dns:"); n != 1 {
		t.Errorf("the provider is written %d times:\n%s", n, got)
	}
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNSProviders) != 1 || len(cfg.Deployments) != 5 {
		t.Errorf("providers %d, deployments %d", len(cfg.DNSProviders), len(cfg.Deployments))
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("warnings: %v", w)
	}
}

func TestAddDNS01RefusesADifferentDefinition(t *testing.T) {
	f := dnsFixture(t)
	if err := f.addSpec(f.dnsSpec(), false); err != nil {
		t.Fatal(err)
	}
	other := f.p("etc", "dns", "other.yaml")
	for name, edit := range map[string]func(*DeploymentSpec){
		"type":        func(s *DeploymentSpec) { s.DNSType = DNSTypeCloudflare },
		"credentials": func(s *DeploymentSpec) { s.DNSCredentials = other },
		"nameserver":  func(s *DeploymentSpec) { s.DNSNameserver = "192.0.2.54" },
		"zone":        func(s *DeploymentSpec) { s.DNSZone = "homelab.lan" },
		"resolver":    func(s *DeploymentSpec) { s.DNSResolver = "192.0.2.1" },
	} {
		t.Run(name, func(t *testing.T) {
			before := f.tree()
			spec := f.dnsSpec()
			spec.Name, spec.Dir = "second", f.p("ssl", "second")
			edit(&spec)
			err := f.addSpec(spec, false)
			if err == nil || !strings.Contains(err.Error(), "exists with another definition") || !strings.Contains(err.Error(), "edit agent.yaml by hand") {
				t.Fatalf("got %v", err)
			}
			if !sameTree(before, f.tree()) {
				t.Error("a refused add changed the host")
			}
		})
	}
}

func TestAddDNS01FlagRefusals(t *testing.T) {
	f := dnsFixture(t)
	tests := []struct {
		name string
		edit func(*DeploymentSpec)
		want string
	}{
		{"no provider name", func(s *DeploymentSpec) { s.DNSProvider = "" }, "needs --dns-provider"},
		{"bad provider name", func(s *DeploymentSpec) { s.DNSProvider = "Home_DNS" }, "--dns-provider"},
		{"unknown provider without a type", func(s *DeploymentSpec) { s.DNSType, s.DNSCredentials, s.DNSNameserver = "", "", "" }, "is not in agent.yaml"},
		{"unknown type", func(s *DeploymentSpec) { s.DNSType = "route53" }, "--dns-type: rfc2136 or cloudflare"},
		{"rfc2136 without nameserver", func(s *DeploymentSpec) { s.DNSNameserver = "" }, "needs --dns-nameserver"},
		{"no credentials file", func(s *DeploymentSpec) { s.DNSCredentials = "" }, "--dns-credentials FILE is required"},
		{"cloudflare with a nameserver", func(s *DeploymentSpec) { s.DNSType = DNSTypeCloudflare }, "are for --dns-type rfc2136"},
		{"relative credentials path", func(s *DeploymentSpec) { s.DNSCredentials = "dns/homelab.yaml" }, "credentials_file"},
		{"credentials under /home", func(s *DeploymentSpec) { s.DNSCredentials = "/home/admin/dns.yaml" }, "ProtectHome=yes"},
		{"credentials where the agent writes", func(s *DeploymentSpec) { s.DNSCredentials = f.p("ssl", "wild", "dns.yaml") }, "credentials_file"},
		{"bad nameserver", func(s *DeploymentSpec) { s.DNSNameserver = "ns one" }, "nameserver"},
		{"bad resolver", func(s *DeploymentSpec) { s.DNSResolver = "ns1.homelab.lan" }, "resolver"},
		{"webroot with dns-01", func(s *DeploymentSpec) { s.Webroot = f.p("www") }, "belongs to --challenge webroot"},
		{"check without a concrete name", func(s *DeploymentSpec) { s.CheckName, s.Names = "", []string{"*.homelab.lan"} }, "pass --check-name"},
		{"check-name without check", func(s *DeploymentSpec) { s.Check = "" }, "--check-name goes with a TLS check"},
		{"check-name that is a wildcard", func(s *DeploymentSpec) { s.CheckName = "*.homelab.lan" }, "check_name"},
		{"dns flags with webroot", func(s *DeploymentSpec) { s.Challenge, s.Webroot = ChallengeWebroot, f.p("www") }, "belong to --challenge dns-01"},
		{"dns flags with standalone", func(s *DeploymentSpec) { s.Challenge = ChallengeStandalone }, "belong to --challenge dns-01"},
		{"wildcard with webroot", func(s *DeploymentSpec) {
			s.Challenge, s.Webroot = ChallengeWebroot, f.p("www")
			s.DNSProvider, s.DNSType, s.DNSCredentials, s.DNSNameserver = "", "", "", ""
		}, "can only be proven with dns-01"},
		{"unknown challenge", func(s *DeploymentSpec) { s.Challenge = "tls-alpn-01" }, "standalone, webroot or dns-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := f.tree()
			spec := f.dnsSpec()
			tt.edit(&spec)
			err := f.addSpec(spec, false)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
			if !sameTree(before, f.tree()) {
				t.Error("a refused add changed the host")
			}
		})
	}
}

// A file that is missing, wrongly protected or unreadable is a warning, not an
// error: Salt runs "deployment add" before it places the secret.
func TestAddDNS01CredentialsProblemsAreWarnings(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*editFixture)
		want  string
		unix  bool // needs POSIX modes
	}{
		{"missing", func(*editFixture) {}, "missing", false},
		{"invalid content", func(f *editFixture) { f.writeCreds(0o600, "api_token: "+dnsSecretSentinel+"\n") }, "invalid", false},
		{"mode 0644", func(f *editFixture) { f.writeCreds(0o644, goodTSIGFile) }, "wrong mode", true},
		{"mode 0660", func(f *editFixture) { f.writeCreds(0o660, goodTSIGFile) }, "wrong mode", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unix && !credsEnforcePermissions {
				t.Skip("no POSIX modes on this platform")
			}
			f := dnsFixture(t)
			tt.setup(f)
			if err := f.addSpec(f.dnsSpec(), false); err != nil {
				t.Fatalf("a credentials problem must not fail the add: %v", err)
			}
			got := f.stderr.String()
			if !strings.Contains(got, "warning: DNS credentials file") || !strings.Contains(got, tt.want) {
				t.Errorf("stderr: %q, want a warning with %q", got, tt.want)
			}
			if strings.Contains(got+f.stdout.String(), dnsSecretSentinel) {
				t.Error("a secret reached the output")
			}
			if _, err := LoadConfig(f.config); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A dry run warns too, and writes nothing.
	f := dnsFixture(t)
	before := f.tree()
	if err := f.addSpec(f.dnsSpec(), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.stderr.String(), "missing") || !sameTree(before, f.tree()) {
		t.Errorf("dry run: stderr %q", f.stderr.String())
	}
}

// The editor keeps the comments and the blank lines of a hand-written file and
// puts dns_providers where the canonical order wants it: after enrollment.
func TestEditorAddDNSProviderKeepsComments(t *testing.T) {
	f := dnsFixture(t)
	if err := f.addSpec(f.dnsSpec(), false); err != nil {
		t.Fatal(err)
	}
	got := f.normalize(f.read(f.config))
	for _, want := range []string{"# MyOwnPKI agent on proxy1 - edited by hand over the years.", "# the agent listener", "# Hooks: no shell, absolute path first.",
		"# nginx -t needs /var/log/nginx in the sandbox", "# Directories the agent may write.", "# the public site", "# fullchain.pem and privkey.pem"} {
		if !strings.Contains(got, want) {
			t.Errorf("comment lost: %q", want)
		}
	}
	if enrollment, providers, hooks := strings.Index(got, "\nenrollment:"), strings.Index(got, "\ndns_providers:"), strings.Index(got, "\nhooks:"); enrollment >= providers || providers >= hooks {
		t.Errorf("order: enrollment %d, dns_providers %d, hooks %d", enrollment, providers, hooks)
	}
	// An entry that exists is never rewritten by the editor.
	ed, err := openYAMLEditor([]byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if err = ed.addDNSProvider("homelab-dns", DNSProvider{Type: DNSTypeCloudflare}); err == nil || !strings.Contains(err.Error(), "edit it by hand") {
		t.Errorf("editor overwrote an entry: %v", err)
	}
}

// ParseDeploymentAdd is the one place that knows the flags; the Add host
// assistant and the command both use it.
func TestParseDeploymentAddDNSFlags(t *testing.T) {
	fs := flag.NewFlagSet("deployment add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "")
	cmd, err := ParseDeploymentAdd(fs, config, []string{"wild", "--dir", "/etc/ssl/wild", "--name", "*.homelab.lan", "--name", "homelab.lan", "--challenge", "dns-01",
		"--dns-provider", "homelab-dns", "--dns-type", "rfc2136", "--dns-credentials", "/etc/myownpki-agent/dns/homelab.yaml",
		"--dns-nameserver", "192.0.2.53", "--dns-zone", "homelab.lan", "--dns-resolver", "192.0.2.1", "--check", "127.0.0.1:443", "--check-name", "www.homelab.lan", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	s := cmd.Spec
	if !cmd.DryRun || s.Challenge != ChallengeDNS01 || !slices.Equal(s.Names, []string{"*.homelab.lan", "homelab.lan"}) || s.DNSProvider != "homelab-dns" ||
		s.DNSType != "rfc2136" || s.DNSCredentials != "/etc/myownpki-agent/dns/homelab.yaml" || s.DNSNameserver != "192.0.2.53" ||
		s.DNSZone != "homelab.lan" || s.DNSResolver != "192.0.2.1" || s.Check != "127.0.0.1:443" || s.CheckName != "www.homelab.lan" {
		t.Errorf("spec: %+v", s)
	}
	// A recipe works with dns-01: its check stays, and the flags win.
	fs = flag.NewFlagSet("deployment add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config = fs.String("config", "", "")
	cmd, err = ParseDeploymentAdd(fs, config, []string{"nginx", "--recipe", "nginx", "--challenge", "dns-01", "--dns-provider", "p", "--check-name", "a.homelab.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Spec.Check == "" || cmd.Spec.CheckName != "a.homelab.lan" || cmd.Spec.Challenge != ChallengeDNS01 {
		t.Errorf("recipe spec: %+v", cmd.Spec)
	}
}

// With a recipe the nginx hooks still need the low ports of their own
// sockets; what the challenge adds is nothing.
func TestDNS01ChallengeAloneAddsNoLowPorts(t *testing.T) {
	cfg := &Config{Enrollment: Enrollment{Challenge: ChallengeWebroot}, Deployments: []Deployment{{Name: "a", Challenge: ChallengeDNS01, DNSProvider: "p"}}}
	if got := lowPortsWanted(cfg, false); got != lowPortsDontCare {
		t.Errorf("lowPortsWanted = %v", got)
	}
	cfg.Deployments = append(cfg.Deployments, Deployment{Name: "b", Challenge: ChallengeStandalone})
	if got := lowPortsWanted(cfg, false); got != lowPortsYes {
		t.Errorf("a standalone deployment next to it: %v", got)
	}
}

func TestDryRunDeploymentAddMapsTheCredentialsPath(t *testing.T) {
	f := dnsFixture(t)
	spec := f.dnsSpec()
	// The assistant gives a path as the host sees it; the dry run maps it below its root.
	rel := "/etc/myownpki-agent/dns/homelab.yaml"
	spec.DNSCredentials = rel
	spec.Dir = "/ssl/wild"
	mapped := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(mapped), 0o755); err != nil { // #nosec G301 -- test directory.
		t.Fatal(err)
	}
	if err := os.WriteFile(mapped, []byte(goodTSIGFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.root, "ssl"), 0o755); err != nil { // #nosec G301 -- test directory.
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	out, err := DryRunDeploymentAdd(context.Background(), DeploymentAddCommand{ConfigPath: f.config, DryRun: true, Spec: spec},
		DryRunHost{Root: f.root, ConfigPath: f.config, UnitPath: f.unit, Stderr: &stderr})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "+dns_providers:") || strings.Contains(stderr.String(), "warning: DNS credentials") {
		t.Errorf("out:\n%s\nstderr: %s", out, stderr.String())
	}
}
