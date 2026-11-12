package web

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agentpath"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

// The Add host assistant (docs/PHASE3.md section 11, step 32) turns a few
// answers into the commands an admin pastes on a new host. This file is the
// part that has no HTTP in it: what a form may contain, and how the command
// lines are made. Nothing the user typed reaches a command line unchecked and
// unquoted: every value is validated first (the whitelists below), and every
// value that is not a fixed word of this program goes through shellQuote.
// Hook commands never come from a form; they come from internal/recipe.

// Routes of the assistant. They live under /hosts/add, not /agents/add:
// "GET /agents/add/{host}" would collide with "GET /agents/{id}/update".
const (
	hostAddPath      = "/hosts/add"
	hostAddCommands  = "/hosts/add/commands"
	hostAddNavKey    = "add-host"
	hostAddRefresh   = 10  // seconds between two loads of the progress page
	hostAddTokenTTL  = 15  // minutes a one-use token of the assistant lives
	maxHostAddExtras = 4   // certificate names besides the host name
	maxHostPath      = 200 // bytes of a webroot
)

// Ways to be admitted (step 2).
const (
	admitToken = "token" // a one-use join token for this host, made with the second factor
	admitPass  = "pass"  // an enrollment pass an admin made earlier; the assistant never shows it
	admitNone  = "none"  // no secret: the host waits in the queue and an admin approves it
)

// hostService is a choice of step 1. The ID is the deployment's name on the
// host; Recipe is an internal/recipe name, "" for the certificate files alone.
type hostService struct {
	ID, Label, Recipe string
}

var hostServices = []hostService{
	{"nginx", "nginx", "nginx"},
	{"postfix", "Postfix (example recipe)", "postfix"},
	{"dovecot", "Dovecot (example recipe)", "dovecot"},
	{"proxmox", "Proxmox VE (example recipe)", "proxmox"},
	{"files", "Certificate files only (no service, no reload)", ""},
}

func hostServiceByID(id string) (hostService, bool) {
	i := slices.IndexFunc(hostServices, func(s hostService) bool { return s.ID == id })
	if i < 0 {
		return hostService{}, false
	}
	return hostServices[i], true
}

// certDirRoot is where the "files only" choice puts fullchain.pem and
// privkey.pem: below the directory the recipes use, named after the host.
const certDirRoot = "/etc/ssl/myownpki"

// hostPlan is a validated step 1. Only parseHostPlan makes one.
type hostPlan struct {
	Host      string
	Names     []string // the certificate names: Host first, then the extra ones
	Service   hostService
	Challenge string // standalone | webroot
	Webroot   string
	Arch      string
	Format    string // deb | rpm | tarball | none (the agent is installed already)
	Admission string
}

// ExtraNames are the certificate names besides the host name.
func (p hostPlan) ExtraNames() []string { return p.Names[1:] }

// parseHostPlan validates a submitted step 1 (and the hidden copy of it that
// later steps carry). artifacts says whether the server has packages to offer;
// without them only "already installed" is valid. Every error is an
// agents.ErrInvalid the user can read.
func parseHostPlan(get func(string) string, artifacts bool) (hostPlan, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{agents.ErrInvalid}, args...)...)
	}
	var p hostPlan
	p.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(get("hostname"))), ".")
	host, err := agents.CheckPattern(p.Host)
	if err != nil || host != p.Host || strings.Contains(host, "*") {
		return p, invalid("the host name must be one exact, fully qualified, lower case name such as proxy1.homelab.lan")
	}
	p.Names = []string{p.Host}
	for _, raw := range splitNames(get("names")) {
		name := strings.TrimSuffix(strings.ToLower(raw), ".")
		checked, nameErr := agents.CheckPattern(name)
		if nameErr != nil || checked != name || strings.Contains(name, "*") {
			return p, invalid("certificate names must be exact, fully qualified names (no wildcard): %q is not", clipText(raw, 40))
		}
		if !slices.Contains(p.Names, name) {
			p.Names = append(p.Names, name)
		}
	}
	if len(p.Names) > 1+maxHostAddExtras {
		return p, invalid("at most %d certificate names besides the host name", maxHostAddExtras)
	}
	var ok bool
	if p.Service, ok = hostServiceByID(get("service")); !ok {
		return p, invalid("choose one of the listed services")
	}
	switch p.Challenge = get("challenge"); p.Challenge {
	case "standalone":
		if strings.TrimSpace(get("webroot")) != "" {
			return p, invalid("a webroot belongs to the webroot challenge; clear it or choose webroot")
		}
	case "webroot":
		p.Webroot = strings.TrimSpace(get("webroot"))
		if err = checkHostPath(p.Webroot); err != nil {
			return p, invalid("webroot: %v", err)
		}
	default:
		return p, invalid("choose standalone or webroot")
	}
	p.Format, p.Arch = get("format"), get("arch")
	switch {
	case p.Format == "none":
		p.Arch = ""
	case !artifacts, !slices.Contains(agentdist.Formats, p.Format), !slices.Contains(agentdist.Arches, p.Arch):
		return p, invalid("choose a package format and architecture from the list, or \"already installed\"")
	}
	switch p.Admission = get("admission"); p.Admission {
	case admitToken, admitPass, admitNone:
	case "":
		p.Admission = admitNone
	default:
		return p, invalid("choose how the host is admitted from the list")
	}
	return p, nil
}

// checkHostPath validates a directory typed by a person that becomes part of a
// command line and of the agent's configuration: an absolute path of letters,
// digits and . _ - / only, already clean, not a system root. The agent applies
// its own, wider rules again; this is the whitelist in front of them, and it is
// stricter than the unit file needs (no white space, quote, backslash, % or $,
// nothing a shell or systemd would read as more than a path).
func checkHostPath(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("a directory is required")
	case len(p) > maxHostPath || !utf8.ValidString(p):
		return fmt.Errorf("at most %d characters", maxHostPath)
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("an absolute path, for example /var/www/acme")
	}
	for _, r := range p {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("./_-", r) {
			return fmt.Errorf("only letters, digits and . _ - / are allowed")
		}
	}
	if path.Clean(p) != p {
		return fmt.Errorf("a clean path: no //, no . or .. segment, no trailing /")
	}
	if agentpath.Broad(p) {
		return fmt.Errorf("%s is a system directory the agent may not write; use a subdirectory such as /var/www/acme", p)
	}
	return nil
}

// clipText cuts s to n runes for display and drops control characters. Text
// from a host (a deployment's last error, a failed check) is attacker
// influenced: templ escapes it, this keeps it short and on one line.
func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// acmeDirectoryFor checks the ACME directory URL of this server for the agent,
// which wants https.
func acmeDirectoryFor(raw string) (string, error) {
	u, err := url.Parse(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: ACME is off on this server, so an agent could not get a certificate; turn it on first (OPERATIONS.md, chapter ACME)", agents.ErrInvalid)
	}
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("%w: the ACME directory of this server is not an https URL, which the agent requires", agents.ErrInvalid)
	}
	return raw, nil
}

// ---------------------------------------------------------------- commands

// joinWords writes one shell command with line continuations; the words are
// either fixed words of this program or already shellQuoted.
func joinWords(words ...string) string {
	return strings.Join(words, " \\\n  ")
}

// certParents are the directories above the files the deployment writes. The
// agent creates the last directory of its targets, but not their parents, and
// without --create-dirs it refuses a missing one; install -d makes exactly
// those, and nothing else.
func certParents(p hostPlan) []string {
	var dirs []string
	add := func(dir string) {
		if dir != "" && !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	if p.Service.Recipe == "" {
		add(certDirRoot)
		return dirs
	}
	r, ok := recipe.Get(p.Service.Recipe)
	if !ok {
		return nil
	}
	if r.Profile == "nginx" {
		add(path.Dir(strings.ReplaceAll(r.Dir, "{name}", p.Service.ID)))
		return dirs
	}
	for _, f := range []string{r.Certificate, r.Chain, r.Fullchain, r.Key} {
		if f != "" {
			add(path.Dir(f))
		}
	}
	return dirs
}

// deploymentAddCommand is the block that adds the deployment on the host. The
// recipe fills hooks, check, owner, mode and sandbox on the host (explicit
// flags win there); this line carries only what the form decided.
func deploymentAddCommand(p hostPlan, acmeDirectory string) string {
	var b strings.Builder
	b.WriteString("( set -euo pipefail\n")
	for _, dir := range certParents(p) {
		fmt.Fprintf(&b, "install -d -m 0755 %s\n", shellQuote(dir))
	}
	words := []string{agentdist.BinaryPath + " deployment add " + shellQuote(p.Service.ID)}
	if p.Service.Recipe != "" {
		words = append(words, "--recipe "+p.Service.Recipe)
	} else {
		words = append(words, "--dir "+shellQuote(certDirRoot+"/"+p.Host), "--key-mode 0600")
	}
	for _, name := range p.Names {
		words = append(words, "--name "+shellQuote(name))
	}
	challenge := "--challenge " + p.Challenge
	if p.Webroot != "" {
		challenge += " --webroot " + shellQuote(p.Webroot)
	}
	words = append(words, challenge, "--acme-directory "+shellQuote(acmeDirectory), "--restart")
	b.WriteString(joinWords(words...))
	b.WriteString("\n )\n")
	return b.String()
}

// verifyCommand is the one command that shows the result on the host.
func verifyCommand() string { return agentdist.BinaryPath + " deployment list\n" }

// passFileCommands writes the pass an admin typed on the host to the root-only
// token file. The assistant does not know the pass (only its hash is stored),
// so the secret is typed or pasted on the host, never part of this page.
func passFileCommands() string {
	return "( set -euo pipefail\numask 077\nread -r -s -p 'Enrollment pass: ' pass\necho\nprintf '%s\\n' \"$pass\" > " + agentTokenPath + "\nunset pass\n )"
}

// ---------------------------------------------------------------- admission

// admissionOutcome says, in words, what happens at the server when the host
// enrolls with the given admission in the given tenant mode, and whether one
// approval by an admin is still needed. The rules are those of agents.admits
// (docs/PHASE3.md section 6.1 and 11.2).
func admissionOutcome(mode, admission string) (approval bool, text string) {
	switch mode {
	case tenant.EnrollManual:
		return true, "The tenant is in manual mode: every enrollment waits for an admin to approve it, whatever secret it brings."
	case tenant.EnrollAuto:
		if admission == admitNone {
			return false, "The tenant is in auto mode: a host that passes the http-01 check is admitted without an approval. That mode admits any machine that can answer port 80 for a name below one of your domains."
		}
		return false, "The host is admitted as soon as it has passed the http-01 check; nobody has to approve it."
	}
	if admission == admitNone {
		return true, "Without a token the host waits in the queue after it has passed the http-01 check, and an admin approves it once (with the second factor). The progress page has the button."
	}
	return false, "With the secret and a passed http-01 check the host is admitted without an approval. If the check fails (port 80 not reachable, wrong webroot), it waits in the queue instead."
}
