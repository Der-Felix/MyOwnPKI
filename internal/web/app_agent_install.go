package web

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

type agentInstallInput struct {
	hostname, arch, format, mode, webroot string
	token                                 bool
}

type agentTrust struct {
	rootSHA256, rootSHA1, rootURL string
}

func (a *app) requireAgentInstallAdmin(c *rc) bool {
	if c.may(authz.ManageAgents, "") {
		return true
	}
	c.fail(authz.ErrDenied)
	return false
}

func (a *app) agentInstallPage(c *rc) {
	if !a.requireAgentInstallAdmin(c) {
		return
	}
	if a.d.Agents == nil || a.d.AgentDist == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	form := c.form(admin.FormData{
		Title: "Guided installation", Action: "/agents/install", Submit: "Prepare installation",
		Intro: []string{"The exact host, architecture, format and enrollment mode are fixed by these commands. Creating an optional 15-minute, one-use token needs a fresh second factor."},
		Fields: []admin.Field{
			{ID: "hostname", Label: "Exact host FQDN", Required: true},
			{ID: "arch", Label: "Architecture", Type: "select", Options: []admin.Option{{Value: "amd64", Label: "linux/amd64", Selected: true}, {Value: "arm64", Label: "linux/arm64"}}},
			{ID: "format", Label: "Package format", Type: "select", Options: []admin.Option{{Value: "deb", Label: ".deb", Selected: true}, {Value: "rpm", Label: ".rpm"}, {Value: "tarball", Label: "tarball"}}},
			{ID: "mode", Label: "Enrollment http-01", Type: "select", Options: []admin.Option{{Value: "standalone", Label: "standalone", Selected: true}, {Value: "webroot", Label: "existing webroot"}}},
			{ID: "webroot", Label: "Webroot (required in webroot mode)", Hint: "Absolute existing directory on the host, for example /var/www/acme"},
			{ID: "token", Label: "Create an exact-host, one-use token valid for 15 minutes", Type: "checkbox", Checked: true},
		},
	})
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("Install agent", "agents", view.Crumb{Label: "Agents", Href: "/agents"}), form))
}

func (a *app) agentInstallInput(c *rc) (agentInstallInput, error) {
	in := agentInstallInput{
		hostname: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.r.PostFormValue("hostname"))), "."),
		arch:     c.r.PostFormValue("arch"), format: c.r.PostFormValue("format"), mode: c.r.PostFormValue("mode"),
		webroot: strings.TrimSpace(c.r.PostFormValue("webroot")), token: yes(c.r.PostFormValue("token")),
	}
	host, err := agents.CheckPattern(in.hostname)
	if err != nil || host != in.hostname || strings.Contains(host, "*") {
		return in, fmt.Errorf("%w: exact host FQDN required", agents.ErrInvalid)
	}
	if _, err := a.d.AgentDist.Artifact(in.format, in.arch); err != nil {
		return in, ca.ErrNotFound
	}
	switch in.mode {
	case "standalone":
		if in.webroot != "" {
			return in, fmt.Errorf("%w: webroot is only valid in webroot mode", agents.ErrInvalid)
		}
	case "webroot":
		if !strings.HasPrefix(in.webroot, "/") || path.Clean(in.webroot) != in.webroot || in.webroot == "/" || strings.ContainsAny(in.webroot, "\x00\r\n") {
			return in, fmt.Errorf("%w: webroot must be a clean absolute directory other than /", agents.ErrInvalid)
		}
	default:
		return in, fmt.Errorf("%w: enrollment mode", agents.ErrInvalid)
	}
	return in, nil
}

func (a *app) agentInstall(c *rc) {
	if !a.requireAgentInstallAdmin(c) {
		return
	}
	if a.d.Agents == nil || a.d.AgentDist == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	in, err := a.agentInstallInput(c)
	if err != nil {
		c.refused(err, "/agents/install")
		return
	}
	if err = c.sess.Principal.FreshStepUp(a.now()); err != nil {
		c.refused(err, "/agents/install")
		return
	}
	secret := ""
	if in.token {
		secret, _, err = a.d.Agents.CreateJoinToken(c.r.Context(), c.who(), "Guided install "+in.hostname, []string{in.hostname}, 15*time.Minute)
		if err != nil {
			c.refused(err, "/agents/install")
			return
		}
	}
	sections, err := a.guidedInstallSections(c, in, secret)
	if err != nil {
		c.fail(err)
		return
	}
	c.once(c.page("Install agent on "+in.hostname, "agents", view.Crumb{Label: "Agents", Href: "/agents"}), admin.DetailData{Sections: sections})
}

func (a *app) agentUpdatePage(c *rc) {
	if !a.requireAgentInstallAdmin(c) {
		return
	}
	if a.d.Agents == nil || a.d.AgentDist == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	ag, err := a.d.Agents.GetAgent(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return
	}
	if !a.agentOlder(*ag) {
		c.fail(ca.ErrNotFound)
		return
	}
	format := ag.PackageFormat
	if format == "" {
		format = "tarball"
	}
	in := agentInstallInput{hostname: ag.Hostname, arch: ag.Arch, format: format, mode: "standalone"}
	sections, err := a.guidedInstallSections(c, in, "")
	if err != nil {
		c.fail(err)
		return
	}
	sections = append([]admin.Section{{Text: []string{
		"This update preserves agent.yaml and restarts an already enrolled agent. Choose standalone only if its existing configuration already uses it; setup preserves the existing enrollment configuration either way.",
	}}}, sections...)
	c.once(c.page("Update agent on "+ag.Hostname, "agents", view.Crumb{Label: "Agents", Href: "/agents"}, view.Crumb{Label: ag.Hostname, Href: "/agents/" + ag.ID}), admin.DetailData{Sections: sections})
}

func (a *app) agentOlder(ag agents.Agent) bool {
	if a.d.AgentDist == nil {
		return false
	}
	cmp, err := version.Compare(ag.Version, a.d.AgentDist.Version())
	return err == nil && cmp < 0
}

func (a *app) agentTLSTrust(c *rc) (agentTrust, error) {
	t, err := agents.TLSTrust(c.r.Context(), a.d.Engine, c.who(), a.d.AgentTLSIssuer)
	return agentTrust{rootSHA256: t.SHA256, rootSHA1: t.SHA1, rootURL: t.URL}, err
}

func (a *app) guidedInstallSections(c *rc, in agentInstallInput, secret string) ([]admin.Section, error) {
	trust, err := a.agentTLSTrust(c)
	if err != nil {
		return nil, err
	}
	artifact, err := a.d.AgentDist.Artifact(in.format, in.arch)
	if err != nil {
		return nil, err
	}
	rootPath := agentRootPath
	packagePath := "/root/" + artifact.Name
	base := strings.TrimRight(a.d.AgentBaseURL, "/")
	packageURL := base + agentdist.BasePath + artifact.Name
	sumsURL := base + agentdist.BasePath + agentdist.Checksums
	var commands strings.Builder
	writeRootCheck(&commands, trust)
	fmt.Fprintf(&commands, "curl --fail --silent --show-error --cacert %s --output %s %s\n", rootPath, packagePath, shellQuote(packageURL))
	fmt.Fprintf(&commands, "curl --fail --silent --show-error --cacert %s --output /root/checksums.txt %s\n", rootPath, shellQuote(sumsURL))
	fmt.Fprintf(&commands, "printf '%%s  %%s\\n' %s %s | sha256sum --check - || { echo \"package checksum does not match the UI value – nothing installed\" >&2; exit 1; }\n", shellQuote(artifact.SHA256), packagePath)
	switch in.format {
	case "deb":
		fmt.Fprintf(&commands, "apt-get install -y %s\n", packagePath)
	case "rpm":
		fmt.Fprintf(&commands, "dnf install -y %s\n", packagePath)
	case "tarball":
		commands.WriteString("install -d -m 0700 /root/myownpki-agent-package\n")
		fmt.Fprintf(&commands, "tar -xzf %s -C /root/myownpki-agent-package\n", packagePath)
		fmt.Fprintf(&commands, "install -m 0755 /root/myownpki-agent-package/myownpki-agent %s\n", agentdist.BinaryPath)
	}
	// The absolute path: root's PATH may lack /usr/local/bin.
	fmt.Fprintf(&commands, "%s setup --server %s --ca-bundle %s --root-sha256 %s --package-format %s --hostname %s",
		agentdist.BinaryPath, shellQuote(a.d.AgentBaseURL), rootPath, shellQuote(trust.rootSHA256), in.format, shellQuote(in.hostname))
	if in.mode == "webroot" {
		fmt.Fprintf(&commands, " --webroot %s", shellQuote(in.webroot))
	}
	if secret != "" {
		commands.WriteString(" --token-file " + agentTokenPath)
	}
	commands.WriteString(" )\n")
	sections := []admin.Section{
		{Title: "Independent values from this authenticated UI", Text: []string{
			"Only SHA-256 authorizes installation. Compare these literals yourself; neither the downloaded root nor checksums.txt supplies an expected value. Root SHA-1 is display-only for the Windows certificate dialog.",
		}, KV: []view.KV{
			{Key: "Root SHA-256 (DER, authoritative)", Value: trust.rootSHA256, Mono: true},
			{Key: "Root SHA-1 (Windows dialog comparison only)", Value: trust.rootSHA1, Mono: true},
			{Key: "Package SHA-256", Value: artifact.SHA256, Mono: true},
		}},
	}
	if secret != "" {
		sections = append(sections, admin.Section{Title: "One-use join token — shown only now", Text: []string{
			"This token is valid for 15 minutes and only for " + in.hostname + ". It is absent from URLs, process arguments, action summaries and later pages.",
		}, Pre: []admin.Pre{{Title: "Write the root-only token file", Text: tokenFileCommands(secret)}}})
	}
	sections = append(sections, admin.Section{Title: "Verified download, installation and setup", Text: []string{
		"Run as root on " + in.hostname + ". The root comes over HTTP but is accepted only after its DER fingerprint matches the independent UI literal. Packages and checksums then use HTTPS with that verified root.",
	}, Pre: []admin.Pre{{Title: "Commands", Text: commands.String()}}})
	return sections, nil
}

// Files the generated commands write on the host.
const (
	agentRootPath  = "/root/myownpki-root.pem"
	agentTokenPath = "/root/myownpki-join-token" // #nosec G101 -- a file path, not a credential
)

// writeRootCheck opens a fail-closed root subshell and fetches the agent TLS
// root over HTTP. It is accepted only when its DER SHA-256 matches the
// literal from this authenticated UI – the download never vouches for itself.
func writeRootCheck(b *strings.Builder, trust agentTrust) {
	b.WriteString("( set -euo pipefail\n")
	b.WriteString("umask 077\n")
	fmt.Fprintf(b, "curl --fail --silent --show-error --output %s %s\n", agentRootPath, shellQuote(trust.rootURL))
	fmt.Fprintf(b, "test \"$(openssl x509 -in %s -outform DER | sha256sum | awk '{print $1}')\" = %s || { echo \"root fingerprint does not match the UI value – nothing installed\" >&2; exit 1; }\n", agentRootPath, shellQuote(trust.rootSHA256))
}

// tokenFileCommands writes the join token to a root-only file by here-doc,
// so the secret never becomes a process argument.
func tokenFileCommands(secret string) string {
	return "( set -euo pipefail\numask 077\ncat > " + agentTokenPath + " <<'MYOWNPKI_TOKEN'\n" + secret + "\nMYOWNPKI_TOKEN\nchmod 0600 " + agentTokenPath + "\n )"
}

// joinTokenHostSection is the host part of a new join token: the token file,
// the verified root and setup. Setup, not enroll: on a fresh package or
// tarball host only setup writes agent.yaml and installs the unit. A token
// for one exact name fixes --hostname; with patterns the host's FQDN must
// match one of them. A pass (pass = true) is for several hosts, so every host
// names itself.
func (a *app) joinTokenHostSection(trust agentTrust, patterns []string, secret string, pass bool) admin.Section {
	hostname := `"$(hostname -f)"`
	if !pass && len(patterns) == 1 && !strings.Contains(patterns[0], "*") {
		hostname = shellQuote(patterns[0])
	}
	var commands strings.Builder
	writeRootCheck(&commands, trust)
	// The installed format, so that update links suggest the right one later.
	commands.WriteString("if dpkg -s myownpki-agent >/dev/null 2>&1; then format=deb; elif rpm -q myownpki-agent >/dev/null 2>&1; then format=rpm; else format=tarball; fi\n")
	fmt.Fprintf(&commands, "%s setup --server %s --ca-bundle %s --root-sha256 %s --package-format \"$format\" --hostname %s --token-file %s )\n",
		agentdist.BinaryPath, shellQuote(a.d.AgentBaseURL), agentRootPath, shellQuote(trust.rootSHA256), hostname, agentTokenPath)
	title, intro := "On the host", "Run as root on the host after installing the agent package or tarball; Agents → Install agent does both for one exact host. The root comes over HTTP and is accepted only when its DER SHA-256 matches the value shown here."
	if pass {
		title = "On each host"
		intro = "Run as root on every host after installing the agent package or tarball; a Salt state, an Ansible task or a script can run the same two blocks. setup deletes the pass file once the host is admitted; a host that still waits keeps it. The root comes over HTTP and is accepted only when its DER SHA-256 matches the value shown here."
	}
	return admin.Section{Title: title, Text: []string{intro}, KV: []view.KV{{Key: "Root SHA-256 (DER, authoritative)", Value: trust.rootSHA256, Mono: true}},
		Pre: []admin.Pre{{Title: "Write the root-only token file", Text: tokenFileCommands(secret)}, {Title: "Verify the root and run setup", Text: commands.String()}}}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
