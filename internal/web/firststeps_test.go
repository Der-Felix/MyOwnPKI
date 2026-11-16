package web

import (
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/help"
)

func titles(steps []help.Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Title
	}
	return out
}

func stateOf(steps []help.Step) map[string]string {
	out := map[string]string{}
	for _, s := range steps {
		out[s.Title] = s.StatusText
	}
	return out
}

func allGuides(slug string) (string, bool) { return "Guide of " + slug, true }

var activeCA = ca.CAInfo{Name: "issuing", Kind: ca.KindIntermediate, Status: ca.StatusActive, BaseURL: "http://pki.homelab.lan"}

func completeFacts() firstStepsFacts {
	return firstStepsFacts{
		TenantWide: true, MayManageCA: true, CanIssue: true, InstanceAdmin: true,
		CAs:          []ca.CAInfo{activeCA},
		DomainsKnown: true, Domains: 1, CertificatesKnown: true, Certificates: 3,
		ACMEDirectory: "https://pki.homelab.lan/acme/directory", AgentsOn: true, AgentsKnown: true, Agents: 2,
		NotifiersKnown: true, Notifiers: 1, GuideTitle: allGuides,
	}
}

// TestFirstStepsStates: the rows, in order, for every kind of instance and role.
func TestFirstStepsStates(t *testing.T) {
	t.Parallel()
	const (
		unseal, authority, baseURL, domain, acme = "Unseal the server", "Create a certificate authority", "Public base URL and CRL", "Add a domain", "Turn on ACME"
		cert, host, backup, trust, notify        = "Issue a first certificate", "Add a host with an agent (optional)", "Back up the instance", "Trust the root on your devices", "Set up notifications (optional)"
		done, open, none, noAccess               = "Done", "Open", "Not detected", "Not available to your role"
	)
	wantOrder := []string{unseal, authority, baseURL, domain, acme, cert, host, backup, trust, notify}
	empty := firstStepsFacts{TenantWide: true, MayManageCA: true, InstanceAdmin: true, DomainsKnown: true, CertificatesKnown: true, ACMEDirectory: "https://pki.homelab.lan/acme/directory",
		NotifiersKnown: true, AgentsKnown: true, GuideTitle: allGuides}
	partial := empty
	partial.CAs = []ca.CAInfo{activeCA}
	sealed := completeFacts()
	sealed.Sealed = true
	viewer := completeFacts()
	viewer.InstanceAdmin, viewer.MayManageCA, viewer.CanIssue = false, false, false
	scoped := firstStepsFacts{CAs: []ca.CAInfo{activeCA}, CanIssue: true, GuideTitle: allGuides, ACMEDirectory: "https://pki.homelab.lan/acme/directory", AgentsOn: true}
	acmeOff := completeFacts()
	acmeOff.ACMEDirectory = ""
	agentsOff := completeFacts()
	agentsOff.AgentsOn, agentsOff.AgentsKnown, agentsOff.Agents = false, false, 0
	pending := empty
	pending.CAs = []ca.CAInfo{{Name: "issuing", Status: ca.StatusPendingSignature}}
	noURL := completeFacts()
	noURL.CAs = []ca.CAInfo{{Name: "issuing", Status: ca.StatusActive}}
	crl := completeFacts()
	crl.CAs = []ca.CAInfo{{Name: "issuing", Status: ca.StatusActive, BaseURL: "http://pki.homelab.lan", Generations: []ca.GenerationInfo{{CRL: &ca.CRLStatus{State: ca.CRLWarning}}}}}
	renewDue := completeFacts()
	renewDue.CAs = []ca.CAInfo{{Name: "issuing", Status: ca.StatusActive, BaseURL: "http://pki.homelab.lan", Generations: []ca.GenerationInfo{{CRL: &ca.CRLStatus{State: ca.CRLRenewDue}}}}}
	denied := completeFacts()
	denied.DomainsKnown, denied.CertificatesKnown, denied.AgentsKnown, denied.NotifiersKnown = false, false, false, false

	tests := []struct {
		name  string
		facts firstStepsFacts
		want  map[string]string
	}{
		{"empty", empty, map[string]string{unseal: done, authority: open, baseURL: open, domain: open, acme: done, cert: open, host: open, backup: none, trust: none, notify: none}},
		{"partial", partial, map[string]string{unseal: done, authority: done, baseURL: done, domain: open, acme: done, cert: open, host: open, backup: none, trust: none, notify: none}},
		{"complete", completeFacts(), map[string]string{unseal: done, authority: done, baseURL: done, domain: done, acme: done, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"sealed", sealed, map[string]string{unseal: open, authority: done, baseURL: done, domain: done, acme: done, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"viewer", viewer, map[string]string{unseal: done, authority: done, baseURL: done, domain: done, acme: done, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"role limited to one CA", scoped, map[string]string{unseal: done, authority: done, baseURL: done, domain: noAccess, acme: noAccess, cert: noAccess, host: noAccess, backup: none, trust: none, notify: noAccess}},
		{"ACME off", acmeOff, map[string]string{unseal: done, authority: done, baseURL: done, domain: done, acme: open, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"agents off", agentsOff, map[string]string{unseal: done, authority: done, baseURL: done, domain: done, acme: done, cert: done, host: open, backup: none, trust: none, notify: done}},
		{"CA waits for its signature", pending, map[string]string{unseal: done, authority: open, baseURL: open, domain: open, acme: done, cert: open, host: open, backup: none, trust: none, notify: none}},
		{"a CA without a base URL", noURL, map[string]string{unseal: done, authority: done, baseURL: open, domain: done, acme: done, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"a CRL that needs attention", crl, map[string]string{unseal: done, authority: done, baseURL: open, domain: done, acme: done, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"a CRL that is due for renewal is fine", renewDue, map[string]string{unseal: done, authority: done, baseURL: done, domain: done, acme: done, cert: done, host: done, backup: none, trust: none, notify: done}},
		{"lists the role may not read", denied, map[string]string{unseal: done, authority: done, baseURL: done, domain: noAccess, acme: done, cert: noAccess, host: noAccess, backup: none, trust: none, notify: none}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			steps := buildFirstSteps(tt.facts)
			if got := titles(steps); strings.Join(got, "|") != strings.Join(wantOrder, "|") {
				t.Fatalf("rows = %v", got)
			}
			got := stateOf(steps)
			for title, want := range tt.want {
				if got[title] != want {
					t.Errorf("%s: %q, want %q (%s)", title, got[title], want, steps[indexOf(steps, title)].Text)
				}
			}
			for _, s := range steps {
				if s.Text == "" && s.StatusText != noAccess {
					t.Errorf("%s has no text", s.Title)
				}
			}
		})
	}
}

func indexOf(steps []help.Step, title string) int {
	for i, s := range steps {
		if s.Title == title {
			return i
		}
	}
	return 0
}

func linkSet(s help.Step) string {
	var parts []string
	for _, l := range s.Links {
		parts = append(parts, l.Href)
	}
	return strings.Join(parts, " ")
}

// TestFirstStepsLinks: a row offers an action only to a role that has it, the
// guides appear only when the build contains them, every link is a path of the
// UI or the documentation site, and the unseal link goes to an instance admin only.
func TestFirstStepsLinks(t *testing.T) {
	t.Parallel()
	full := buildFirstSteps(firstStepsFacts{TenantWide: true, MayManageCA: true, CanIssue: true, InstanceAdmin: true, Sealed: true, GuideTitle: allGuides, AgentsOn: true, AgentsKnown: true,
		DomainsKnown: true, CertificatesKnown: true})
	byTitle := map[string]string{}
	for _, s := range full {
		byTitle[s.Title] = linkSet(s)
	}
	for title, want := range map[string]string{
		"Unseal the server":              "/unseal",
		"Create a certificate authority": "/authorities /authorities/new /guides/build-a-ca /guides/offline-root",
		"Add a domain":                   "/domains /domains/new",
		"Issue a first certificate":      "/certificates /certificates/new /guides/connect-certbot",
		"Back up the instance":           "/guides/backup-and-restore",
	} {
		if byTitle[title] != want {
			t.Errorf("%s links to %q, want %q", title, byTitle[title], want)
		}
	}
	if got := byTitle["Add a host with an agent (optional)"]; got != "/hosts/add /guides/install-the-agent" {
		t.Errorf("add host: %q", got)
	}
	// A role without rights has no action, a build without guides has no guide link.
	viewer := buildFirstSteps(firstStepsFacts{TenantWide: true, Sealed: true, DomainsKnown: true, CertificatesKnown: true})
	for _, s := range viewer {
		for _, l := range s.Links {
			if l.Href == "/unseal" || strings.HasSuffix(l.Href, "/new") || l.Href == hostAddPath || strings.HasPrefix(l.Href, guidesPath+"/") {
				t.Errorf("%s offers %s to a viewer without guides", s.Title, l.Href)
			}
		}
	}
	for _, s := range full {
		for _, l := range s.Links {
			switch {
			case strings.HasPrefix(l.Href, "/") && !strings.HasPrefix(l.Href, "//"), strings.HasPrefix(l.Href, "https://der-felix.github.io/MyOwnPKI/") && l.External:
			default:
				t.Errorf("%s: link %q", s.Title, l.Href)
			}
		}
	}
}

// TestFirstStepsTextCarriesNoSecret: the ACME directory is the one value the
// rows repeat; it is text for templ to escape.
func TestFirstStepsTextCarriesNoSecret(t *testing.T) {
	t.Parallel()
	f := completeFacts()
	f.ACMEDirectory = `<script>alert(1)</script>`
	for _, s := range buildFirstSteps(f) {
		if s.Title == "Turn on ACME" && !strings.Contains(s.Text, f.ACMEDirectory) {
			t.Error("the directory address is not in the ACME row")
		}
	}
}
