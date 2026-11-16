package web

import (
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/guides"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/help"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// First steps (docs/PHASE3.md section 17, step 73): a checklist computed on
// every request from what the instance already knows. It reads, it never
// writes, and it keeps nothing: no "done" flag, no dismissal, no migration.
// Each row is one of four states, and a row the signed-in role may not read is
// "not available to your role" – never an error and never a tenant-wide fact
// for a role limited to one CA.

// The slugs of the guides the checklist points to. A guide that the build does
// not contain is left out of the row; the row still works.
const (
	guideBuildCA     = "build-a-ca"
	guideOfflineRoot = "offline-root"
	guideCertbot     = "connect-certbot"
	guideAgent       = "install-the-agent"
	guideBackup      = "backup-and-restore"
)

// firstStepsPath and firstStepsNavKey name the page.
const (
	firstStepsPath   = "/first-steps"
	firstStepsNavKey = "first-steps"
)

// docTrustRoot is the page of the documentation site about trusting the root.
const docTrustRoot = guides.SiteBase + "/guides/trust-the-root/"

type stepState int

const (
	stepDone stepState = iota + 1
	stepOpen
	stepNotDetected
	stepNoAccess
)

// firstStepsFacts is everything the checklist is built from. Every field was
// read under the signed-in user's own permissions; a Known field is false when
// the user may not read it.
type firstStepsFacts struct {
	Sealed        bool
	InstanceAdmin bool
	// TenantWide: the role reads the whole tenant (ReadPKI without a CA scope).
	// Only then do the tenant-wide rows say anything.
	TenantWide  bool
	MayManageCA bool
	CanIssue    bool

	CAs []ca.CAInfo // the CAs the user may see

	DomainsKnown bool
	Domains      int

	CertificatesKnown bool
	Certificates      int64 // end-entity certificates, agent certificates not counted

	ACMEDirectory string // "" = ACME is off

	AgentsOn    bool // the agent service is configured
	AgentsKnown bool
	Agents      int

	NotifiersKnown bool
	Notifiers      int
	AlertsOn       bool // the Alerts page exists on this server

	// GuideTitle returns the title of a guide, ok false when the build has none.
	GuideTitle func(slug string) (string, bool)
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.FormatInt(n, 10) + " " + many
}

// step builds one row from its state.
func (f firstStepsFacts) step(title string, st stepState, text string, links ...help.Link) help.Step {
	s := help.Step{Title: title, Text: text, Links: links}
	switch st {
	case stepDone:
		s.Status, s.StatusText = view.StatusOK, "Done"
	case stepOpen:
		s.Status, s.StatusText = view.StatusInfo, "Open"
	case stepNotDetected:
		s.Status, s.StatusText = view.StatusNeutral, "Not detected"
	case stepNoAccess:
		s.Status, s.StatusText = view.StatusNeutral, "Not available to your role"
		s.Text = "Your role does not read this part of the instance. An admin sees the state of this step."
	}
	return s
}

// guideLinks are the links to the named guides that this build contains.
func (f firstStepsFacts) guideLinks(slugs ...string) []help.Link {
	var out []help.Link
	for _, slug := range slugs {
		if title, ok := f.GuideTitle(slug); ok {
			out = append(out, help.Link{Label: "Guide: " + title, Href: guidesPath + "/" + slug})
		}
	}
	return out
}

func linksOf(page []help.Link, guides []help.Link) []help.Link {
	return append(append([]help.Link{}, page...), guides...)
}

// buildFirstSteps turns the facts into the rows, in the order of the page.
func buildFirstSteps(f firstStepsFacts) []help.Step {
	if f.GuideTitle == nil {
		f.GuideTitle = func(string) (string, bool) { return "", false }
	}
	var rows []help.Step
	rows = append(rows, f.stepUnseal(), f.stepCA(), f.stepBaseURL(), f.stepDomain(), f.stepACME(), f.stepCertificate(),
		f.stepHost(), f.stepBackup(), f.stepTrust(), f.stepNotifications())
	return rows
}

func (f firstStepsFacts) stepUnseal() help.Step {
	const title = "Unseal the server"
	if !f.Sealed {
		return f.step(title, stepDone, "The server is unsealed, so it can sign certificates.")
	}
	if f.InstanceAdmin {
		return f.step(title, stepOpen, "The server is sealed: signing is off until an instance admin enters the passphrase.", help.Link{Label: "Unseal", Href: "/unseal"})
	}
	return f.step(title, stepOpen, "The server is sealed: signing is off until an instance admin enters the passphrase. Ask one to unseal it.")
}

// activeCAs counts the CAs that sign.
func (f firstStepsFacts) activeCAs() (active, pending int) {
	for _, info := range f.CAs {
		switch info.Status {
		case ca.StatusActive:
			active++
		case ca.StatusPendingSignature:
			pending++
		}
	}
	return active, pending
}

func (f firstStepsFacts) stepCA() help.Step {
	const title = "Create a certificate authority"
	active, pending := f.activeCAs()
	page := []help.Link{{Label: "Certificate authorities", Href: "/authorities"}}
	if f.MayManageCA {
		page = append(page, help.Link{Label: "New CA", Href: "/authorities/new"})
	}
	guide := f.guideLinks(guideBuildCA, guideOfflineRoot)
	switch {
	case active > 0:
		return f.step(title, stepDone, plural(int64(active), "certificate authority exists", "certificate authorities exist")+".", linksOf(page[:1], guide)...)
	case pending > 0:
		return f.step(title, stepOpen, "A CA waits for the certificate from its offline root. Install it on the CA's page.", linksOf(page[:1], guide)...)
	case !f.TenantWide:
		return f.step(title, stepNoAccess, "")
	}
	return f.step(title, stepOpen, "There is no CA yet. Create an intermediate for daily use, and keep the root offline if you can.", linksOf(page, guide)...)
}

func (f firstStepsFacts) stepBaseURL() help.Step {
	const title = "Public base URL and CRL"
	active, _ := f.activeCAs()
	link := help.Link{Label: "Certificate authorities", Href: "/authorities"}
	if active == 0 {
		if !f.TenantWide {
			return f.step(title, stepNoAccess, "")
		}
		return f.step(title, stepOpen, "A CA comes first. Its public base URL ends up in every certificate it signs, as the address of the CA certificate and the CRL.")
	}
	var noURL, crl int
	for _, info := range f.CAs {
		if info.Status != ca.StatusActive {
			continue
		}
		if info.BaseURL == "" {
			noURL++
		}
		for _, g := range info.Generations {
			if g.CRL != nil && g.CRL.State != ca.CRLOK && g.CRL.State != ca.CRLRenewDue {
				crl++
				break
			}
		}
	}
	switch {
	case noURL > 0:
		return f.step(title, stepOpen, plural(int64(noURL), "CA has", "CAs have")+" no public base URL, so its certificates carry no address for the CA certificate and the CRL.", link)
	case crl > 0:
		return f.step(title, stepOpen, plural(int64(crl), "CA has", "CAs have")+" a CRL that needs attention; the dashboard says which.", link)
	}
	return f.step(title, stepDone, "Every CA has a public base URL and a current CRL. This page does not test whether clients can reach that address.", link)
}

func (f firstStepsFacts) stepDomain() help.Step {
	const title = "Add a domain"
	if !f.DomainsKnown {
		return f.step(title, stepNoAccess, "")
	}
	page := []help.Link{{Label: "Domains", Href: "/domains"}}
	if f.Domains > 0 {
		return f.step(title, stepDone, plural(int64(f.Domains), "domain says", "domains say")+" which names ACME issues for and which CA signs.", page...)
	}
	if f.MayManageCA {
		page = append(page, help.Link{Label: "New domain", Href: "/domains/new"})
	}
	return f.step(title, stepOpen, "ACME issues nothing until a domain says which names it may issue for and which CA signs.", page...)
}

func (f firstStepsFacts) stepACME() help.Step {
	const title = "Turn on ACME"
	if !f.TenantWide {
		return f.step(title, stepNoAccess, "")
	}
	guide := f.guideLinks(guideCertbot)
	if f.ACMEDirectory != "" {
		return f.step(title, stepDone, "The ACME server is on. Clients use the directory address "+f.ACMEDirectory+".", linksOf([]help.Link{{Label: "EAB keys", Href: "/acme/eab"}}, guide)...)
	}
	return f.step(title, stepOpen, "ACME is off: acme.base_url is empty in the configuration. Without it only this web UI issues certificates.", guide...)
}

func (f firstStepsFacts) stepCertificate() help.Step {
	const title = "Issue a first certificate"
	if !f.CertificatesKnown {
		return f.step(title, stepNoAccess, "")
	}
	page := []help.Link{{Label: "Certificates", Href: "/certificates"}}
	if f.Certificates > 0 {
		return f.step(title, stepDone, plural(f.Certificates, "certificate exists", "certificates exist")+" (certificates of agents are not counted).", page...)
	}
	if f.CanIssue {
		page = append(page, help.Link{Label: "Issue certificate", Href: "/certificates/new"})
	}
	return f.step(title, stepOpen, "No certificate has been issued yet. Issue one here, or let a client ask over ACME.", linksOf(page, f.guideLinks(guideCertbot))...)
}

func (f firstStepsFacts) stepHost() help.Step {
	const title = "Add a host with an agent (optional)"
	guide := f.guideLinks(guideAgent)
	switch {
	case !f.TenantWide:
		return f.step(title, stepNoAccess, "")
	case !f.AgentsOn:
		return f.step(title, stepOpen, "Agents are off: agent.base_url, agent.tls_issuer and agent.ca are not all set in the configuration. An agent renews and installs certificates on a host.", guide...)
	case !f.AgentsKnown:
		return f.step(title, stepNoAccess, "")
	case f.Agents > 0:
		return f.step(title, stepDone, plural(int64(f.Agents), "host has", "hosts have")+" an agent.", linksOf([]help.Link{{Label: "Agents", Href: "/agents"}}, guide)...)
	}
	return f.step(title, stepOpen, "No host has an agent yet. Add host takes you from a host name to a deployed certificate.", linksOf([]help.Link{{Label: "Add host", Href: hostAddPath}}, guide)...)
}

func (f firstStepsFacts) stepBackup() help.Step {
	return f.step("Back up the instance", stepNotDetected,
		"The server cannot see whether a backup runs: the daily timer belongs to the host. The guide shows how to check it and how to test a restore.",
		f.guideLinks(guideBackup)...)
}

func (f firstStepsFacts) stepTrust() help.Step {
	return f.step("Trust the root on your devices", stepNotDetected,
		"Devices accept your certificates only after they trust the root. The server cannot know which devices do. The page of a root offers a trust portal with the steps per system.",
		help.Link{Label: "Certificate authorities", Href: "/authorities"}, help.Link{Label: "Trust the root (documentation site)", Href: docTrustRoot, External: true})
}

func (f firstStepsFacts) stepNotifications() help.Step {
	const title = "Set up notifications (optional)"
	if !f.TenantWide {
		return f.step(title, stepNoAccess, "")
	}
	var links []help.Link
	if f.AlertsOn {
		links = []help.Link{{Label: "Alerts", Href: "/alerts"}}
	}
	if f.NotifiersKnown && f.Notifiers > 0 {
		return f.step(title, stepDone, plural(int64(f.Notifiers), "notification channel is", "notification channels are")+" configured.", links...)
	}
	return f.step(title, stepNotDetected, "No notification channel is configured, or this server cannot tell. Open alerts show on the dashboard either way.", links...)
}
