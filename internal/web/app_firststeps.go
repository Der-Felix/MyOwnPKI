package web

import (
	"errors"
	"net/http"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/help"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// firstSteps is GET /first-steps: a read-only checklist (decision 11). It has
// no form, writes nothing, stores nothing and shows no secret. Every fact is
// read with the calls the dashboard and the list pages make, under the
// signed-in user's own permissions; the page needs no permission of its own
// (decision 14).
func (a *app) firstSteps(c *rc) {
	f, err := a.firstStepsFacts(c)
	if err != nil {
		c.fail(err)
		return
	}
	p := c.page("First steps", firstStepsNavKey)
	p.Description = "What a new instance still needs, with a link to the page or the guide that finishes each step."
	render(c.w, c.r, a.log, http.StatusOK, help.FirstSteps(p, help.FirstStepsData{
		Messages: c.messages(),
		Intro: []string{
			"This page reads what the server knows about the instance and lists what is still to do. It changes nothing and remembers nothing: finish a step on its own page, then reload this one.",
			"A step marked Not detected is something the server cannot see; the guide behind it says how to check it yourself.",
		},
		Steps: buildFirstSteps(f),
	}))
}

// firstStepsFacts reads what the checklist needs. A part the user's role may not
// read stays unknown; only a real failure is an error.
func (a *app) firstStepsFacts(c *rc) (firstStepsFacts, error) {
	ctx := c.r.Context()
	f := firstStepsFacts{
		Sealed:        a.d.Keys.Status().Sealed,
		InstanceAdmin: c.instanceAdmin(),
		TenantWide:    c.may(authz.ReadPKI, ""),
		MayManageCA:   c.may(authz.ManageCA, ""),
		ACMEDirectory: a.d.ACMEDirectory,
		AgentsOn:      a.d.Agents != nil,
		AlertsOn:      a.d.Alerts != nil,
		GuideTitle: func(slug string) (string, bool) {
			g, ok := a.guides.Get(slug)
			if !ok {
				return "", false
			}
			return g.Title, true
		},
	}
	cas, err := a.d.Engine.CAs(ctx, c.who())
	if err != nil {
		return f, err
	}
	f.CAs = cas
	if issuable, issueErr := a.issuableCAs(c); issueErr == nil {
		f.CanIssue = len(issuable) > 0
	}
	if !f.TenantWide {
		// A role limited to one CA reads its own CAs and nothing tenant-wide:
		// the other rows do not say anything about the instance.
		return f, nil
	}
	domains, err := a.d.Engine.ListDomains(ctx, c.who())
	if err != nil && !errors.Is(err, authz.ErrDenied) {
		return f, err
	}
	f.DomainsKnown, f.Domains = err == nil, len(domains)
	counts, _, err := a.d.Engine.CertificateCounts(ctx, c.who(), ca.CertificateFilter{HideAgentCertificates: true})
	if err != nil && !errors.Is(err, authz.ErrDenied) {
		return f, err
	}
	f.CertificatesKnown, f.Certificates = err == nil, counts.Total()
	if a.d.Agents != nil {
		list, listErr := a.d.Agents.ListAgents(ctx, c.who())
		if listErr != nil && !errors.Is(listErr, authz.ErrDenied) {
			return f, listErr
		}
		f.AgentsKnown, f.Agents = listErr == nil, len(list)
	}
	if a.d.Notifier != nil {
		f.NotifiersKnown, f.Notifiers = true, len(a.d.Notifier.Names())
	}
	return f, nil
}

// newInstanceNotice is the one information message of the dashboard while the
// instance is new. It is derived on every request from the same facts and has
// no state: it goes away when the data exists. It names no secret.
var newInstanceNotice = view.Message{Kind: view.MessageInfo, Text: "Your instance is new – see First steps.", Href: firstStepsPath, LinkText: "First steps"}

// instanceIsNew is true while there is no CA, no certificate or, when ACME is
// on, no domain. Only a role that reads the whole tenant can tell; for every
// other role it is false, so the dashboard never claims "no CA" from a view
// that is limited to one.
func (a *app) instanceIsNew(c *rc, cas []ca.CAInfo, endEntity ca.Counts) bool {
	if !c.may(authz.ReadPKI, "") {
		return false
	}
	if len(cas) == 0 || endEntity.Total() == 0 {
		return true
	}
	if a.d.ACMEDirectory != "" {
		domains, err := a.d.Engine.ListDomains(c.r.Context(), c.who())
		return err == nil && len(domains) == 0
	}
	return false
}
