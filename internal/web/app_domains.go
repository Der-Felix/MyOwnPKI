package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Domains (PHASE2 step 1): the name spaces ACME issues for.

func domainCrumbs() []view.Crumb { return []view.Crumb{{Label: "Domains", Href: "/domains"}} }

func (a *app) domainList(c *rc) {
	list, err := a.d.Engine.ListDomains(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	d := admin.TableData{Messages: c.messages(), Empty: "No domains yet – ACME issues nothing until there is one.",
		Columns: []admin.Column{{Label: "Domain"}, {Label: "CA"}, {Label: "Challenges"}, {Label: "Approval"}, {Label: "Validity", Num: true}}}
	if c.may(authz.ManageCA, "") {
		d.Commands = []admin.Command{{Label: "New domain", Href: "/domains/new", Primary: true}}
	}
	for _, dm := range list {
		name := dm.Name
		if dm.IncludeSubdomains {
			name += " (and below)"
		}
		d.Rows = append(d.Rows, []admin.Cell{{Text: name, Href: "/domains/" + dm.ID}, {Text: dm.CA},
			{Text: strings.Join(dm.ChallengeTypes, ", ")}, {Text: approvalText(dm.Approval)},
			{Text: strconv.Itoa(dm.EffectiveValidityDays()) + " days", Num: true}})
	}
	p := c.page("Domains", "domains")
	p.Description = "Name spaces ACME issues for: which CA signs, which challenges prove control, who must approve."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

func approvalText(a string) string {
	switch a {
	case ca.ApprovalOpen:
		return "open"
	case ca.ApprovalAccount:
		return "approved accounts"
	case ca.ApprovalNewName:
		return "new names"
	}
	return a
}

// domainFields is the form of a domain; d nil = a new one with defaults.
func (a *app) domainFields(c *rc, d *ca.Domain) ([]admin.Field, error) {
	cas, err := a.d.Engine.CAs(c.r.Context(), c.who())
	if err != nil {
		return nil, err
	}
	if d == nil {
		d = &ca.Domain{IncludeSubdomains: true, ChallengeTypes: []string{ca.ChallengeHTTP01, ca.ChallengeDNS01},
			Approval: ca.ApprovalAccount, Preset: "server", AddressPolicy: ca.AddressInternal}
	}
	var caOpts []admin.Option
	for _, info := range cas {
		if info.Kind != ca.KindIntermediate || info.Status != ca.StatusActive || info.KeyMode == ca.KeyModeOffline {
			continue
		}
		caOpts = append(caOpts, admin.Option{Value: info.Name, Label: info.Name, Selected: info.Name == d.CA})
	}
	var presetOpts []admin.Option
	for _, name := range a.d.Presets.Names() {
		p, _ := a.d.Presets.Get(name)
		if slices.Contains(p.SubjectAltNames.Offered, preset.SANDNS) {
			presetOpts = append(presetOpts, admin.Option{Value: name, Label: name, Selected: name == d.Preset})
		}
	}
	opts := func(values []string, current string, label func(string) string) []admin.Option {
		var o []admin.Option
		for _, v := range values {
			o = append(o, admin.Option{Value: v, Label: label(v), Selected: v == current})
		}
		return o
	}
	ranges := make([]string, 0, len(d.IPRanges))
	for _, r := range d.IPRanges {
		ranges = append(ranges, r.String())
	}
	validity := ""
	if d.ValidityDays > 0 {
		validity = strconv.Itoa(d.ValidityDays)
	}
	return []admin.Field{
		{ID: "ca", Label: "Signing CA", Type: "select", Options: caOpts, Hint: "An intermediate whose name constraints permit the domain."},
		{ID: "subdomains", Label: "Names below the domain too (nas.homelab.lan for homelab.lan)", Type: "checkbox", Checked: d.IncludeSubdomains},
		{ID: "wildcards", Label: "Wildcards (*.name) – proven by dns-01 only", Type: "checkbox", Checked: d.Wildcards},
		{ID: "http01", Label: "http-01 (the server fetches a file on port 80)", Type: "checkbox", Checked: d.AllowsChallenge(ca.ChallengeHTTP01)},
		{ID: "dns01", Label: "dns-01 (the server reads a TXT record)", Type: "checkbox", Checked: d.AllowsChallenge(ca.ChallengeDNS01)},
		{ID: "approval", Label: "Approval", Type: "select", Options: opts(ca.Approvals, d.Approval, approvalLabel),
			Hint: "Approved accounts: a new ACME account waits for an admin, or brings an EAB key."},
		{ID: "preset", Label: "Preset", Type: "select", Options: presetOpts},
		{ID: "validity", Label: "Validity in days", Type: "number", Value: validity, Hint: "Empty: 90 days, never beyond the CA's maximum."},
		{ID: "address", Label: "Addresses http-01 may reach", Type: "select", Options: opts(ca.AddressPolicies, d.AddressPolicy, addressLabel)},
		{ID: "ips", Label: "IP ranges for IP certificates", Value: strings.Join(ranges, ", "), Hint: "Comma-separated IPs or CIDRs, e.g. 192.0.2.0/24. http-01 only."},
	}, nil
}

func approvalLabel(v string) string {
	switch v {
	case ca.ApprovalOpen:
		return "open – any account that passes the challenge"
	case ca.ApprovalAccount:
		return "approved accounts – new accounts wait for an admin or bring an EAB key"
	case ca.ApprovalNewName:
		return "new names – the first certificate for a name waits for an admin"
	}
	return v
}

func addressLabel(v string) string {
	if v == ca.AddressPublic {
		return "public addresses only"
	}
	return "internal networks too (homelab)"
}

// domainSettingsFromForm reads the form; every field is sent, so every
// setting is given.
func domainSettingsFromForm(c *rc) ca.DomainSettings {
	f := c.r.PostFormValue
	var challenges []string
	if yes(f("http01")) {
		challenges = append(challenges, ca.ChallengeHTTP01)
	}
	if yes(f("dns01")) {
		challenges = append(challenges, ca.ChallengeDNS01)
	}
	if challenges == nil {
		challenges = []string{}
	}
	ranges := []string{}
	for r := range strings.SplitSeq(f("ips"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			ranges = append(ranges, r)
		}
	}
	validity := 0
	if v := strings.TrimSpace(f("validity")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			n = -1
		}
		validity = n
	}
	caName, approval, presetName, address := f("ca"), f("approval"), f("preset"), f("address")
	sub, wild := yes(f("subdomains")), yes(f("wildcards"))
	return ca.DomainSettings{
		CA: &caName, IncludeSubdomains: &sub, Wildcards: &wild, ChallengeTypes: challenges, Approval: &approval,
		Preset: &presetName, ValidityDays: &validity, AddressPolicy: &address, IPRanges: ranges,
	}
}

func (a *app) domainNew(c *rc) {
	fields, err := a.domainFields(c, nil)
	if err != nil {
		c.fail(err)
		return
	}
	fields = append([]admin.Field{{ID: "name", Label: "Domain", Required: true, Hint: "Lower case, at least two labels, e.g. homelab.lan."}}, fields...)
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("New domain", "domains", domainCrumbs()...), c.form(admin.FormData{
		Intro:  []string{"ACME issues for a name only when a domain covers it. The signing CA's name constraints must permit the domain."},
		Action: "/domains", Submit: "Create domain", Cancel: "/domains", Fields: fields,
	})))
}

func (a *app) domainCreate(c *rc) {
	d, err := a.d.Engine.CreateDomain(c.r.Context(), ca.DomainRequest{
		Name: strings.TrimSpace(c.r.PostFormValue("name")), DomainSettings: domainSettingsFromForm(c), Who: c.who(),
	})
	if err != nil {
		c.refused(err, "/domains/new")
		return
	}
	c.done("/domains/"+d.ID, "Domain "+d.Name+" created.")
}

func (a *app) domainDetail(c *rc) {
	d, err := a.d.Engine.GetDomain(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return
	}
	ranges := make([]string, 0, len(d.IPRanges))
	for _, r := range d.IPRanges {
		ranges = append(ranges, r.String())
	}
	yesNo := map[bool]string{true: "yes", false: "no"}
	sections := []admin.Section{{KV: []view.KV{
		{Key: "Domain", Value: d.Name}, {Key: "Signing CA", Value: d.CA},
		{Key: "Names below it", Value: yesNo[d.IncludeSubdomains]}, {Key: "Wildcards", Value: yesNo[d.Wildcards]},
		{Key: "Challenges", Value: strings.Join(d.ChallengeTypes, ", ")}, {Key: "Approval", Value: approvalLabel(d.Approval)},
		{Key: "Preset", Value: d.Preset}, {Key: "Validity", Value: strconv.Itoa(d.EffectiveValidityDays()) + " days"},
		{Key: "http-01 may reach", Value: addressLabel(d.AddressPolicy)}, {Key: "IP ranges", Value: orDash(strings.Join(ranges, ", "))},
	}}}
	if c.may(authz.ManageCA, d.CA) {
		fields, ferr := a.domainFields(c, d)
		if ferr != nil {
			c.fail(ferr)
			return
		}
		self := "/domains/" + d.ID
		sections = append(sections, admin.Section{Forms: []admin.FormData{
			c.form(admin.FormData{Title: "Change", Action: self, Submit: "Save", Fields: fields}),
			c.form(admin.FormData{Title: "Delete", Action: self + "/delete", Submit: "Delete domain", Danger: true,
				Intro: []string{"Certificates already issued stay valid. Open ACME orders for its names fail."}}),
		}})
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page(d.Name, "domains", domainCrumbs()...), admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func (a *app) domainUpdate(c *rc) {
	id := c.r.PathValue("id")
	if _, err := a.d.Engine.UpdateDomain(c.r.Context(), id, domainSettingsFromForm(c), c.who()); err != nil {
		c.refused(err, "/domains/"+id)
		return
	}
	c.done("/domains/"+id, "Domain saved.")
}

func (a *app) domainDelete(c *rc) {
	id := c.r.PathValue("id")
	if err := a.d.Engine.DeleteDomain(c.r.Context(), id, c.who()); err != nil {
		c.refused(err, "/domains/"+id)
		return
	}
	c.done("/domains", "Domain deleted.")
}
