package web

import (
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/certificates"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// planView turns the engine's plan into the strings of the review step. It
// copies text and decides nothing: the verdict, the reasons and the checks are
// the engine's own. Every string may carry requested names – the templates
// escape them.
func planView(p *ca.Plan) *certificates.PlanView {
	v := &certificates.PlanView{
		Allowed: p.Allowed, Sealed: p.Sealed,
		Prepared: p.GeneratedAt.UTC().Format("15:04") + " UTC",
		Reasons:  p.Reasons, Notes: p.Notes, Warnings: p.Warnings,
		Dropped: p.DroppedCSRNames,
		Subject: p.SubjectDN, AIA: p.AIAURL, CDP: p.CDPURL,
		KeyUsage: orPlain(p.KeyUsage, " (critical)"),
	}
	for _, c := range p.Checks {
		stopped := p.StoppedAt != "" && c.Name == p.StoppedAt
		v.Checks = append(v.Checks, certificates.PlanCheck{Title: c.Title(), Passed: len(c.Problems) == 0, Stopped: stopped, Problems: c.Problems})
		if stopped {
			v.StoppedAt = c.Title()
		}
	}
	if p.StoppedAt != "" && v.StoppedAt == "" {
		v.StoppedAt = p.StoppedAt
	}
	if p.Preset != "" {
		v.Preset = p.Preset + " – " + p.PresetDescription
	}
	for _, n := range p.Names {
		v.Names = append(v.Names, view.KV{Key: nameLabel(n.Type), Value: n.Value, Mono: n.Type == "ip"})
	}
	switch p.KeySource {
	case "csr":
		v.Key = "From the uploaded request: " + algorithmLabel(p.KeyAlgorithm)
	case "server":
		v.Key = "Generated on the server: " + algorithmLabel(p.KeyAlgorithm) + ", stored encrypted"
	}
	if !p.NotBefore.IsZero() {
		v.NotBefore, v.NotAfter = view.DateTime(p.NotBefore), view.DateTime(p.NotAfter)
		v.Days = strconv.Itoa(p.Days) + " days"
	}
	if len(p.ExtKeyUsage) > 0 {
		v.ExtKeyUsage = strings.Join(p.ExtKeyUsage, ", ")
		if p.ExtKeyUsageCritical {
			v.ExtKeyUsage += " (critical)"
		}
	}
	for _, e := range p.Extensions {
		v.Extensions = append(v.Extensions, certificates.PlanExtension{Name: e.Name, OID: e.OID, Critical: e.Critical, Detail: e.Detail})
	}
	if p.CA != "" {
		v.CA = p.CA
		v.CAFacts = "generation " + strconv.FormatInt(p.Generation, 10) + ", signs for at most " + strconv.Itoa(p.MaxValidityDays) + " days"
	}
	for i, l := range p.Chain {
		role := "Intermediate CA"
		switch {
		case l.Root:
			role = "Root"
		case i == 0:
			role = "Issuing CA"
		}
		v.Chain = append(v.Chain, certificates.PlanLink{Role: role, Subject: l.Subject, SHA256: strings.Split(view.Fingerprint(l.SHA256), "\n"), Expires: view.Date(l.NotAfter)})
	}
	return v
}

// orPlain joins names with commas and adds suffix; no names, no text.
func orPlain(names []string, suffix string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ") + suffix
}

func nameLabel(t string) string {
	switch t {
	case "dns":
		return "DNS name"
	case "ip":
		return "IP address"
	case "email":
		return "E-mail address"
	case "uri":
		return "URI"
	default:
		return "Name (" + t + ")"
	}
}
