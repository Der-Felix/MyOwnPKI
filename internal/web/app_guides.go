package web

import (
	"log/slog"
	"net/http"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/guides"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/help"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The guides (docs/PHASE3.md section 17, step 72): short, embedded texts in the
// Help area. Both pages are GET only, have no form and change nothing; every
// signed-in user reads them (decision 14). The only thing from the request is
// the slug, and it is an allow-list lookup in the registry: an unknown slug is
// the standard 404 page. Values that appear in commands (the ACME directory, a
// CA name) come from configuration and engine data, never from the request
// (decision 12).

const (
	guidesNavKey = "guides"
	guidesPath   = "/guides"
)

// guideRegistry returns the guides of this app: the ones in the binary, or the
// set the tests give.
func guideRegistry(d AppDeps, log *slog.Logger) *guides.Registry {
	if d.Guides != nil {
		return d.Guides
	}
	reg, err := guides.Embedded()
	if err != nil {
		// Cannot happen in a released build: a test parses every guide.
		log.Error("the embedded guides do not parse; the Help pages stay empty", slog.Any("error", err))
		return guides.Empty()
	}
	return reg
}

// guideValues are the instance values for the placeholders of a guide.
func (a *app) guideValues(c *rc) guides.Values {
	var v guides.Values
	// First steps names the directory address to a role that reads the whole
	// tenant only; every other role gets the documented example, as when ACME
	// is off.
	if c.may(authz.ReadPKI, "") {
		v.ACMEDirectory = a.d.ACMEDirectory
	}
	if cas, err := a.issuableCAs(c); err == nil && len(cas) > 0 {
		v.CAName = cas[0].Name
	}
	return v
}

func (a *app) guideList(c *rc) {
	d := admin.TableData{
		Messages: c.messages(),
		Empty:    "There are no guides in this build.",
		Columns:  []admin.Column{{Label: "Guide"}, {Label: "What it covers"}, {Label: "For"}},
	}
	for _, g := range a.guides.List() {
		d.Rows = append(d.Rows, []admin.Cell{{Text: g.Title, Href: guidesPath + "/" + g.Slug}, {Text: g.Summary}, {Text: g.Audience}})
	}
	p := c.page("Guides", guidesNavKey)
	p.Description = "Short texts for this instance: they show what to do and which command to run, and never change anything or show a secret."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

func (a *app) guidePage(c *rc) {
	g, ok := a.guides.Get(c.r.PathValue("slug"))
	if !ok {
		c.fail(ca.ErrNotFound)
		return
	}
	p := c.page(g.Title, guidesNavKey, view.Crumb{Label: "Guides", Href: guidesPath})
	p.Description = g.Summary
	render(c.w, c.r, a.log, http.StatusOK, help.Guide(p, help.GuideData{Messages: c.messages(), Guide: g.Resolve(a.guideValues(c))}))
}
