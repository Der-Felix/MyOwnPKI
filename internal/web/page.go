package web

import (
	"net/http"
	"slices"

	"github.com/Der-Felix/MyOwnPKI/internal/web/fixture"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// newPage builds the shell metadata for a request. Phase 0 takes tenant and
// user from the fixture; phase 1 takes them from the authenticated session.
// Every page except the dashboard gets "Dashboard" as the first breadcrumb.
func newPage(r *http.Request, title, section string, dev bool, crumbs ...view.Crumb) view.Page {
	if section != "dashboard" {
		crumbs = append([]view.Crumb{{Label: "Dashboard", Href: "/"}}, crumbs...)
	}
	tenant := fixture.Tenants[0]
	if t := r.URL.Query().Get("tenant"); slices.Contains(fixture.Tenants, t) {
		tenant = t
	}
	return view.Page{
		Title:   title,
		Section: section,
		Crumbs:  crumbs,
		Prefs:   view.PrefsFromRequest(r),
		Dev:     dev,
		Tenant:  tenant,
		Tenants: fixture.Tenants,
		User:    fixture.User,
	}
}
