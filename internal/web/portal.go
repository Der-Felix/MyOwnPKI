package web

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// portalOff is the hint of the "Trust portal" row while the tenant setting
// trust_page is off.
const portalOff = "Switched off in Administration → Tenant settings."

// portal describes the trust portal of one root for its detail page: the text
// of the "Trust portal" row and, when the portal is on and the address is
// usable, the plain text "Message for your users". message is "" otherwise.
//
// baseURL is the root's public base URL (the one inside its certificates).
// It goes through trustkit.ValidBaseURL: an empty or odd value gives a hint
// and no address, never a half-checked one. fingerprint is the SHA-256 of the
// certificate in hex ("" while the certificate waits for its signature).
// Every value is shown as escaped text by templ.
func portal(name, baseURL, fingerprint string, enabled bool) (row, message string) {
	if !enabled {
		return portalOff, ""
	}
	base, ok := trustkit.ValidBaseURL(baseURL)
	if !ok {
		return "No address: the public base URL of this root is empty or not a plain http:// or https:// address.", ""
	}
	portalURL := base + "/"
	if fingerprint == "" {
		return portalURL, ""
	}
	return portalURL, userMessage(name, portalURL, fingerprint)
}

// userMessage is the text an admin copies into a mail or a wiki page. It
// carries the address, the root's name and its SHA-256 fingerprint, and says
// that nothing on the page proves itself: the value is the check.
func userMessage(name, url, fingerprint string) string {
	var b strings.Builder
	b.WriteString("Please install our root certificate \"" + name + "\" so that your device trusts our internal websites.\n\n")
	b.WriteString("1. Open this address in your browser: " + url + "\n")
	b.WriteString("2. Pick your device on that page and follow the steps.\n\n")
	b.WriteString("Compare this fingerprint with the SHA-256 shown on that page before you install anything; if they differ, stop and tell us.\n\n")
	b.WriteString("SHA-256 fingerprint of \"" + name + "\":\n")
	b.WriteString(view.Fingerprint(trustkit.ColonHex(fingerprint)) + "\n\n")
	b.WriteString("On an iPhone or iPad there is a second step after the profile is installed: Settings > General > About > Certificate Trust Settings, then switch the root on.\n")
	return b.String()
}

// portalFor is portal for the real UI: it asks the tenant setting trust_page
// (default on; without a settings store the default applies). A setting that
// cannot be read gives a hint and no address.
func (a *app) portalFor(ctx context.Context, name, baseURL, fingerprint string) (row, message string) {
	enabled := true
	if a.d.Settings != nil {
		on, err := a.d.Settings.TrustPage(ctx, a.d.Tenant)
		if err != nil {
			a.log.WarnContext(ctx, "web: reading the trust_page setting", slog.Any("error", err))
			return "Not known: the tenant setting could not be read.", ""
		}
		enabled = on
	}
	return portal(name, baseURL, fingerprint, enabled)
}
