package web

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// portalOff is the hint of the "Trust portal" row while the tenant setting
// trust_page is off.
const portalOff = "Switched off in Administration → Tenant settings."

// portal describes the trust portal of one root for its detail page: the text
// of the "Trust portal" row and, when the portal is on and lists the root and
// the address is usable, the plain text "Message for your users". message is ""
// otherwise.
//
// baseURL is the root's public base URL (the one inside its certificates).
// It goes through trustkit.ValidBaseURL: an empty or odd value gives a hint
// and no address, never a half-checked one. fingerprint is the SHA-256 of the
// certificate in hex ("" while the certificate waits for its signature).
// unlisted is why the portal does not list this root ([portalUnlisted]; "" when
// it does): the row says so and there is no message, because the address would
// lead to a page without this root. Every value is shown as escaped text by
// templ.
func portal(name, baseURL, fingerprint string, enabled bool, unlisted string) (row, message string) {
	if !enabled {
		return portalOff, ""
	}
	if unlisted != "" {
		return "This root is not offered on the portal (status: " + unlisted + ").", ""
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

// portalUnlisted says why the portal does not list the current generation g of
// a root, or "" when it does. It mirrors what the portal lists (publish.shown):
// the CA is active, and the generation has a signed certificate that is not
// revoked and valid now. The text is a fixed word or the CA's status column.
func portalUnlisted(info ca.CAInfo, g ca.GenerationInfo, hasGeneration bool, now time.Time) string {
	switch {
	case info.Status == ca.StatusPendingSignature:
		return "waits for its signature"
	case info.Status != ca.StatusActive:
		return info.Status
	case !hasGeneration:
		return "no certificate"
	case g.Pending:
		return "waits for its signature"
	case g.Revoked != "":
		return "revoked"
	case now.Before(genTime(g.NotBefore)):
		return "not valid yet"
	case now.After(genTime(g.NotAfter)):
		return "expired"
	}
	return ""
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
func (a *app) portalFor(ctx context.Context, name, baseURL, fingerprint, unlisted string) (row, message string) {
	enabled := true
	if a.d.Settings != nil {
		on, err := a.d.Settings.TrustPage(ctx, a.d.Tenant)
		if err != nil {
			a.log.WarnContext(ctx, "web: reading the trust_page setting", slog.Any("error", err))
			return "Not known: the tenant setting could not be read.", ""
		}
		enabled = on
	}
	return portal(name, baseURL, fingerprint, enabled, unlisted)
}
