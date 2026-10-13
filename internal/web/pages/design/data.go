// Package design renders the component gallery at /design: every CSS class of
// web/styles is shown with realistic sample data (frontend.md).
package design

import (
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

type swatch struct {
	Class, Token, Note string
}

var neutralSwatches = []swatch{
	{"sw-bg", "--bg", "content background"},
	{"sw-bg-subtle", "--bg-subtle", "code blocks"},
	{"sw-sidebar", "--sidebar-bg", "navigation"},
	{"sw-header", "--header-bg", "header bar"},
	{"sw-border", "--border", "row separators"},
	{"sw-text", "--text", "body text"},
	{"sw-text-muted", "--text-muted", "labels, hints"},
	{"sw-selected", "--row-selected", "selected rows"},
	{"sw-brand", "--brand", "primary action (themeable)"},
}

var statusSwatches = []swatch{
	{"sw-ok", "--status-ok", "valid, success"},
	{"sw-warn", "--status-warn", "expires soon, attention"},
	{"sw-crit", "--status-crit", "expired, revoked, error"},
	{"sw-info", "--status-info", "pending, information"},
}

var sampleRows = []view.CertRow{
	{ID: "c-0101", CommonName: "nas.homelab.lan", Preset: "server", CA: "homelab-issuing", Serial: "4F3A9C21E07B5D8816A2F0C3B9D47E15", Expires: "2027-01-04", ExpiresRel: "in 83 days", Status: view.StatusOK, StatusText: "Valid"},
	{ID: "c-0102", CommonName: "proxmox.homelab.lan", Preset: "server", CA: "homelab-issuing", Serial: "1B7E0D44A9C3F28E5560B1D7A2C98F03", Expires: "2026-11-02", ExpiresRel: "in 20 days", Status: view.StatusWarn, StatusText: "Expires soon"},
	{ID: "c-0104", CommonName: "radius.homelab.lan", Preset: "server-client", CA: "homelab-issuing", Serial: "7D45B0E8C2F19A3667B3E5D0A4C81F92", Expires: "2027-05-21", ExpiresRel: "in 220 days", Status: view.StatusCrit, StatusText: "Revoked"},
	{ID: "c-0111", CommonName: "it-admin@homelab.lan", Preset: "smime", CA: "homelab-users", Serial: "2A91F7C05E3B6D8441C9A0E2B7F35D18", Expires: "2026-08-30", ExpiresRel: "44 days ago", Status: view.StatusCrit, StatusText: "Expired"},
}

var sampleNumbers = []components.Number{
	{Label: "Certificates", Value: "1,284"},
	{Label: "Valid", Value: "1,241"},
	{Label: "Expire in 30 days", Value: "17", Status: view.StatusWarn},
	{Label: "Revoked", Value: "3"},
	{Label: "Expired", Value: "23", Status: view.StatusCrit},
	{Label: "Certificate authorities", Value: "3"},
}

var sampleKV = []view.KV{
	{Key: "Subject", Value: "CN=nas.homelab.lan"},
	{Key: "Issuer", Value: "CN=Homelab Issuing CA 1, O=Homelab, C=DE"},
	{Key: "Serial number", Value: "4F3A9C21E07B5D8816A2F0C3B9D47E15", Mono: true},
	{Key: "SHA-256 fingerprint", Value: view.Fingerprint("3B9F0AC17E52D48816E0A92C5BF76103CD498A2EF107B693D5206CE84A917F12"), Mono: true},
	{Key: "Valid", Value: "2025-12-03 – 2027-01-04 (83 days left)"},
}

var sampleTabs = []view.Tab{
	{Label: "Overview", Href: "#tabs", Active: true},
	{Label: "Extensions", Href: "#tabs"},
	{Label: "Chain", Href: "#tabs"},
	{Label: "History", Href: "#tabs"},
}

var sampleSteps = []components.Step{
	{Label: "Preset", State: "done"},
	{Label: "Names", State: "current"},
	{Label: "Key", State: "todo"},
	{Label: "Review", State: "todo"},
}

const samplePEM = `-----BEGIN CERTIFICATE-----
MIIB9TCCAZugAwIBAgIUTzqcIeB7XYgWovDDudR+FTAKBggqhkjOPQQDAjAaMRgw
FgYDVQQDDA9ob21lbGFiLWlzc3VpbmcwHhcNMjYxMDEzMDAwMDAwWhcNMjcwMTA0
… sample data – not a real certificate …
-----END CERTIFICATE-----`

// logoVariant is one file of assets/brand shown in the Brand section.
type logoVariant struct {
	File, Use string
	Dark      bool // shown on the header background
	Small     bool // shown at header size instead of sample size
}

var logoVariants = []logoVariant{
	{File: "logo.svg", Use: "Light backgrounds, 64 px and larger (README, documents)"},
	{File: "logo-on-dark.svg", Use: "Dark backgrounds, 64 px and larger", Dark: true},
	{File: "logo-small.svg", Use: "Light backgrounds, 16–48 px: no document lines, larger seal", Small: true},
	{File: "logo-small-on-dark.svg", Use: "Dark backgrounds, 16–48 px – the app header", Dark: true, Small: true},
	{File: "logo-mono.svg", Use: "One color via currentColor (print, embossing); black when used as an image"},
	{File: "favicon.svg", Use: "Browser tab; switches between navy and light with the color scheme", Small: true},
}

// brandColors are the logo colors. They are deliberately not CSS tokens:
// gold is close to the fixed warning color and must never become a UI color.
var brandColors = []view.KV{
	{Key: "Navy", Value: "#1B2B45 – shield and document on light backgrounds"},
	{Key: "Light", Value: "#E6ECF5 – shield and document on dark backgrounds"},
	{Key: "Gold", Value: "#C27F12 – the seal, logo only"},
}
