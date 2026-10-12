// Package design renders the component gallery at /design: every CSS class of
// web/styles is shown here with realistic sample data (frontend.md).
package design

import "github.com/Der-Felix/MyOwnPKI/internal/web/components"

// sampleCert is fixed demo data. Dates are absolute (with a relative hint), as
// the UI will show them; nothing here depends on the current time.
type sampleCert struct {
	CommonName string
	Preset     string
	CA         string
	Serial     string
	Expires    string
	Relative   string
	Status     components.Status
	StatusText string
}

var sampleCerts = []sampleCert{
	{"nas.homelab.lan", "server", "homelab-issuing", "4F3A9C21E07B5D8816A2F0C3B9D47E15", "2027-01-04", "in 83 days", components.StatusOK, "Valid"},
	{"proxmox.homelab.lan", "server", "homelab-issuing", "1B7E0D44A9C3F28E5560B1D7A2C98F03", "2026-11-02", "in 20 days", components.StatusWarn, "Expires soon"},
	{"*.apps.homelab.lan", "wildcard", "homelab-issuing", "6C02E9B5F1A47D3388E0C5B2D91A7F64", "2027-03-18", "in 156 days", components.StatusOK, "Valid"},
	{"it-admin@homelab.lan", "smime", "homelab-users", "2A91F7C05E3B6D8441C9A0E2B7F35D18", "2026-08-30", "44 days ago", components.StatusCrit, "Expired"},
	{"radius.homelab.lan", "server-client", "homelab-issuing", "7D45B0E8C2F19A3667B3E5D0A4C81F92", "2027-05-21", "in 220 days", components.StatusCrit, "Revoked"},
	{"vpn.homelab.lan", "vpn-server", "homelab-issuing", "3E8C1A6F09D27B5554F2B8C0E6A93D71", "2027-09-12", "in 334 days", components.StatusOK, "Valid"},
}

type swatch struct {
	Class, Token, Note string
}

var neutralSwatches = []swatch{
	{"sw-bg", "--bg", "page background"},
	{"sw-surface", "--surface", "tables, cards, inputs"},
	{"sw-surface-2", "--surface-2", "headers, hover"},
	{"sw-border", "--border", "lines"},
	{"sw-text", "--text", "body text"},
	{"sw-text-muted", "--text-muted", "labels, hints"},
	{"sw-brand", "--brand", "primary action (themeable)"},
	{"sw-link", "--link", "links (themeable)"},
}

var statusSwatches = []swatch{
	{"sw-ok", "--status-ok", "valid, success"},
	{"sw-warn", "--status-warn", "expires soon, attention"},
	{"sw-crit", "--status-crit", "expired, revoked, error"},
	{"sw-info", "--status-info", "pending, information"},
}

type tocEntry struct {
	ID, Label string
}

var toc = []tocEntry{
	{"colors", "Colors"},
	{"type", "Typography"},
	{"badges", "Status badges"},
	{"buttons", "Buttons"},
	{"tables", "Tables"},
	{"stats", "KPI tiles"},
	{"forms", "Forms"},
	{"notes", "Notices"},
	{"details", "Details"},
	{"empty", "Empty state & charts"},
	{"themes", "Dark mode & density"},
}

// sampleDNSNames fills the textarea of the form demo (one name per line).
const sampleDNSNames = "nas.homelab.lan\nnas.example.org"

// samplePEM is a truncated, clearly fake PEM block for the code-block demo.
const samplePEM = `-----BEGIN CERTIFICATE-----
MIIB9TCCAZugAwIBAgIUTzqcIeB7XYgWovDDudR+FTAKBggqhkjOPQQDAjAaMRgw
FgYDVQQDDA9ob21lbGFiLWlzc3VpbmcwHhcNMjYxMDEzMDAwMDAwWhcNMjcwMTA0
… sample data – not a real certificate …
-----END CERTIFICATE-----`
