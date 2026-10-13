package view

import (
	"net/http"
	"slices"
	"strings"
)

// PrefsCookie stores the appearance preferences. It holds no secret, so it
// isn't signed; every value is checked against an allow-list when read.
// With TLS (phase 1) it gets the __Host- prefix and Secure.
const PrefsCookie = "myownpki_ui"

// Layout is the shell variant (ADR-13).
type Layout string

// Theme is the color scheme.
type Theme string

// Density is the spacing of tables and controls.
type Density string

// Allowed values.
const (
	LayoutA Layout = "a" // narrow sidebar
	LayoutB Layout = "b" // standard sidebar
	LayoutC Layout = "c" // no sidebar

	ThemeLight  Theme = "light"
	ThemeDark   Theme = "dark"
	ThemeSystem Theme = "system"

	DensityComfortable Density = "comfortable"
	DensityCompact     Density = "compact"
)

// Layouts, Themes and Densities list the allowed values in display order.
var (
	Layouts   = []Layout{LayoutA, LayoutB, LayoutC}
	Themes    = []Theme{ThemeLight, ThemeDark, ThemeSystem}
	Densities = []Density{DensityComfortable, DensityCompact}
)

// Prefs are the per-user appearance settings.
type Prefs struct {
	Layout  Layout
	Theme   Theme
	Density Density
}

// DefaultPrefs: standard sidebar, light, comfortable.
func DefaultPrefs() Prefs {
	return Prefs{Layout: LayoutB, Theme: ThemeLight, Density: DensityComfortable}
}

// ParsePrefs reads the cookie value "layout.theme.density". Unknown or
// missing parts fall back to the default, so a tampered cookie can never
// inject anything into the page.
func ParsePrefs(value string) Prefs {
	p := DefaultPrefs()
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return p
	}
	if l := Layout(parts[0]); slices.Contains(Layouts, l) {
		p.Layout = l
	}
	if t := Theme(parts[1]); slices.Contains(Themes, t) {
		p.Theme = t
	}
	if d := Density(parts[2]); slices.Contains(Densities, d) {
		p.Density = d
	}
	return p
}

// String is the cookie value.
func (p Prefs) String() string {
	return string(p.Layout) + "." + string(p.Theme) + "." + string(p.Density)
}

// PrefsFromRequest returns the preferences of the request, or the defaults.
func PrefsFromRequest(r *http.Request) Prefs {
	c, err := r.Cookie(PrefsCookie)
	if err != nil {
		return DefaultPrefs()
	}
	return ParsePrefs(c.Value)
}

// Cookie returns the cookie that stores p. secure must be true on TLS listeners.
func (p Prefs) Cookie(secure bool) *http.Cookie {
	// Secure is true on TLS listeners; dev mode is plain HTTP bound to loopback.
	return &http.Cookie{ //nolint:gosec // Secure depends on the listener, see above
		Name:     PrefsCookie,
		Value:    p.String(),
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}
