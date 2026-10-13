// Package view holds the types shared by the shell, components and pages:
// page metadata, the user's appearance preferences, status values and date
// formatting. Pages receive plain view models; they never query services.
package view

import (
	"fmt"
	"strings"
	"time"

	"github.com/a-h/templ"
)

// Page is what every page passes to the application shell. The shell renders
// the page header – breadcrumb, title, status, description, actions – from it,
// so every page has the same header.
type Page struct {
	Title       string
	Description string // optional one-line description under the title
	Status      Status // optional status next to the title
	StatusText  string
	Actions     templ.Component // optional command groups right of the title
	Section     string          // key of the active navigation entry
	Crumbs      []Crumb         // breadcrumb trail, without the current page
	Prefs       Prefs
	Dev         bool // show the DEV MODE banner
	Tenant      string
	Tenants     []string
	User        string
	Search      string // current value of the header search box
}

// WithActions returns a copy of p with the given header actions.
func (p Page) WithActions(c templ.Component) Page {
	p.Actions = c
	return p
}

// WithStatus returns a copy of p with a status next to the title.
func (p Page) WithStatus(s Status, text string) Page {
	p.Status, p.StatusText = s, text
	return p
}

// Crumb is one breadcrumb entry; an empty Href renders plain text.
type Crumb struct {
	Label, Href string
}

// Status is the meaning of a status text. Colors are fixed tokens (ADR-12).
type Status string

// Statuses map to the CSS classes st-ok, st-warn, st-crit, st-info, st-neutral.
const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusCrit    Status = "crit"
	StatusInfo    Status = "info"
	StatusNeutral Status = "neutral"
)

// MessageKind selects the label of a message bar.
type MessageKind string

// Message kinds and their labels ("Warning:", "Error:" …).
const (
	MessageInfo    MessageKind = "info"
	MessageSuccess MessageKind = "ok"
	MessageWarning MessageKind = "warn"
	MessageError   MessageKind = "crit"
)

// Label is the text label shown in front of the message.
func (k MessageKind) Label() string {
	switch k {
	case MessageSuccess:
		return "Done:"
	case MessageWarning:
		return "Warning:"
	case MessageError:
		return "Error:"
	case MessageInfo:
		return "Note:"
	default:
		return "Note:"
	}
}

// Message is one message bar.
type Message struct {
	Kind MessageKind
	Text string
}

// KV is one row of a key/value list.
type KV struct {
	Key, Value string
	Mono       bool
}

// Tab is one tab of a tabbed detail page.
type Tab struct {
	Label, Href string
	Active      bool
}

// Date formats a time as an absolute UTC date (2027-01-04).
func Date(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// DateTime formats a time in UTC with minutes (2026-10-13 04:17 UTC).
func DateTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

// Relative describes t relative to now in whole days ("in 83 days", "44 days ago", "today").
func Relative(now, t time.Time) string {
	days := int(t.Sub(now).Hours() / 24)
	switch {
	case days == 0:
		return "today"
	case days == 1:
		return "tomorrow"
	case days == -1:
		return "yesterday"
	case days > 0:
		return fmt.Sprintf("in %d days", days)
	default:
		return fmt.Sprintf("%d days ago", -days)
	}
}

// ColonHex formats hex digits as colon-separated byte pairs, like
// `openssl x509 -fingerprint` (78:3D:62:…). Input case and existing colons are ignored.
func ColonHex(hex string) string {
	h := strings.ToUpper(strings.ReplaceAll(hex, ":", ""))
	pairs := make([]string, 0, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		pairs = append(pairs, h[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// Fingerprint formats a SHA-256 fingerprint like OpenSSL, split into two lines
// of 16 bytes so it fits a details column and can be compared line by line.
func Fingerprint(hex string) string {
	c := ColonHex(hex)
	const firstLine = 16*3 - 1 // 16 pairs and 15 colons
	if len(c) <= firstLine {
		return c
	}
	return c[:firstLine] + ":\n" + c[firstLine+1:]
}
