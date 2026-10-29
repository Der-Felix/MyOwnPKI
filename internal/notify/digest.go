// Package notify tells someone about alerts (docs/PHASE3.md §9.3): one
// digest per evaluation and channel, sent by e-mail (net/smtp) or as a
// signed webhook, queued in system.db with retries. The channels and their
// secrets come from the configuration and files, never from the database,
// so a sealed server still reports that it is sealed.
package notify

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// States of an event in a digest.
const (
	Opened   = "opened"   // new alert
	Raised   = "raised"   // warning → critical
	Reminder = "reminder" // still open after repeat_every
	Resolved = "resolved"
	Test     = "test" // `myownpki notify test`
)

// Event is one alert in a digest.
type Event struct {
	Kind     string    `json:"kind"`
	Subject  string    `json:"subject"`
	Severity string    `json:"severity"`
	State    string    `json:"state"`
	Since    time.Time `json:"since"`
	Detail   string    `json:"detail"`
	Link     string    `json:"link,omitempty"`
}

// Digest is one message: everything that changed in one evaluation.
type Digest struct {
	Server  string    `json:"server"`
	Created time.Time `json:"created"`
	Events  []Event   `json:"events"`
}

// TestDigest is the message of `myownpki notify test`.
func TestDigest(server string, now time.Time) Digest {
	return Digest{Server: server, Created: now.UTC(), Events: []Event{{
		Kind: Test, Subject: "Test message", Severity: "info", State: Test, Since: now.UTC(),
		Detail: "A test of this notification channel. Nothing needs attention.",
	}}}
}

// JSON is the webhook body and the queued payload.
func (d Digest) JSON() ([]byte, error) { return json.Marshal(d) }

// ParseDigest reads a queued payload.
func ParseDigest(data []byte) (Digest, error) {
	var d Digest
	err := json.Unmarshal(data, &d)
	return d, err
}

// Subject is the e-mail subject: "[MyOwnPKI] pki01: 2 new, 1 resolved".
func (d Digest) Subject() string {
	count := map[string]int{}
	for _, e := range d.Events {
		count[e.State]++
	}
	var parts []string
	for _, p := range []struct{ state, text string }{
		{Test, "test message"}, {Opened, "new"}, {Raised, "now critical"}, {Reminder, "still open"}, {Resolved, "resolved"},
	} {
		if n := count[p.state]; n > 0 {
			if p.state == Test {
				parts = append(parts, p.text)
				continue
			}
			parts = append(parts, strconv.Itoa(n)+" "+p.text)
		}
	}
	return clean("[MyOwnPKI] " + d.Server + ": " + strings.Join(parts, ", "))
}

// Text is the plain-text e-mail body, grouped by state.
func (d Digest) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "MyOwnPKI on %s, %s\n", clean(d.Server), d.Created.UTC().Format("2006-01-02 15:04 UTC"))
	for _, g := range []struct{ state, title string }{
		{Test, "TEST"}, {Opened, "NEW"}, {Raised, "NOW CRITICAL"}, {Reminder, "STILL OPEN"}, {Resolved, "RESOLVED"},
	} {
		first := true
		for _, e := range d.Events {
			if e.State != g.state {
				continue
			}
			if first {
				fmt.Fprintf(&b, "\n%s\n", g.title)
				first = false
			}
			if e.State == Resolved {
				fmt.Fprintf(&b, "\n  %s (open since %s)\n", clean(e.Subject), e.Since.UTC().Format("2006-01-02 15:04 UTC"))
			} else {
				fmt.Fprintf(&b, "\n  [%s] %s\n  %s\n", e.Severity, clean(e.Subject), clean(e.Detail))
			}
			if e.Link != "" {
				fmt.Fprintf(&b, "  %s\n", clean(e.Link))
			}
		}
	}
	b.WriteString("\n-- \nSent by MyOwnPKI. The open alerts are on the dashboard.\n")
	return b.String()
}

// clean replaces control characters: subjects and details can carry names
// from certificates (attacker input) and must not add mail headers or lines.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
