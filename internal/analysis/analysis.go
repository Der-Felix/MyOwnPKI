// Package analysis finds the oddities of a PKI that no alarm covers: a
// certificate nobody serves, two sources issuing for the same names, a
// renewal loop, a wave of expiries, a weak key, a CA that ends before the
// certificates it issues (docs/PHASE3.md section 14).
//
// The rules are pure Go functions over a Snapshot, a plain copy of what the
// server knows at one moment (Load builds it through the existing services).
// Each rule answers in one of three states: ok, findings, or unknown when its
// input is missing (D9: a rule never claims more than the snapshot shows).
// Nothing is stored, nothing is dismissed and nothing leaves the server: the
// package opens no connection (a test checks the import list), and findings
// never become alerts, e-mails or webhooks (D8).
//
// Untrusted text. Certificate, agent and CA names come from CSRs, ACME
// clients and agents. Findings carry them as raw strings, with control and bidi
// characters removed and clipped to a fixed length, inside fixed text templates;
// they never hold markup. Escaping is the job of the template and the JSON
// encoder that render them.
package analysis

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Finding severities (D10). "info" is never a call to act.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Rule states (D9).
const (
	StateOK       = "ok"
	StateFindings = "findings"
	StateUnknown  = "unknown"
)

// MaxFindingsPerRule bounds the findings a Result keeps; the rest is counted.
const MaxFindingsPerRule = 200

// maxClip is the longest attacker-supplied name that goes into a finding,
// in runes.
const maxClip = 120

// Finding is one thing a rule saw. Every field is text, none is markup.
type Finding struct {
	// Key is "rule:subject id", stable between runs.
	Key  string
	Rule string
	// Severity is SeverityInfo, SeverityWarning or SeverityCritical.
	Severity string
	// Subject names what it is about (a certificate, an agent, a week).
	Subject string
	// Seen is what the snapshot shows; Why says why it matters; Recommendation
	// says what to do. A finding never states more than Seen.
	Seen, Why, Recommendation string
	// Href is a path inside the UI ("/certificates/<id>"), or "".
	Href string
}

// Counts are findings by severity.
type Counts struct{ Critical, Warning, Info int }

// Total is every finding counted.
func (c Counts) Total() int { return c.Critical + c.Warning + c.Info }

// Result is what one rule found.
type Result struct {
	ID, Title string
	// State is StateOK, StateFindings or StateUnknown.
	State string
	// Counts are all findings of the rule by severity; Findings holds at most
	// MaxFindingsPerRule of them, most severe first.
	Counts   Counts
	Findings []Finding
	// Unassessed is how many things the rule could not judge for lack of data;
	// UnknownReason says why. With State unknown the reason is the whole
	// answer; with State findings it qualifies them ("and N could not be
	// assessed").
	Unassessed    int
	UnknownReason string
}

// Rule is one rule of the analysis.
type Rule struct {
	ID    string
	Title string
	Eval  func(Snapshot) Result
}

// Rules returns the ten rules in the order of docs/PHASE3.md section 14.2.
func Rules() []Rule {
	return []Rule{
		{RuleOrphanedCertificate, "Orphaned certificate", OrphanedCertificate},
		{RuleDuplicateCertificates, "Duplicate certificates", DuplicateCertificates},
		{RuleRenewalLoop, "Renewal loop", RenewalLoop},
		{RuleExpiryWave, "Expiry wave", ExpiryWave},
		{RuleWeakKey, "Weak key", WeakKey},
		{RuleWeakSignature, "Weak signature", WeakSignature},
		{RuleCACliff, "CA ends before its certificates", CACliff},
		{RuleOutdatedAgent, "Outdated agent", OutdatedAgent},
		{RuleUnusedACMEAccount, "Unused ACME account", UnusedACMEAccount},
		{RuleUnusedDomain, "Unused domain", UnusedDomain},
	}
}

// Run evaluates every rule against the snapshot. The results come in the
// order of Rules; the findings of each are sorted by severity (most severe
// first), subject and key.
func Run(s Snapshot) []Result {
	rules := Rules()
	out := make([]Result, 0, len(rules))
	for _, r := range rules {
		res := r.Eval(s)
		res.ID, res.Title = r.ID, r.Title
		out = append(out, res)
	}
	return out
}

// Findings flattens the results into one list sorted by severity (most severe
// first), rule and subject.
func Findings(results []Result) []Finding {
	var out []Finding
	for _, r := range results {
		out = append(out, r.Findings...)
	}
	sortFindings(out)
	return out
}

// Summary counts what the page and the API show in one line.
type Summary struct {
	Critical, Warning, Info int
	// Unknown is the number of rules that cannot be assessed.
	Unknown int
}

// Summarize counts all findings (also those beyond the cap) and the rules in
// state unknown.
func Summarize(results []Result) Summary {
	var s Summary
	for _, r := range results {
		s.Critical += r.Counts.Critical
		s.Warning += r.Counts.Warning
		s.Info += r.Counts.Info
		if r.State == StateUnknown {
			s.Unknown++
		}
	}
	return s
}

var severityRank = map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}

func sortFindings(f []Finding) {
	slices.SortStableFunc(f, func(a, b Finding) int {
		if c := severityRank[a.Severity] - severityRank[b.Severity]; c != 0 {
			return c
		}
		if c := ruleOrder(a.Rule) - ruleOrder(b.Rule); c != 0 {
			return c
		}
		if c := strings.Compare(a.Subject, b.Subject); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
}

func ruleOrder(id string) int {
	if i := slices.Index(ruleIDs, id); i >= 0 {
		return i
	}
	return len(ruleIDs)
}

// finish builds the Result of a rule from its findings and the number of
// things it could not assess. The state is findings if there are any, else
// unknown if something was left unassessed, else ok.
func finish(findings []Finding, unassessed int, reason string) Result {
	for i := range findings {
		findings[i].clean()
	}
	sortFindings(findings)
	r := Result{State: StateOK}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			r.Counts.Critical++
		case SeverityWarning:
			r.Counts.Warning++
		default:
			r.Counts.Info++
		}
	}
	r.Findings = findings
	if len(findings) > MaxFindingsPerRule {
		r.Findings = slices.Clone(findings[:MaxFindingsPerRule])
	}
	switch {
	case len(findings) > 0:
		r.State = StateFindings
	case unassessed > 0:
		r.State = StateUnknown
	}
	if unassessed > 0 {
		r.Unassessed, r.UnknownReason = unassessed, reason
	}
	return r
}

// unknown is the Result of a rule whose input is missing altogether.
func unknown(reason string) Result {
	return Result{State: StateUnknown, UnknownReason: reason}
}

// clip cleans attacker-supplied text (see CleanText) and shortens it to
// maxClip runes.
func clip(s string) string {
	s = CleanText(s)
	if r := []rune(s); len(r) > maxClip {
		return string(r[:maxClip-1]) + "…"
	}
	return s
}

// CleanText drops control characters (line breaks, TAB, ESC), format
// characters (bidi overrides and isolates, zero-width marks) and invalid UTF-8
// from text that came from a certificate, a CSR or an agent. A name that
// reorders the text around it or hides a character must not reach a page, a
// log or an API consumer. The result is still data: the template escapes it.
func CleanText(s string) string {
	if !strings.ContainsFunc(s, unwantedRune) && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if !unwantedRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unwantedRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError
}

// SafeHref returns href if it is a path inside the UI: one leading slash, then
// no second slash, no backslash and no byte below 0x20 or 0x7f. Browsers strip
// TAB, CR and LF from a URL, so "/<TAB>/host" would become "//host", and some
// treat a backslash like a slash. Anything else gives "": the text of a finding
// stays, its link goes.
func SafeHref(href string) string {
	if !strings.HasPrefix(href, "/") || strings.HasPrefix(href, "//") || strings.ContainsRune(href, '\\') {
		return ""
	}
	for i := 0; i < len(href); i++ {
		if href[i] < 0x20 || href[i] == 0x7f {
			return ""
		}
	}
	return href
}

// clean makes the text fields of a finding safe to render: no control or
// format characters in any of them, and a link that stays inside the UI.
func (f *Finding) clean() {
	f.Subject, f.Seen, f.Why, f.Recommendation = CleanText(f.Subject), CleanText(f.Seen), CleanText(f.Why), CleanText(f.Recommendation)
	f.Href = SafeHref(f.Href)
}
