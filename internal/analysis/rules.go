package analysis

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

// Rule IDs. They are stable and appear in the API (docs/PHASE3.md section 14.2).
const (
	RuleOrphanedCertificate   = "orphaned_certificate"
	RuleDuplicateCertificates = "duplicate_certificates"
	RuleRenewalLoop           = "renewal_loop"
	RuleExpiryWave            = "expiry_wave"
	RuleWeakKey               = "weak_key"
	RuleWeakSignature         = "weak_signature"
	RuleCACliff               = "ca_cliff"
	RuleOutdatedAgent         = "outdated_agent"
	RuleUnusedACMEAccount     = "unused_acme_account"
	RuleUnusedDomain          = "unused_domain"
)

// Thresholds (D8: constants, not configuration; docs/PHASE3.md open point 4
// says they are defaults to try).
const (
	day = 24 * time.Hour

	// orphaned_certificate: old enough to have been deployed, and the scan
	// window in which an endpoint must have been seen with something else.
	orphanMinAge     = 14 * day
	orphanScanWindow = 7 * day

	// duplicate_certificates: a certificate counts while more than a third
	// of its lifetime is left (the overlap of a renewal is normal); three
	// from one source is the soft case.
	duplicateSameSource = 3

	// renewal_loop.
	loopDay      = 24 * time.Hour
	loopDayWarn  = 3
	loopDayCrit  = 6
	loopWeekWarn = 8

	// expiry_wave: certificates in one week, their share of all valid
	// certificates, and the smallest tenant the share means anything for.
	waveMinInWeek  = 10
	waveMinPercent = 30
	waveMinTenant  = 20

	// weak_key: RSA keys below this are flagged; 2048 is not.
	weakKeyBits = 2048

	// ca_cliff: a CA that ends sooner than this is critical.
	cliffCritical = 14 * day

	// outdated_agent, unused_acme_account, unused_domain.
	accountMinAge = 30 * day
	accountIdle   = 90 * day
	domainMinAge  = 30 * day
)

// ruleIDs is the order of the rules, for sorting.
var ruleIDs = []string{
	RuleOrphanedCertificate, RuleDuplicateCertificates, RuleRenewalLoop, RuleExpiryWave, RuleWeakKey,
	RuleWeakSignature, RuleCACliff, RuleOutdatedAgent, RuleUnusedACMEAccount, RuleUnusedDomain,
}

// --- helpers ---------------------------------------------------------------

func certHref(c *Certificate) string { return "/certificates/" + c.ID }

// afterSnapshot reports whether a certificate was created after the snapshot
// time. Load reads the certificates, their traits and their origins in
// separate queries, so a certificate issued in between is in the walk but not
// in the other maps: that is a race, not a certificate that cannot be read,
// and it belongs to the next snapshot.
func afterSnapshot(c *Certificate, s Snapshot) bool { return c.CreatedAt.After(s.Now) }

// nameSet is the normalized set of a certificate's names – DNS names and IPs,
// or the common name when there are none. Two certificates for the same set
// replace each other (the same notion as internal/monitor).
func nameSet(c *Certificate) string {
	var names []string
	for _, n := range c.DNSNames {
		names = append(names, "dns:"+strings.TrimSuffix(strings.ToLower(n), "."))
	}
	for _, ip := range c.IPs {
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.Unmap().String()
		}
		names = append(names, "ip:"+ip)
	}
	if len(names) == 0 {
		names = append(names, "cn:"+strings.ToLower(c.CommonName))
	}
	slices.Sort(names)
	return strings.Join(slices.Compact(names), ",")
}

// namesOf is the readable form of a name set: "a.lan, b.lan", clipped.
func namesOf(set string) string {
	parts := strings.Split(set, ",")
	for i, p := range parts {
		_, v, _ := strings.Cut(p, ":")
		parts[i] = v
	}
	return clip(strings.Join(parts, ", "))
}

// label is what a certificate is called in a finding.
func label(c *Certificate) string {
	switch {
	case c.CommonName != "":
		return clip(c.CommonName)
	case len(c.DNSNames) > 0:
		return clip(c.DNSNames[0])
	case len(c.IPs) > 0:
		return clip(c.IPs[0])
	}
	return clip(c.Serial)
}

// shortHash identifies a name set in a finding key: stable, short, and free
// of the attacker's characters.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// weekStart is the Monday 00:00 UTC of the ISO week of t.
func weekStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day()-(int(t.Weekday())+6)%7, 0, 0, 0, 0, time.UTC)
}

func weekLabel(t time.Time) string {
	y, w := t.UTC().ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func wholeDays(d time.Duration) int { return int(d / day) }

// describeSource names an issuer key for a finding. The IDs are made by the
// server; the text is clipped all the same.
func describeSource(key string) string {
	switch {
	case key == "ui":
		return "the UI or API"
	case strings.HasPrefix(key, "acme:"):
		return "ACME account " + clip(strings.TrimPrefix(key, "acme:"))
	case strings.HasPrefix(key, "agent:"):
		return "agent " + clip(strings.TrimPrefix(key, "agent:"))
	}
	return "an unknown source"
}

func joinSources(keys []string) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = describeSource(k)
	}
	return strings.Join(parts, ", ")
}

// superseded reports whether a valid certificate with the same name set ends
// later – the notion of "current" the monitor uses.
func supersededSet(certs []Certificate) func(*Certificate) bool {
	latest := map[string]time.Time{}
	for i := range certs {
		k := nameSet(&certs[i])
		if certs[i].NotAfter.After(latest[k]) {
			latest[k] = certs[i].NotAfter
		}
	}
	return func(c *Certificate) bool { return latest[nameSet(c)].After(c.NotAfter) }
}

// --- orphaned_certificate ---------------------------------------------------

// OrphanedCertificate flags a current certificate that no scanned endpoint
// and no agent has served for a week although endpoints that cover its names
// were scanned. It says "not seen", never "unused": the scan reaches only
// the endpoints somebody entered, and only their last answer is stored.
//
// Evidence needed: an endpoint that covers one of the names, was scanned
// successfully within 7 days, serves another certificate, and has done so
// since at least 7 days (FingerprintSince), so no scan of the window can have
// seen this certificate. A certificate without such an endpoint is not judged;
// the rule then reports one summary count, never a finding per certificate.
func OrphanedCertificate(s Snapshot) Result {
	if s.Missing.Scan != "" {
		return unknown(s.Missing.Scan)
	}
	deployed := map[string]bool{} // serial, certificate ID and fingerprint of what agents report as deployed
	for _, a := range s.Agents {
		for _, d := range a.Deployments {
			if d.State != "deployed" || d.Removed {
				continue
			}
			for _, k := range []string{d.Serial, d.CertificateID, d.Fingerprint} {
				if k != "" {
					deployed[strings.ToUpper(k)] = true
				}
			}
		}
	}
	isSuperseded := supersededSet(s.Certificates)
	var findings []Finding
	unassessed := 0
	for i := range s.Certificates {
		c := &s.Certificates[i]
		if c.NotBefore.After(s.Now) || s.Now.Sub(c.CreatedAt) < orphanMinAge || isSuperseded(c) {
			continue
		}
		if deployed[strings.ToUpper(c.Serial)] || deployed[strings.ToUpper(c.ID)] || deployed[strings.ToUpper(c.Fingerprint)] {
			continue
		}
		served, witnesses := false, 0
		for _, ep := range s.Endpoints {
			if !tlsscan.CoversName(c.DNSNames, c.IPs, ep.Name) {
				continue
			}
			if strings.EqualFold(ep.Fingerprint, c.Fingerprint) {
				served = true
				break
			}
			recent := !ep.LastOKAt.IsZero() && s.Now.Sub(ep.LastOKAt) < orphanScanWindow
			stable := !ep.FingerprintSince.IsZero() && s.Now.Sub(ep.FingerprintSince) >= orphanScanWindow
			if recent && stable && ep.Fingerprint != "" {
				witnesses++
			}
		}
		switch {
		case served:
		case witnesses == 0:
			unassessed++
		default:
			findings = append(findings, Finding{
				Key: RuleOrphanedCertificate + ":" + c.ID, Rule: RuleOrphanedCertificate, Severity: SeverityInfo,
				Subject: label(c), Href: certHref(c),
				Seen: fmt.Sprintf("No scanned endpoint served this certificate in the last 7 days and no agent deployment reports it as deployed; %s that cover its names served another certificate.",
					plural(witnesses, "scanned endpoint", "scanned endpoints")),
				Why:            "It may belong to a host that is gone or that no longer uses it. A host that serves two certificates for one name, or several servers behind one address, shows only one of them to the scan.",
				Recommendation: "Check the host, then revoke the certificate if it is not needed (second factor).",
			})
		}
	}
	reason := fmt.Sprintf("%s cannot be checked: no scanned endpoint covers them with a stable result from the last 7 days.", plural(unassessed, "certificate", "certificates"))
	if unassessed == 1 {
		reason = "1 certificate cannot be checked: no scanned endpoint covers it with a stable result from the last 7 days."
	}
	return finish(findings, unassessed, reason)
}

// --- duplicate_certificates -------------------------------------------------

// DuplicateCertificates flags valid certificates with identical names from
// two sources (warning) or three or more from one source (info). A
// certificate counts only while more than a third of its lifetime is left, so
// the overlap of a renewal does not.
func DuplicateCertificates(s Snapshot) Result {
	groups := map[string][]*Certificate{}
	for i := range s.Certificates {
		c := &s.Certificates[i]
		if c.Source != "issued" || afterSnapshot(c, s) {
			continue // imported and external certificates have no issuer of ours; a newer one is for the next run
		}
		lifetime, left := c.NotAfter.Sub(c.NotBefore), c.NotAfter.Sub(s.Now)
		if lifetime <= 0 || left*3 <= lifetime {
			continue
		}
		k := nameSet(c)
		groups[k] = append(groups[k], c)
	}
	var findings []Finding
	unassessed := 0
	for set, certs := range groups {
		if len(certs) < 2 {
			continue
		}
		if slices.ContainsFunc(certs, func(c *Certificate) bool { return c.Class == "" || c.IssuerKey == "" }) {
			unassessed++
			continue
		}
		var issuers []string
		for _, c := range certs {
			if !slices.Contains(issuers, c.IssuerKey) {
				issuers = append(issuers, c.IssuerKey)
			}
		}
		slices.Sort(issuers)
		newest := slices.MaxFunc(certs, func(a, b *Certificate) int { return a.CreatedAt.Compare(b.CreatedAt) })
		f := Finding{
			Key: RuleDuplicateCertificates + ":" + shortHash(set), Rule: RuleDuplicateCertificates,
			Subject: namesOf(set), Href: certHref(newest),
		}
		switch {
		case len(issuers) >= 2:
			f.Severity = SeverityWarning
			f.Seen = fmt.Sprintf("%s for these names come from %s: %s.", plural(len(certs), "valid certificate", "valid certificates"),
				plural(len(issuers), "source", "sources"), joinSources(issuers))
			f.Why = "Two sources issue for the same names; the renewal overlap of one source is normal and ignored. One of them may be forgotten."
			f.Recommendation = "Find out which source is still wanted. Stop the other (an ACME client deactivates its account) and revoke the certificates you do not need (second factor)."
		case len(certs) >= duplicateSameSource:
			f.Severity = SeverityInfo
			f.Seen = fmt.Sprintf("%s for these names come from one source (%s), each with more than a third of its lifetime left.",
				plural(len(certs), "valid certificate", "valid certificates"), joinSources(issuers))
			f.Why = "A client that requests a new certificate before it needs one, or several hosts that share one name, leave surplus certificates behind."
			f.Recommendation = "Check how often the client requests certificates and revoke the surplus ones (second factor)."
		default:
			continue
		}
		findings = append(findings, f)
	}
	return finish(findings, unassessed, fmt.Sprintf("%s for the same names could not be compared: the issuance source of some of their certificates is not known.",
		plural(unassessed, "group of certificates", "groups of certificates")))
}

// --- renewal_loop -------------------------------------------------------------

// RenewalLoop flags a name set for which a client got three or more
// certificates within 24 hours (critical at six) or eight within 7 days. It
// counts certificates of any status: a loop that revokes its predecessors is
// still a loop.
func RenewalLoop(s Snapshot) Result {
	type tally struct {
		day, week int
		issuers   []string
		newest    *Certificate
	}
	groups := map[string]*tally{}
	for i := range s.Recent {
		c := &s.Recent[i]
		age := s.Now.Sub(c.CreatedAt)
		if c.Source != "issued" || age >= RecentWindow || age < 0 {
			continue
		}
		k := nameSet(c)
		t := groups[k]
		if t == nil {
			t = &tally{}
			groups[k] = t
		}
		t.week++
		if age < loopDay {
			t.day++
		}
		src := c.IssuerKey
		if !slices.Contains(t.issuers, src) {
			t.issuers = append(t.issuers, src)
		}
		if t.newest == nil || c.CreatedAt.After(t.newest.CreatedAt) {
			t.newest = c
		}
	}
	var findings []Finding
	for set, t := range groups {
		var sev string
		switch {
		case t.day >= loopDayCrit:
			sev = SeverityCritical
		case t.day >= loopDayWarn, t.week >= loopWeekWarn:
			sev = SeverityWarning
		default:
			continue
		}
		slices.Sort(t.issuers)
		seen := fmt.Sprintf("%s for these names were created in the last 24 hours (%d in 7 days), from %s.",
			plural(t.day, "certificate", "certificates"), t.week, joinSources(t.issuers))
		if t.day < loopDayWarn {
			seen = fmt.Sprintf("%s for these names were created in the last 7 days, from %s.", plural(t.week, "certificate", "certificates"), joinSources(t.issuers))
		}
		findings = append(findings, Finding{
			Key: RuleRenewalLoop + ":" + shortHash(set), Rule: RuleRenewalLoop, Severity: sev, Subject: namesOf(set), Href: certHref(t.newest),
			Seen:           seen,
			Why:            "Usually a deploy hook that fails and rolls back, or a job that never stores the result. ACME servers rate-limit this.",
			Recommendation: "Look at the log of the client on the host that requests them and fix the hook or the job; revoke the surplus certificates if they are not needed (second factor).",
		})
	}
	return finish(findings, 0, "")
}

// --- expiry_wave --------------------------------------------------------------

// ExpiryWave flags a calendar week (ISO, UTC) in which at least 10 valid
// certificates and at least 30% of all valid certificates end. A tenant with
// fewer than 20 valid certificates cannot show a wave: unknown.
func ExpiryWave(s Snapshot) Result {
	total := len(s.Certificates)
	if total < waveMinTenant {
		return unknown(fmt.Sprintf("too few certificates to judge: the tenant has %s and a wave needs at least %d.", plural(total, "valid certificate", "valid certificates"), waveMinTenant))
	}
	weeks := map[time.Time]int{}
	for i := range s.Certificates {
		weeks[weekStart(s.Certificates[i].NotAfter)]++
	}
	var findings []Finding
	for start, n := range weeks {
		if n < waveMinInWeek || n*100 < waveMinPercent*total {
			continue
		}
		lbl := weekLabel(start)
		findings = append(findings, Finding{
			Key: RuleExpiryWave + ":" + lbl, Rule: RuleExpiryWave, Severity: SeverityWarning,
			Subject: "Week " + lbl + " (from " + start.Format(time.DateOnly) + ")", Href: "/certificates",
			Seen:           fmt.Sprintf("%d of %d valid certificates end in week %s.", n, total, lbl),
			Why:            "Renewals that fail together become one big incident.",
			Recommendation: "Let ACME clients renew at two thirds of the lifetime and add jitter, so the ends spread out.",
		})
	}
	return finish(findings, 0, "")
}

// --- weak_key -----------------------------------------------------------------

// WeakKey flags valid certificates with an RSA key under 2048 bits. RSA 2048
// is not flagged. A certificate whose key size could not be read is not
// judged.
func WeakKey(s Snapshot) Result {
	var findings []Finding
	unassessed := 0
	for i := range s.Certificates {
		c := &s.Certificates[i]
		switch {
		case c.Traits == nil && afterSnapshot(c, s):
			// Created after the traits were read: out of scope, not unreadable.
		case c.Traits == nil:
			unassessed++
		case c.Traits.KeyAlgorithm == ca.TraitRSA && c.Traits.KeyBits <= 0:
			unassessed++
		case c.Traits.KeyAlgorithm == ca.TraitRSA && c.Traits.KeyBits < weakKeyBits:
			findings = append(findings, Finding{
				Key: RuleWeakKey + ":" + c.ID, Rule: RuleWeakKey, Severity: SeverityCritical, Subject: label(c), Href: certHref(c),
				Seen:           fmt.Sprintf("The key of this valid certificate is RSA %d bits.", c.Traits.KeyBits),
				Why:            fmt.Sprintf("RSA %d bits can be factored with moderate effort.", c.Traits.KeyBits),
				Recommendation: "Reissue with ECDSA P-256 or RSA 3072 and revoke the old one (second factor).",
			})
		}
	}
	return finish(findings, unassessed, fmt.Sprintf("%s could not be read, so its key size is unknown.", plural(unassessed, "certificate", "certificates")))
}

// --- weak_signature -----------------------------------------------------------

// weakSignatures are the digests that are broken (MD2, MD5) or banned for new
// certificates (SHA-1: CA/B Forum Baseline Requirements).
var weakSignatures = []x509.SignatureAlgorithm{x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1}

func weakSignature(a x509.SignatureAlgorithm) bool { return slices.Contains(weakSignatures, a) }

// WeakSignature flags a valid end-entity or intermediate CA certificate that
// is signed with SHA-1, MD5 or MD2. The signature of a root certificate is
// its own and irrelevant. An algorithm Go does not know is not judged.
func WeakSignature(s Snapshot) Result {
	const why = "SHA-1 collisions are practical; the CA/B Forum Baseline Requirements ban SHA-1 for new certificates."
	var findings []Finding
	unassessed := 0
	for i := range s.Certificates {
		c := &s.Certificates[i]
		switch {
		case c.Traits == nil && afterSnapshot(c, s):
			// Created after the traits were read: out of scope, not unreadable.
		case c.Traits == nil || c.Traits.Signature == x509.UnknownSignatureAlgorithm:
			unassessed++
		case weakSignature(c.Traits.Signature):
			findings = append(findings, Finding{
				Key: RuleWeakSignature + ":" + c.ID, Rule: RuleWeakSignature, Severity: SeverityCritical, Subject: label(c), Href: certHref(c),
				Seen: fmt.Sprintf("This valid certificate is signed with %s.", c.Traits.Signature), Why: why,
				Recommendation: "Reissue from a CA that signs with SHA-256 or better and revoke the old one (second factor).",
			})
		}
	}
	for i := range s.CAs {
		authority := &s.CAs[i]
		for _, g := range authority.Generations {
			if !g.Intermediate || !g.Signed || g.Revoked || !g.NotAfter.After(s.Now) {
				continue
			}
			switch {
			case g.Signature == x509.UnknownSignatureAlgorithm:
				unassessed++
			case weakSignature(g.Signature):
				findings = append(findings, Finding{
					Key: fmt.Sprintf("%s:%s/%d", RuleWeakSignature, authority.ID, g.Number), Rule: RuleWeakSignature, Severity: SeverityCritical,
					Subject: fmt.Sprintf("CA %s, generation %d", clip(authority.Name), g.Number), Href: "/authorities/" + authority.ID,
					Seen: fmt.Sprintf("The certificate of this intermediate CA is signed with %s.", g.Signature), Why: why,
					Recommendation: "Renew the CA below a root that signs with SHA-256 or better (second factor).",
				})
			}
		}
	}
	return finish(findings, unassessed, fmt.Sprintf("%s could not be read, so its signature algorithm is unknown.", plural(unassessed, "certificate", "certificates")))
}

// --- ca_cliff -----------------------------------------------------------------

// CACliff flags an issuing CA whose current certificate ends sooner than the
// default validity of the certificates it issues. The engine shortens a
// default validity to the end of the CA and refuses a longer explicit one, so
// every certificate issued from now on ends with the CA. The default is the
// ACME default: the longest validity_days of the domains of the CA, 90 days
// without a domain, and never more than the CA's maximum validity. The monitor's ca_expiry alert stays the alarm.
func CACliff(s Snapshot) Result {
	var findings []Finding
	unassessed := 0
	for i := range s.CAs {
		authority := &s.CAs[i]
		if !authority.Issuing {
			continue
		}
		gi := slices.IndexFunc(authority.Generations, func(g Generation) bool { return g.Current })
		if gi < 0 || !authority.Generations[gi].Signed {
			unassessed++
			continue
		}
		g := authority.Generations[gi]
		if g.Revoked {
			continue
		}
		// Without a domain the default is the 90 days of the plan; with
		// domains it is the longest of theirs (a CA that ends before the
		// longest default shortens some certificates).
		validity, hasDomain := 0, false
		for j := range s.Domains {
			if s.Domains[j].CAID == authority.ID {
				hasDomain = true
				validity = max(validity, s.Domains[j].EffectiveValidityDays())
			}
		}
		if !hasDomain {
			validity = ca.DefaultACMEValidityDays
		}
		// The engine caps a leaf at the maximum of the CA (which can be
		// lowered after a domain was made), so the default cannot be longer.
		if authority.MaxValidityDays > 0 {
			validity = min(validity, authority.MaxValidityDays)
		}
		left := g.NotAfter.Sub(s.Now)
		if left >= time.Duration(validity)*day {
			continue
		}
		f := Finding{
			Key: RuleCACliff + ":" + authority.ID, Rule: RuleCACliff, Severity: SeverityWarning,
			Subject: "CA " + clip(authority.Name), Href: "/authorities/" + authority.ID,
			Recommendation: "Renew the CA first (second factor). The monitor's ca_expiry alert is the alarm.",
		}
		end := g.NotAfter.UTC().Format(time.DateOnly)
		ending := 0
		for j := range s.Certificates {
			if c := &s.Certificates[j]; c.CAID == authority.ID && c.NotAfter.Equal(g.NotAfter) {
				ending++
			}
		}
		if left <= 0 {
			f.Severity = SeverityCritical
			f.Seen = fmt.Sprintf("The current certificate of this CA ended on %s.", end)
			f.Why = "A CA issues nothing beyond its own end."
		} else {
			if left < cliffCritical {
				f.Severity = SeverityCritical
			}
			f.Seen = fmt.Sprintf("This CA ends on %s, sooner than the ACME default validity of %d days that new certificates get.", end, validity)
			if ending > 0 {
				f.Seen += fmt.Sprintf(" %s already end that day.", plural(ending, "valid certificate", "valid certificates"))
			}
			f.Why = "Every certificate it issues from now on ends on that day at the latest, and a longer explicit request is refused."
		}
		findings = append(findings, f)
	}
	verb := "have"
	if unassessed == 1 {
		verb = "has"
	}
	return finish(findings, unassessed, fmt.Sprintf("%s %s no signed generation yet.", plural(unassessed, "issuing CA", "issuing CAs"), verb))
}

// --- outdated_agent -----------------------------------------------------------

// releaseCore returns major and minor of a strict SemVer string the caller
// has already compared (an optional leading v is allowed).
func releaseCore(v string) (major, minor int) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		major, _ = strconv.Atoi(parts[0])
		minor, _ = strconv.Atoi(parts[1])
	}
	return major, minor
}

// OutdatedAgent flags an active agent older than the server: a minor version
// or more behind is a warning, a patch only info. With a server that is a
// development build, or an agent version that is not strict SemVer, nothing
// can be compared: unknown.
func OutdatedAgent(s Snapshot) Result {
	if s.Missing.Agents != "" {
		return unknown(s.Missing.Agents)
	}
	if _, err := version.Compare(s.ServerVersion, s.ServerVersion); err != nil {
		return unknown("the server runs a development build or a version that is not a release, so versions cannot be compared.")
	}
	sMajor, sMinor := releaseCore(s.ServerVersion)
	var findings []Finding
	unassessed := 0
	for _, a := range s.Agents {
		if a.Status != "active" {
			continue
		}
		cmp, err := version.Compare(a.Version, s.ServerVersion)
		switch {
		case err != nil:
			unassessed++
			continue
		case cmp >= 0:
			continue
		}
		aMajor, aMinor := releaseCore(a.Version)
		sev := SeverityInfo
		if aMajor != sMajor || aMinor != sMinor {
			sev = SeverityWarning
		}
		findings = append(findings, Finding{
			Key: RuleOutdatedAgent + ":" + a.ID, Rule: RuleOutdatedAgent, Severity: sev, Subject: "Agent " + clip(a.Hostname), Href: "/agents/" + a.ID,
			Seen:           fmt.Sprintf("Agent %s runs %s, the server runs %s.", clip(a.Hostname), clip(a.Version), clip(s.ServerVersion)),
			Why:            "An agent that is behind misses fixes and may not understand what the server asks of it.",
			Recommendation: "Update it from Agents, Update, or with the Salt formula.",
		})
	}
	reason := fmt.Sprintf("%s have a version that is not a release number.", plural(unassessed, "agent", "agents"))
	if unassessed == 1 {
		reason = "1 agent has a version that is not a release number."
	}
	return finish(findings, unassessed, reason)
}

// --- unused_acme_account ------------------------------------------------------

// UnusedACMEAccount flags a valid account without agent link that is at
// least 30 days old and has no order for 90 days or ever. Contacts are not
// shown.
func UnusedACMEAccount(s Snapshot) Result {
	var findings []Finding
	for _, a := range s.Accounts {
		age := s.Now.Sub(a.CreatedAt)
		if a.Status != "valid" || a.AgentLinked || age < accountMinAge {
			continue
		}
		var seen string
		switch {
		case a.LastOrderAt.IsZero():
			seen = fmt.Sprintf("This account never ordered a certificate and is %s old.", plural(wholeDays(age), "day", "days"))
		case s.Now.Sub(a.LastOrderAt) >= accountIdle:
			seen = fmt.Sprintf("No orders for %s.", plural(wholeDays(s.Now.Sub(a.LastOrderAt)), "day", "days"))
		default:
			continue
		}
		findings = append(findings, Finding{
			Key: RuleUnusedACMEAccount + ":" + a.ID, Rule: RuleUnusedACMEAccount, Severity: SeverityInfo,
			Subject: "ACME account " + clip(a.ID), Href: "/acme/accounts/" + a.ID,
			Seen:           seen,
			Why:            "It may belong to a retired client; a valid account is a standing permission to order.",
			Recommendation: "An ACME client deactivates its account (RFC 8555 section 7.3.6); the UI cannot yet. Until then it only shows here.",
		})
	}
	// With more accounts than were read, the older ones were not judged: the
	// rule must not say "ok" for them. The number is not known, so it counts
	// as one part that is unassessed.
	if s.AccountsLimit > 0 {
		return finish(findings, 1, fmt.Sprintf("only the newest %d accounts were checked.", s.AccountsLimit))
	}
	return finish(findings, 0, "")
}

// --- unused_domain ------------------------------------------------------------

// UnusedDomain flags a domain at least 30 days old for which no certificate
// of the tenant, whatever its status, has a name the domain covers.
func UnusedDomain(s Snapshot) Result {
	var findings []Finding
	for i := range s.Domains {
		d := &s.Domains[i]
		if s.Now.Sub(d.CreatedAt) < domainMinAge {
			continue
		}
		if slices.ContainsFunc(s.Names, func(n ca.CertName) bool { return d.Covers(n.Type, n.Value) }) {
			continue
		}
		findings = append(findings, Finding{
			Key: RuleUnusedDomain + ":" + d.ID, Rule: RuleUnusedDomain, Severity: SeverityInfo,
			Subject: "Domain " + clip(d.Name), Href: "/domains/" + d.ID,
			Seen:           "No certificate was ever issued for a name under this domain.",
			Why:            "An approved name space nobody uses is a standing permission.",
			Recommendation: "Remove the domain, or issue a first certificate under it.",
		})
	}
	return finish(findings, 0, "")
}
