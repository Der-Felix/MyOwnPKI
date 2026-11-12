package tlsscan

import (
	"net/netip"
	"strings"
	"time"
)

// States of an endpoint (docs/PHASE3.md §10.2). The page, the API and the
// alerts show the same one – Assess computes it.
const (
	StatePending     = "pending"     // no scan yet
	StateOK          = "ok"          // the served leaf is the issued one and the chain is trusted
	StateUnmanaged   = "unmanaged"   // nothing was issued for the name and the leaf is not from this PKI
	StateOlder       = "older"       // a valid certificate of this PKI, but superseded
	StateForeign     = "foreign"     // not from this PKI, although the name has a certificate here
	StateWrongName   = "wrong_name"  // from this PKI, but not for this name
	StateRevoked     = "revoked"     // a revoked certificate of this PKI
	StateChain       = "chain"       // the leaf is right, the chain is incomplete or untrusted
	StateUnreachable = "unreachable" // the last scans failed
	StateRefused     = "refused"     // no domain covers the host any more, or the guard refuses it
)

// Alarm severities. They have the values of internal/monitor's Warning and
// Critical (a test there pins it).
const (
	Warning  = "warning"
	Critical = "critical"
)

// ConfirmScans is how many successful scans in a row must see the same
// certificate before a mismatch or a chain problem is an alert: a deployment
// that is half through must not alert.
const ConfirmScans = 2

// DownCritical is how long an endpoint must have been unreachable for
// scan_unreachable to turn critical.
const DownCritical = 24 * time.Hour

// Params are the thresholds of the assessment.
type Params struct {
	// UnreachableAfter is scan_unreachable_after: failed scans in a row.
	UnreachableAfter int
	// MismatchAfter is scan_mismatch_after: the grace time, measured from
	// the creation of the newest certificate for the name.
	MismatchAfter time.Duration
	// ExpiryWarn and ExpiryCrit are monitor.expiry_days: the same question
	// as for certificates, "how long until clients refuse it".
	ExpiryWarn, ExpiryCrit time.Duration
}

// Issued is a certificate of this PKI that counts as current for an
// endpoint's name: valid now, not an agent identity certificate, covering the
// name and not superseded (docs/PHASE3.md §10.2 "What the issued one means").
type Issued struct {
	ID          string
	Fingerprint string
	Serial      string
	NotAfter    time.Time
	CreatedAt   time.Time
}

// Known is what the PKI knows about the served leaf when it is not among the
// current certificates.
type Known struct {
	ID         string
	Serial     string
	Revoked    bool
	CoversName bool
}

// Input is what the PKI says about an endpoint's name.
type Input struct {
	// Current is the expected set.
	Current []Issued
	// Known is the served leaf as a certificate of this PKI (looked up by its
	// fingerprint), nil if it is not one – or if it is among Current.
	Known *Known
}

// Alarm is an alert the state asks for.
type Alarm struct{ Severity string }

// Assessment is the state of an endpoint and the alarms that follow from it.
// An alarm is already past its confirmation and grace time: nil means no
// alert, and an alert that is open resolves.
type Assessment struct {
	State string
	// Newest is the newest certificate of the expected set, if any.
	Newest *Issued
	// ServedIsOurs: the served leaf is a certificate of this PKI.
	ServedIsOurs bool

	Mismatch    *Alarm // scan_mismatch
	Expiry      *Alarm // scan_expiry
	Unreachable *Alarm // scan_unreachable
	Chain       *Alarm // scan_chain
}

// Assess is a pure function: the endpoint with its last scans, what this PKI
// issued for its name and the time give the state and the alarms. It does no
// I/O and reads no clock.
func Assess(ep Endpoint, in Input, p Params, now time.Time) Assessment {
	a := Assessment{State: StatePending}
	for i := range in.Current {
		if a.Newest == nil || in.Current[i].CreatedAt.After(a.Newest.CreatedAt) {
			a.Newest = &in.Current[i]
		}
	}
	switch {
	case !ep.Scanned():
		return a
	case IsRefusal(ep.LastErrorKind):
		a.State = StateRefused
		return a
	case ep.FailStreak >= max(p.UnreachableAfter, 1):
		a.State = StateUnreachable
		if Counts(ep.LastErrorKind) {
			a.Unreachable = &Alarm{Severity: Warning}
			since := ep.LastOKAt
			if since.IsZero() {
				since = ep.CreatedAt
			}
			if now.Sub(since) >= DownCritical {
				a.Unreachable.Severity = Critical
			}
		}
		return a
	case ep.Fingerprint == "":
		return a // failing from the start, but not yet often enough: nothing known
	}
	// Failed scans below the threshold change nothing: a host that reboots
	// keeps the state of its last good scan.
	inCurrent := false
	for _, c := range in.Current {
		if strings.EqualFold(c.Fingerprint, ep.Fingerprint) {
			inCurrent = true
			break
		}
	}
	a.ServedIsOurs = inCurrent || in.Known != nil
	confirmed := ep.SameCount >= ConfirmScans
	graceOver := a.Newest != nil && now.Sub(a.Newest.CreatedAt) >= p.MismatchAfter
	switch {
	case inCurrent && ep.ChainState == ChainTrusted:
		a.State = StateOK
	case inCurrent:
		a.State = StateChain
		if confirmed {
			a.Chain = &Alarm{Severity: Warning}
		}
	case in.Known != nil && in.Known.Revoked:
		a.State = StateRevoked
		if confirmed { // no grace: the certificate is on the CRL
			a.Mismatch = &Alarm{Severity: Critical}
		}
	case len(in.Current) == 0 && ep.IsIP() && ep.SNI == "":
		a.State = StateUnmanaged // the IP of a host says nothing about a name: set an SNI
	case in.Known != nil && !in.Known.CoversName:
		a.State = StateWrongName
	case in.Known != nil:
		a.State = StateOlder
	case len(in.Current) == 0:
		a.State = StateUnmanaged
	default:
		a.State = StateForeign
	}
	if confirmed && graceOver && (a.State == StateOlder || a.State == StateForeign || a.State == StateWrongName) {
		a.Mismatch = &Alarm{Severity: Warning}
	}
	if !ep.NotAfter.IsZero() {
		switch left := ep.NotAfter.Sub(now); {
		case left <= p.ExpiryCrit:
			a.Expiry = &Alarm{Severity: Critical}
		case left <= p.ExpiryWarn:
			a.Expiry = &Alarm{Severity: Warning}
		}
	}
	return a
}

// CoversName reports whether a certificate with these DNS and IP names
// covers name by the rules of RFC 6125: an exact DNS name, or a wildcard in
// the whole leftmost label (one label only: "*.homelab.lan" covers
// "proxy.homelab.lan", not "a.b.homelab.lan" or "homelab.lan"). An IP literal
// matches an IP name. A name is never itself a wildcard.
func CoversName(dnsNames, ips []string, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || strings.Contains(name, "*") {
		return false
	}
	if isIPLiteral(name) {
		for _, ip := range ips {
			if sameIP(ip, name) {
				return true
			}
		}
		return false
	}
	for _, d := range dnsNames {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		switch {
		case d == name:
			return true
		case strings.HasPrefix(d, "*."):
			rest := d[1:] // ".homelab.lan"
			label, ok := strings.CutSuffix(name, rest)
			if ok && label != "" && !strings.Contains(label, ".") && strings.Count(rest, ".") >= 2 {
				return true
			}
		}
	}
	return false
}

func sameIP(a, b string) bool {
	x, ex := netip.ParseAddr(a)
	y, ey := netip.ParseAddr(b)
	return ex == nil && ey == nil && x.Unmap() == y.Unmap()
}

// KnownKind reports whether kind is one of the error kinds of the fixed
// vocabulary – the only error text an alert may carry.
func KnownKind(kind string) bool {
	switch kind {
	case KindDNS, KindTimeout, KindConnRefused, KindCouldNotConnect, KindHandshake, KindNoCertificate, KindClientCert,
		KindRefusedPolicy, KindRefusedDomain, KindRefusedPort:
		return true
	}
	return false
}
