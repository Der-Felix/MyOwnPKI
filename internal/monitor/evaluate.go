package monitor

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// Finding is one condition the evaluation found. Key is stable across runs
// (kind and the ID of what it is about), so the store can tell new, changed
// and gone conditions apart.
type Finding struct {
	Key, Kind, Subject, Severity, Detail, Href string
}

// Engine is what the evaluation reads from the CA engine.
type Engine interface {
	Certificates(ctx context.Context, who keys.Who, f ca.CertificateFilter) (*ca.CertificatePage, error)
	Certificate(ctx context.Context, who keys.Who, id string) (*ca.CertificateInfo, error)
	CAs(ctx context.Context, who keys.Who) ([]ca.CAInfo, error)
}

// Agents is what the evaluation reads about agents; nil when the agent
// listener is off.
type Agents interface {
	ListAgents(ctx context.Context, who keys.Who) ([]agents.Agent, error)
	GetAgent(ctx context.Context, who keys.Who, id string) (*agents.Agent, error)
}

// Evaluator finds the conditions of docs/PHASE3.md §9.2.
type Evaluator struct {
	Engine Engine
	Agents Agents // nil = no agent rules
	Seal   func() keys.Status
	Rules  Rules
	Who    keys.Who // a system principal that may read the whole tenant
}

// Evaluate returns every condition that holds at now, sorted by key.
func (e *Evaluator) Evaluate(ctx context.Context, now time.Time) ([]Finding, error) {
	var out []Finding
	certs, err := e.certificates(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("monitor: certificates: %w", err)
	}
	out = append(out, certs...)
	cas, err := e.Engine.CAs(ctx, e.Who)
	if err != nil {
		return nil, fmt.Errorf("monitor: CAs: %w", err)
	}
	sealed := e.Seal()
	out = append(out, e.caFindings(cas, now, sealed.Sealed)...)
	out = append(out, e.sealFinding(cas, sealed, now)...)
	if e.Agents != nil {
		ag, err := e.agentFindings(ctx, now)
		if err != nil {
			return nil, fmt.Errorf("monitor: agents: %w", err)
		}
		out = append(out, ag...)
	}
	slices.SortFunc(out, func(a, b Finding) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

// certificates: end-entity certificates that expire (or expired recently)
// and are not superseded by a newer certificate for the same names.
func (e *Evaluator) certificates(ctx context.Context, now time.Time) ([]Finding, error) {
	// Every valid certificate decides what is superseded; the expired ones
	// of the last ExpiredFor can still be unreplaced.
	valid, err := e.allCertificates(ctx, ca.CertificateFilter{Status: ca.CertValid, HideAgentCertificates: true})
	if err != nil {
		return nil, err
	}
	expired, err := e.allCertificates(ctx, ca.CertificateFilter{Status: ca.CertExpired, HideAgentCertificates: true})
	if err != nil {
		return nil, err
	}
	latest := map[string]time.Time{} // name set → the latest end of a valid certificate
	for i := range valid {
		k := nameSet(&valid[i])
		if valid[i].NotAfter.After(latest[k]) {
			latest[k] = valid[i].NotAfter
		}
	}
	var out []Finding
	check := func(c *ca.CertificateInfo) {
		left := c.NotAfter.Sub(now)
		if left > e.Rules.ExpiryWarn || -left > e.Rules.ExpiredFor {
			return
		}
		if latest[nameSet(c)].After(c.NotAfter) {
			return // renewed: a newer certificate covers the same names
		}
		sev, text := Warning, "expires "+when(now, c.NotAfter)
		switch {
		case left <= 0:
			sev, text = Critical, "EXPIRED "+when(now, c.NotAfter)
		case left <= e.Rules.ExpiryCrit:
			sev = Critical
		}
		out = append(out, Finding{
			Key: KindCertExpiry + ":" + c.ID, Kind: KindCertExpiry, Subject: label(c), Severity: sev,
			Detail: fmt.Sprintf("Certificate %s (serial %s, CA %s) %s and no newer certificate covers its names – renew it.", label(c), c.Serial, c.CAName, text),
			Href:   "/certificates/" + c.ID,
		})
	}
	for i := range valid {
		check(&valid[i])
	}
	for i := range expired {
		check(&expired[i])
	}
	return out, nil
}

func (e *Evaluator) allCertificates(ctx context.Context, f ca.CertificateFilter) ([]ca.CertificateInfo, error) {
	f.Limit = ca.MaxPageSize
	var out []ca.CertificateInfo
	for {
		page, err := e.Engine.Certificates(ctx, e.Who, f)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.NextCursor == "" {
			return out, nil
		}
		f.Cursor = page.NextCursor
	}
}

// nameSet is the normalized set of a certificate's names – the DNS names and
// IPs, or the common name when it has none. Two certificates for the same
// set replace each other.
func nameSet(c *ca.CertificateInfo) string {
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

func label(c *ca.CertificateInfo) string {
	switch {
	case c.CommonName != "":
		return c.CommonName
	case len(c.DNSNames) > 0:
		return c.DNSNames[0]
	case len(c.IPs) > 0:
		return c.IPs[0]
	}
	return c.Serial
}

// caFindings: CA certificates that expire and CRLs that are not current –
// the same states the dashboard shows.
func (e *Evaluator) caFindings(cas []ca.CAInfo, now time.Time, sealed bool) []Finding {
	var out []Finding
	for _, info := range cas {
		href := "/authorities/" + info.ID
		for _, g := range info.Generations {
			if g.CRL != nil && (g.CRL.State == ca.CRLWarning || g.CRL.State == ca.CRLMissing || g.CRL.State == ca.CRLExpired) {
				sev := Warning
				if g.CRL.State == ca.CRLExpired {
					sev = Critical
				}
				subject := info.Name + "/" + strconv.FormatInt(g.Generation, 10)
				out = append(out, Finding{
					Key: KindCRL + ":" + info.ID + "/" + strconv.FormatInt(g.Generation, 10), Kind: KindCRL,
					Subject: "CRL of " + subject, Severity: sev,
					Detail: "CRL of " + subject + ": " + g.CRL.Message(sealed) + ".", Href: href,
				})
			}
		}
		if info.Status != ca.StatusActive {
			continue
		}
		g, ok := currentGeneration(info)
		if !ok || g.Revoked != "" {
			continue
		}
		end, err := time.Parse(time.RFC3339, g.NotAfter)
		if err != nil {
			continue
		}
		left := end.Sub(now)
		if left > e.Rules.CAWarn {
			continue
		}
		sev, text := Warning, "expires "+when(now, end)
		switch {
		case left <= 0:
			sev, text = Critical, "EXPIRED "+when(now, end)
		case left <= e.Rules.CACrit:
			sev = Critical
		}
		out = append(out, Finding{
			Key: KindCAExpiry + ":" + info.ID, Kind: KindCAExpiry, Subject: "CA " + info.Name, Severity: sev,
			Detail: "The certificate of CA " + info.Name + " " + text + " – renew the CA before certificates below it stop working.",
			Href:   href,
		})
	}
	return out
}

func currentGeneration(info ca.CAInfo) (ca.GenerationInfo, bool) {
	for _, g := range info.Generations {
		if g.Current {
			return g, true
		}
	}
	return ca.GenerationInfo{}, false
}

// sealFinding: sealed longer than SealedAfter; critical when an online CA's
// CRL needs a new signature within CRLHorizon.
func (e *Evaluator) sealFinding(cas []ca.CAInfo, st keys.Status, now time.Time) []Finding {
	if !st.Sealed || now.Sub(st.SealedSince) < e.Rules.SealedAfter {
		return nil
	}
	sev := Warning
	detail := "The server has been sealed since " + st.SealedSince.UTC().Format("2006-01-02 15:04 UTC") +
		" – it signs nothing: no certificates, no ACME orders, no CRLs. Unseal it in the browser."
	var soonest time.Time
	for _, info := range cas {
		if info.KeyMode != ca.KeyModeOnlineEncrypted {
			continue
		}
		for _, g := range info.Generations {
			if g.CRL != nil && !g.CRL.NextUpdate.IsZero() && (soonest.IsZero() || g.CRL.NextUpdate.Before(soonest)) {
				soonest = g.CRL.NextUpdate
			}
		}
	}
	if !soonest.IsZero() && soonest.Sub(now) < e.Rules.CRLHorizon {
		sev = Critical
		detail += " A CRL expires " + when(now, soonest) + "; after that, clients that check revocation reject certificates."
	}
	return []Finding{{Key: KindSealed + ":server", Kind: KindSealed, Subject: "Server sealed", Severity: sev, Detail: detail, Href: "/unseal"}}
}

// agentFindings: silent agents, agent certificates that were not renewed,
// failed deployments.
func (e *Evaluator) agentFindings(ctx context.Context, now time.Time) ([]Finding, error) {
	list, err := e.Agents.ListAgents(ctx, e.Who)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, a := range list {
		if a.Status != agents.StatusActive {
			continue
		}
		href := "/agents/" + a.ID
		if !a.LastSeenAt.IsZero() {
			if silent := now.Sub(a.LastSeenAt); silent >= e.Rules.AgentSilentWarn {
				sev := Warning
				if silent >= e.Rules.AgentSilentCrit {
					sev = Critical
				}
				out = append(out, Finding{
					Key: KindAgentSilent + ":" + a.ID, Kind: KindAgentSilent, Subject: "Agent " + a.Hostname, Severity: sev,
					Detail: "Agent " + a.Hostname + " last reported " + when(now, a.LastSeenAt) + " – check that myownpki-agent runs and reaches the server on the agent port.",
					Href:   href,
				})
			}
		}
		if a.CertificateID != "" {
			cert, err := e.Engine.Certificate(ctx, e.Who, a.CertificateID)
			if err != nil {
				return nil, err
			}
			if cert.NotAfter.Sub(now) < e.Rules.AgentCertificate {
				out = append(out, Finding{
					Key: KindAgentCertificate + ":" + a.ID, Kind: KindAgentCertificate, Subject: "Agent " + a.Hostname, Severity: Critical,
					Detail: "The agent certificate of " + a.Hostname + " expires " + when(now, cert.NotAfter) + "; its renewal at 2/3 of the lifetime did not happen. Without it the agent can no longer reach the server.",
					Href:   href,
				})
			}
		}
		full, err := e.Agents.GetAgent(ctx, e.Who, a.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range full.Deployments {
			if d.Removed || (d.State != "failed" && d.State != "rolled_back") {
				continue
			}
			what := "failed"
			if d.State == "rolled_back" {
				what = "was rolled back"
			}
			msg := "Deployment " + d.Name + " on " + a.Hostname + " " + what
			if d.LastError != "" {
				msg += ": " + d.LastError
			}
			out = append(out, Finding{
				Key: KindDeployFailed + ":" + a.ID + "/" + d.Name, Kind: KindDeployFailed, Subject: d.Name + " on " + a.Hostname, Severity: Warning,
				Detail: msg + ". The previous certificate is still in place; check the agent log (journalctl -u myownpki-agent).",
				Href:   href,
			})
		}
	}
	return out, nil
}

// when is "in 3 days (2026-11-01 12:00 UTC)" or "2 hours ago (…)".
func when(now, t time.Time) string {
	d := t.Sub(now)
	abs := d
	if abs < 0 {
		abs = -abs
	}
	var amount string
	switch {
	case abs >= 2*day:
		amount = strconv.Itoa(int(abs/day)) + " days"
	case abs >= 2*time.Hour:
		amount = strconv.Itoa(int(abs/time.Hour)) + " hours"
	default:
		amount = strconv.Itoa(int(abs/time.Minute)) + " minutes"
	}
	stamp := " (" + t.UTC().Format("2006-01-02 15:04 UTC") + ")"
	if d < 0 {
		return amount + " ago" + stamp
	}
	return "in " + amount + stamp
}
