package monitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// EndpointSource is what the evaluation reads about TLS endpoints
// (*tlsscan.Service).
type EndpointSource interface {
	List(ctx context.Context, who keys.Who) ([]tlsscan.Endpoint, error)
}

// scanFindings turns the last scans into the findings of docs/PHASE3.md
// §10.2: scan_mismatch, scan_expiry, scan_unreachable and scan_chain, one per
// endpoint and kind (key kind:endpoint ID). An alert resolves as soon as the
// finding is gone – the next good scan, a deleted endpoint, scanning
// switched off.
//
// The text of a finding travels to e-mail and webhooks, so it holds only what
// this server wrote itself: the endpoint's host, port and name (validated
// when it was entered), serials, dates and fingerprints of certificates
// (numbers and hex), and error kinds of a fixed vocabulary. The subject and
// issuer of a served certificate are chosen by the remote end and never get
// here – they are on the page and in the API, escaped.
func (e *Evaluator) scanFindings(ctx context.Context, now time.Time, certs *certSet) ([]Finding, error) {
	endpoints, err := e.Scan.List(ctx, e.Who)
	if err != nil {
		return nil, err
	}
	params := tlsscan.Params{
		UnreachableAfter: e.Rules.ScanUnreachableAfter, MismatchAfter: e.Rules.ScanMismatchAfter,
		ExpiryWarn: e.Rules.ExpiryWarn, ExpiryCrit: e.Rules.ExpiryCrit,
	}
	certExpiry := map[string]bool{} // the certificates that have their own cert_expiry finding
	for _, f := range certs.findings {
		if f.Kind == KindCertExpiry {
			certExpiry[strings.TrimPrefix(f.Key, KindCertExpiry+":")] = true
		}
	}
	byFP := map[string]*ca.CertificateInfo{}
	for i := range certs.valid {
		byFP[strings.ToUpper(certs.valid[i].Fingerprint)] = &certs.valid[i]
	}
	lookups := map[string]*ca.CertificateInfo{} // fingerprints not in the valid list, looked up once per run
	var out []Finding
	for _, ep := range endpoints {
		name := ep.Name()
		in := tlsscan.Input{Current: expectedSet(certs, name, now)}
		fp := strings.ToUpper(ep.Fingerprint)
		servedID := currentID(in.Current, fp) // the ID of the served leaf, if the PKI knows it
		if servedID == "" && ep.Scanned() && fp != "" {
			var served *ca.CertificateInfo
			if c, ok := byFP[fp]; ok {
				served = c
			} else if c, ok := lookups[fp]; ok {
				served = c
			} else {
				c, err := e.Engine.CertificateByFingerprint(ctx, e.Who, fp)
				switch {
				case errors.Is(err, ca.ErrNotFound):
					c = nil
				case err != nil:
					return nil, err
				}
				lookups[fp], served = c, c
			}
			if served != nil {
				servedID = served.ID
				in.Known = &tlsscan.Known{
					ID: served.ID, Serial: served.Serial, Revoked: served.Status == ca.CertRevoked,
					CoversName: tlsscan.CoversName(served.DNSNames, served.IPs, name),
				}
			}
		}
		a := tlsscan.Assess(ep, in, params, now)
		out = append(out, endpointFindings(ep, a, in, servedID, certExpiry, now)...)
	}
	return out, nil
}

// expectedSet is the expected set of docs/PHASE3.md §10.2: the certificates
// of this PKI that are valid now, cover the name and are not superseded –
// no other valid certificate with the same normalized name set ends later,
// the rule of the cert_expiry alert. Two certificates with different name
// sets (an exact one and a wildcard one) are both current.
func expectedSet(certs *certSet, name string, now time.Time) []tlsscan.Issued {
	var out []tlsscan.Issued
	for i := range certs.valid {
		c := &certs.valid[i]
		if c.NotBefore.After(now) || !tlsscan.CoversName(c.DNSNames, c.IPs, name) || certs.latest[nameSet(c)].After(c.NotAfter) {
			continue
		}
		out = append(out, tlsscan.Issued{ID: c.ID, Fingerprint: c.Fingerprint, Serial: c.Serial, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt})
	}
	return out
}

// currentID is the ID of the certificate in set with this fingerprint, or "".
func currentID(set []tlsscan.Issued, fp string) string {
	for _, c := range set {
		if strings.EqualFold(c.Fingerprint, fp) {
			return c.ID
		}
	}
	return ""
}

func endpointFindings(ep tlsscan.Endpoint, a tlsscan.Assessment, in tlsscan.Input, servedID string, certExpiry map[string]bool, now time.Time) []Finding {
	var out []Finding
	target, name := ep.Target(), ep.Name()
	add := func(kind string, alarm *tlsscan.Alarm, subject, detail string) {
		out = append(out, Finding{
			Key: kind + ":" + ep.ID, Kind: kind, Subject: subject, Severity: severity(alarm), Detail: detail, Href: "/endpoints",
		})
	}
	if a.Mismatch != nil {
		var detail string
		newest := a.Newest
		switch a.State {
		case tlsscan.StateOlder:
			detail = fmt.Sprintf("%s serves an older certificate of this PKI (serial %s, ends %s) instead of the newest one for %s (serial %s, issued %s) – the renewal did not reach it. Reload the service or check the deployment.",
				target, in.Known.Serial, stamp(ep.NotAfter), name, newest.Serial, stamp(newest.CreatedAt))
		case tlsscan.StateWrongName:
			detail = fmt.Sprintf("%s serves a certificate of this PKI (serial %s) that is not valid for %s; the certificate issued for it has serial %s. Point the service at the right certificate.",
				target, in.Known.Serial, name, newest.Serial)
		case tlsscan.StateRevoked:
			detail = fmt.Sprintf("%s serves a REVOKED certificate of this PKI (serial %s) – clients that check revocation reject it. Replace it at once.", target, in.Known.Serial)
		default: // foreign
			detail = fmt.Sprintf("%s serves a certificate that this PKI did not issue (SHA-256 %s, ends %s), but a certificate was issued for %s (serial %s). Point the service at it.",
				target, ep.Fingerprint, stamp(ep.NotAfter), name, newest.Serial)
		}
		add(KindScanMismatch, a.Mismatch, target, detail)
	}
	if a.Expiry != nil && (servedID == "" || !certExpiry[servedID]) {
		text := "expires " + when(now, ep.NotAfter)
		if !ep.NotAfter.After(now) {
			text = "EXPIRED " + when(now, ep.NotAfter)
		}
		who := "a certificate that this PKI did not issue"
		if a.ServedIsOurs {
			who = "a certificate of this PKI"
		}
		add(KindScanExpiry, a.Expiry, target, fmt.Sprintf("%s serves %s (SHA-256 %s) that %s. Clients refuse it afterwards – deploy a current certificate.", target, who, ep.Fingerprint, text))
	}
	if a.Unreachable != nil {
		kind := "an error"
		if tlsscan.KnownKind(ep.LastErrorKind) {
			kind = ep.LastErrorKind
		}
		add(KindScanUnreachable, a.Unreachable, target, fmt.Sprintf("%s did not answer %d scans in a row (last: %s). Check that the service runs and that the port is open from this server.", target, ep.FailStreak, kind))
	}
	if a.Chain != nil {
		var why string
		if ep.ChainState == tlsscan.ChainIncomplete {
			why = "its chain is incomplete: the service does not send the intermediate CA certificate. Configure it with the full chain (fullchain.pem)."
		} else {
			why = "its chain does not lead to a CA of this PKI. Check which chain file the service sends."
		}
		add(KindScanChain, a.Chain, target, fmt.Sprintf("%s serves the right certificate, but %s", target, why))
	}
	return out
}

func severity(a *tlsscan.Alarm) string {
	if a != nil && a.Severity == tlsscan.Critical {
		return Critical
	}
	return Warning
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
