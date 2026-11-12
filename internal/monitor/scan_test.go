package monitor

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// fakeScans is the endpoint list the evaluation reads: the tests set what
// the last scans found, the certificates come from the real engine.
type fakeScans struct{ eps []tlsscan.Endpoint }

func (f *fakeScans) List(context.Context, keys.Who) ([]tlsscan.Endpoint, error) {
	return slices.Clone(f.eps), nil
}

// scanEnv is an environment whose evaluator reads the fake scans.
func scanEnv(t *testing.T) (*env, *fakeScans) {
	t.Helper()
	e := newEnv(t)
	f := &fakeScans{}
	e.eval.Scan = f
	return e, f
}

// served is an endpoint whose last scans saw the certificate with this
// fingerprint, count times in a row, with a trusted chain.
func (e *env) served(id, host, fp string, notAfter time.Time, count int) tlsscan.Endpoint {
	now := e.inst.Clock.Now().UTC().Truncate(time.Second)
	return tlsscan.Endpoint{
		ID: id, Host: host, Port: 443, CreatedAt: now.Add(-48 * time.Hour), LastScanAt: now, LastOKAt: now,
		Fingerprint: fp, Serial: "ABCD", Subject: "CN=" + host, Issuer: "CN=Some CA", NotBefore: now.Add(-day), NotAfter: notAfter,
		ChainLen: 2, ChainState: tlsscan.ChainTrusted, TLSVersion: "TLS 1.3", SameCount: count, FingerprintSince: now.Add(-day),
	}
}

func TestScanPinsTheSeverities(t *testing.T) {
	t.Parallel()
	if tlsscan.Warning != Warning || tlsscan.Critical != Critical {
		t.Errorf("severities differ: %q %q", tlsscan.Warning, tlsscan.Critical)
	}
}

// TestScanMismatch: an older certificate of this PKI that is still served
// alerts after the confirmation scan and the grace time, and resolves with
// the next good scan.
func TestScanMismatch(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	old := e.issue(t, 90, "www.homelab.lan")
	e.inst.Clock.Advance(time.Minute)
	renewed := e.issue(t, 90, "www.homelab.lan") // the renewal: old is superseded

	// The deployment is under way: inside the grace time nothing alerts, even
	// if the older certificate has been seen often.
	scans.eps = []tlsscan.Endpoint{e.served("ep_1", "www.homelab.lan", old.Fingerprint, old.NotAfter, 5)}
	found, _ := e.run(t)
	if got := byKind(found, KindScanMismatch); len(got) != 0 {
		t.Fatalf("inside the grace time: %+v", got)
	}

	// Past the grace time, but this fingerprint was seen only once: wait for the confirmation scan.
	e.inst.Clock.Advance(time.Hour)
	scans.eps = []tlsscan.Endpoint{e.served("ep_1", "www.homelab.lan", old.Fingerprint, old.NotAfter, 1)}
	found, _ = e.run(t)
	if got := byKind(found, KindScanMismatch); len(got) != 0 {
		t.Fatalf("before the confirmation: %+v", got)
	}

	// The second scan of the same fingerprint opens it.
	scans.eps = []tlsscan.Endpoint{e.served("ep_1", "www.homelab.lan", old.Fingerprint, old.NotAfter, 2)}
	found, ch := e.run(t)
	got := byKind(found, KindScanMismatch)
	if len(got) != 1 || got[0].Key != "scan_mismatch:ep_1" || got[0].Severity != Warning || got[0].Subject != "www.homelab.lan:443" || got[0].Href != "/endpoints" ||
		len(only(ch.Opened, KindScanMismatch)) != 1 {
		t.Fatalf("after the confirmation: %+v / %+v", got, ch)
	}
	for _, want := range []string{"www.homelab.lan:443", "older certificate", old.SerialHex, renewed.SerialHex, "Reload the service"} {
		if !strings.Contains(got[0].Detail, want) {
			t.Errorf("detail lacks %q: %s", want, got[0].Detail)
		}
	}

	// The page and the API read the same state.
	states, err := e.eval.EndpointStates(t.Context(), e.inst.Clock.Now())
	if err != nil || len(states) != 1 || states[0].Assessment.State != tlsscan.StateOlder || states[0].ServedID != old.ID ||
		states[0].Input.Known == nil || states[0].Input.Known.Serial != old.SerialHex || states[0].Assessment.Newest == nil || states[0].Assessment.Newest.Serial != renewed.SerialHex {
		t.Fatalf("EndpointStates: %+v, %v", states, err)
	}

	// No duplicates across runs.
	for range 3 {
		if _, ch = e.run(t); len(ch.Opened)+len(ch.Resolved)+len(ch.Raised) != 0 {
			t.Fatalf("another run changed alerts: %+v", ch)
		}
	}

	// The right certificate is served again: the next scan resolves it.
	scans.eps = []tlsscan.Endpoint{e.served("ep_1", "www.homelab.lan", renewed.Fingerprint, renewed.NotAfter, 1)}
	found, ch = e.run(t)
	if len(byKind(found, KindScanMismatch)) != 0 || len(only(ch.Resolved, KindScanMismatch)) != 1 {
		t.Fatalf("after the fix: %+v / %+v", found, ch)
	}
}

func TestScanMismatchForeignWrongNameAndRevoked(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	right := e.issue(t, 90, "www.homelab.lan")
	other := e.issue(t, 90, "other.homelab.lan")
	e.inst.Clock.Advance(2 * time.Hour)
	foreignFP := strings.Repeat("AB", 32)

	scans.eps = []tlsscan.Endpoint{
		e.served("ep_foreign", "www.homelab.lan", foreignFP, e.inst.Clock.Now().Add(90*day), 2),
		e.served("ep_name", "www.homelab.lan", other.Fingerprint, other.NotAfter, 2),
		e.served("ep_ok", "www.homelab.lan", right.Fingerprint, right.NotAfter, 2),
	}
	scans.eps[1].SNI = "" // the other host's certificate, served for www
	found, _ := e.run(t)
	if got := byKind(found, KindScanMismatch); len(got) != 2 || got[0].Severity != Warning || got[1].Severity != Warning {
		t.Fatalf("foreign and wrong name: %+v", got)
	}
	if d := byKey(found, "scan_mismatch:ep_foreign").Detail; !strings.Contains(d, foreignFP) || !strings.Contains(d, "did not issue") {
		t.Errorf("foreign: %s", d)
	}
	if d := byKey(found, "scan_mismatch:ep_name").Detail; !strings.Contains(d, "not valid for www.homelab.lan") || !strings.Contains(d, other.SerialHex) {
		t.Errorf("wrong name: %s", d)
	}

	// A revoked certificate: critical after two scans, with no grace time.
	if _, err := e.inst.Engine.Revoke(t.Context(), ca.RevokeRequest{CertificateID: other.ID, Reason: "keyCompromise", Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	scans.eps = []tlsscan.Endpoint{e.served("ep_rev", "other.homelab.lan", other.Fingerprint, other.NotAfter, 1)}
	if found, _ = e.run(t); len(byKind(found, KindScanMismatch)) != 0 {
		t.Fatalf("revoked, seen once: %+v", found)
	}
	scans.eps[0].SameCount = 2
	found, _ = e.run(t)
	f := byKey(found, "scan_mismatch:ep_rev")
	if f.Severity != Critical || !strings.Contains(f.Detail, "REVOKED") || !strings.Contains(f.Detail, other.SerialHex) {
		t.Fatalf("revoked: %+v", f)
	}
}

// TestScanUnmanaged: a name this PKI never issued for is not a mismatch; its
// unreachability and its expiry still alert.
func TestScanUnmanaged(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	e.issue(t, 90, "www.homelab.lan")
	e.inst.Clock.Advance(2 * time.Hour)
	foreignFP := strings.Repeat("CD", 32)
	soon := e.inst.Clock.Now().Add(2 * day)
	scans.eps = []tlsscan.Endpoint{
		e.served("ep_1", "nas.homelab.lan", foreignFP, soon, 5),
		e.served("ep_2", "192.0.2.10", foreignFP, e.inst.Clock.Now().Add(90*day), 5), // an IP without SNI says nothing about a name
	}
	found, _ := e.run(t)
	if got := byKind(found, KindScanMismatch); len(got) != 0 {
		t.Fatalf("unmanaged: %+v", got)
	}
	if f := byKey(found, "scan_expiry:ep_1"); f.Severity != Critical || !strings.Contains(f.Detail, "did not issue") || !strings.Contains(f.Detail, foreignFP) {
		t.Fatalf("expiry of an unmanaged certificate: %+v", f)
	}
	scans.eps[0].FailStreak, scans.eps[0].LastErrorKind = 3, tlsscan.KindTimeout
	found, _ = e.run(t)
	if len(byKind(found, KindScanUnreachable)) != 1 {
		t.Fatalf("unmanaged and unreachable: %+v", found)
	}
}

func TestScanWildcardAndIPEndpoints(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	wild, err := e.inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "wildcard", DNSNames: []string{"*.homelab.lan"}, ValidityDays: 90, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	e.inst.Clock.Advance(2 * time.Hour)
	scans.eps = []tlsscan.Endpoint{
		e.served("ep_1", "proxy.homelab.lan", wild.Fingerprint, wild.NotAfter, 5),         // one label below: covered
		e.served("ep_2", "a.b.homelab.lan", wild.Fingerprint, wild.NotAfter, 5),           // two labels: not covered, and nothing is issued for the name
		e.served("ep_3", "192.0.2.10", wild.Fingerprint, wild.NotAfter, 5),                // an IP without SNI
		e.served("ep_4", "proxy.homelab.lan", strings.Repeat("EF", 32), wild.NotAfter, 5), // foreign, a wildcard is current for the name
	}
	scans.eps[3].Port = 8443
	scans.eps[2].SNI = ""
	found, _ := e.run(t)
	got := byKind(found, KindScanMismatch)
	if len(got) != 1 || got[0].Key != "scan_mismatch:ep_4" {
		t.Fatalf("mismatches: %+v", got)
	}
	// An IP endpoint with an SNI is judged by that name.
	scans.eps = []tlsscan.Endpoint{e.served("ep_5", "192.0.2.10", wild.Fingerprint, wild.NotAfter, 5)}
	scans.eps[0].SNI = "web.homelab.lan"
	if found, _ = e.run(t); len(found) != 0 {
		t.Fatalf("IP with an SNI the wildcard covers: %+v", found)
	}
}

// TestScanUnreachable: opens at the Nth failed scan and not for a reboot,
// turns critical after a day and resolves when the host is back.
func TestScanUnreachable(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	cert := e.issue(t, 90, "www.homelab.lan")
	ep := e.served("ep_1", "www.homelab.lan", cert.Fingerprint, cert.NotAfter, 4)
	scans.eps = []tlsscan.Endpoint{ep}
	e.run(t)
	for streak := 1; streak <= 2; streak++ { // the host reboots
		ep.FailStreak, ep.LastErrorKind, ep.LastError, ep.LastScanAt = streak, tlsscan.KindConnRefused, tlsscan.KindConnRefused, e.inst.Clock.Now()
		scans.eps = []tlsscan.Endpoint{ep}
		if found, ch := e.run(t); len(found) != 0 || !ch.Empty() {
			t.Fatalf("failure %d alerts: %+v / %+v", streak, found, ch)
		}
	}
	ep.FailStreak = 3
	scans.eps = []tlsscan.Endpoint{ep}
	found, ch := e.run(t)
	f := byKey(found, "scan_unreachable:ep_1")
	if f.Severity != Warning || len(only(ch.Opened, KindScanUnreachable)) != 1 || !strings.Contains(f.Detail, "did not answer 3 scans in a row") || !strings.Contains(f.Detail, tlsscan.KindConnRefused) {
		t.Fatalf("third failure: %+v / %+v", f, ch)
	}
	// Down for 24 hours: critical.
	e.inst.Clock.Advance(25 * time.Hour)
	ep.FailStreak = 90
	scans.eps = []tlsscan.Endpoint{ep}
	found, ch = e.run(t)
	if byKey(found, "scan_unreachable:ep_1").Severity != Critical || len(only(ch.Raised, KindScanUnreachable)) != 1 {
		t.Fatalf("a day later: %+v / %+v", found, ch)
	}
	// Back.
	scans.eps = []tlsscan.Endpoint{e.served("ep_1", "www.homelab.lan", cert.Fingerprint, cert.NotAfter, 5)}
	found, ch = e.run(t)
	if len(byKind(found, KindScanUnreachable)) != 0 || len(only(ch.Resolved, KindScanUnreachable)) != 1 {
		t.Fatalf("recovered: %+v / %+v", found, ch)
	}
	// A refusal and a client certificate demand are no outage.
	for _, kind := range []string{tlsscan.KindRefusedDomain, tlsscan.KindRefusedPolicy, tlsscan.KindClientCert} {
		ep.FailStreak, ep.LastErrorKind = 50, kind
		scans.eps = []tlsscan.Endpoint{ep}
		if found, _ = e.run(t); len(byKind(found, KindScanUnreachable)) != 0 {
			t.Errorf("%s: %+v", kind, found)
		}
	}
}

func TestScanChain(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	cert := e.issue(t, 90, "www.homelab.lan")
	ep := e.served("ep_1", "www.homelab.lan", cert.Fingerprint, cert.NotAfter, 1)
	ep.ChainState, ep.ChainLen = tlsscan.ChainIncomplete, 1
	scans.eps = []tlsscan.Endpoint{ep}
	if found, _ := e.run(t); len(found) != 0 {
		t.Fatalf("seen once: %+v", found)
	}
	scans.eps[0].SameCount = 2
	found, ch := e.run(t)
	f := byKey(found, "scan_chain:ep_1")
	if f.Severity != Warning || !strings.Contains(f.Detail, "incomplete") || !strings.Contains(f.Detail, "fullchain.pem") || len(only(ch.Opened, KindScanChain)) != 1 {
		t.Fatalf("chain: %+v / %+v", f, ch)
	}
	scans.eps[0].ChainState = tlsscan.ChainUntrusted
	if found, _ = e.run(t); !strings.Contains(byKey(found, "scan_chain:ep_1").Detail, "does not lead to a CA of this PKI") {
		t.Fatalf("untrusted: %+v", found)
	}
	scans.eps[0].ChainState = tlsscan.ChainTrusted
	found, ch = e.run(t)
	if len(found) != 0 || len(only(ch.Resolved, KindScanChain)) != 1 {
		t.Fatalf("fixed: %+v / %+v", found, ch)
	}
}

// TestScanExpiry: the served certificate's end, but only when
// cert_expiry does not already say it.
func TestScanExpiry(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	alone := e.issue(t, 20, "alone.homelab.lan")
	oldCert := e.issue(t, 20, "www.homelab.lan")
	e.inst.Clock.Advance(time.Minute)
	e.issue(t, 90, "www.homelab.lan") // oldCert is superseded: it has no cert_expiry alert of its own
	e.inst.Clock.Advance(7 * day)     // 13 days left on both 20-day certificates
	scans.eps = []tlsscan.Endpoint{
		e.served("ep_alone", "alone.homelab.lan", alone.Fingerprint, alone.NotAfter, 5),
		e.served("ep_old", "www.homelab.lan", oldCert.Fingerprint, oldCert.NotAfter, 1),
	}
	found, _ := e.run(t)
	if len(byKind(found, KindCertExpiry)) != 1 || byKind(found, KindCertExpiry)[0].Key != "cert_expiry:"+alone.ID {
		t.Fatalf("cert_expiry: %+v", byKind(found, KindCertExpiry))
	}
	got := byKind(found, KindScanExpiry)
	if len(got) != 1 || got[0].Key != "scan_expiry:ep_old" || got[0].Severity != Warning || !strings.Contains(got[0].Detail, "a certificate of this PKI") || !strings.Contains(got[0].Detail, oldCert.Fingerprint) {
		t.Fatalf("scan_expiry: %+v", got)
	}
	e.inst.Clock.Advance(11 * day) // 2 days left
	found, ch := e.run(t)
	if f := byKey(found, "scan_expiry:ep_old"); f.Severity != Critical || len(only(ch.Raised, KindScanExpiry)) != 1 {
		t.Fatalf("critical: %+v / %+v", f, ch)
	}
	e.inst.Clock.Advance(3 * day) // ended
	found, _ = e.run(t)
	if f := byKey(found, "scan_expiry:ep_old"); f.Severity != Critical || !strings.Contains(f.Detail, "EXPIRED") {
		t.Fatalf("expired: %+v", f)
	}
}

// TestScanDeletedEndpointAndSwitchedOff: the alerts follow the endpoints.
func TestScanDeletedEndpointAndSwitchedOff(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	cert := e.issue(t, 90, "www.homelab.lan")
	ep := e.served("ep_1", "www.homelab.lan", cert.Fingerprint, cert.NotAfter, 5)
	ep.FailStreak, ep.LastErrorKind = 3, tlsscan.KindTimeout
	scans.eps = []tlsscan.Endpoint{ep}
	if _, ch := e.run(t); len(only(ch.Opened, KindScanUnreachable)) != 1 {
		t.Fatalf("not opened: %+v", ch)
	}
	scans.eps = nil // the endpoint is removed
	if found, ch := e.run(t); len(found) != 0 || len(only(ch.Resolved, KindScanUnreachable)) != 1 {
		t.Fatalf("deleted: %+v / %+v", found, ch)
	}
	scans.eps = []tlsscan.Endpoint{ep}
	e.run(t)
	e.eval.ScanOff = true // monitor.scan_interval: off
	if found, ch := e.run(t); len(byKind(found, KindScanUnreachable)) != 0 || len(only(ch.Resolved, KindScanUnreachable)) != 1 {
		t.Fatalf("scanning off: %+v / %+v", found, ch)
	}
	if st, err := e.eval.EndpointStates(t.Context(), e.inst.Clock.Now()); err != nil || len(st) != 1 || st[0].Assessment.State != tlsscan.StateUnreachable {
		t.Fatalf("the last known state is still shown: %+v, %v", st, err)
	}
}

// TestScanTextNeverCarriesWhatTheRemoteEndChose: subject, issuer and error
// text of the remote end are on the page, never in an alert (which travels to
// e-mail and webhooks).
func TestScanTextNeverCarriesWhatTheRemoteEndChose(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	e.issue(t, 90, "www.homelab.lan")
	e.inst.Clock.Advance(2 * time.Hour)
	const evil = "<script>alert(1)</script> SECRET-FROM-THE-REMOTE-END"
	hostile := e.served("ep_1", "www.homelab.lan", strings.Repeat("AB", 32), e.inst.Clock.Now().Add(2*day), 5)
	hostile.Subject, hostile.Issuer, hostile.LastError, hostile.TLSVersion = evil, evil, evil, evil
	failing := e.served("ep_2", "down.homelab.lan", "", time.Time{}, 0)
	failing.Fingerprint, failing.FailStreak, failing.LastErrorKind, failing.LastError = "", 40, tlsscan.KindTimeout, evil
	scans.eps = []tlsscan.Endpoint{hostile, failing}
	found, _ := e.run(t)
	if len(byKind(found, KindScanMismatch)) != 1 || len(byKind(found, KindScanExpiry)) != 1 || len(byKind(found, KindScanUnreachable)) != 1 {
		t.Fatalf("findings: %+v", found)
	}
	for _, f := range found {
		for _, text := range []string{f.Detail, f.Subject, f.Href, f.Key} {
			if strings.Contains(text, "script") || strings.Contains(text, "SECRET") {
				t.Errorf("%s carries the remote end's text: %q", f.Key, text)
			}
		}
	}
}

// TestScanDigest: one digest with a mismatch that opened and another alert
// that resolved in the same run.
func TestScanDigest(t *testing.T) {
	t.Parallel()
	e, scans := scanEnv(t)
	old := e.issue(t, 90, "www.homelab.lan")
	e.inst.Clock.Advance(time.Minute)
	renewed := e.issue(t, 90, "www.homelab.lan")
	e.inst.Clock.Advance(2 * time.Hour)
	down := e.served("ep_down", "down.homelab.lan", renewed.Fingerprint, renewed.NotAfter, 5)
	down.FailStreak, down.LastErrorKind = 3, tlsscan.KindTimeout
	scans.eps = []tlsscan.Endpoint{e.served("ep_www", "www.homelab.lan", renewed.Fingerprint, renewed.NotAfter, 5), down}
	opt := DigestOptions{Server: "pki01", RepeatEvery: 24 * time.Hour, Channels: []string{"webhook"}}
	digest := func() notify.Digest {
		t.Helper()
		e.run(t)
		d, err := e.store.Digest(t.Context(), e.inst.Clock.Now(), opt)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := digest(); len(d.Events) != 1 || d.Events[0].Kind != KindScanUnreachable || d.Events[0].State != notify.Opened {
		t.Fatalf("first digest: %+v", d.Events)
	}
	// Next run: the host is back, and another endpoint serves the old certificate.
	scans.eps = []tlsscan.Endpoint{
		e.served("ep_www", "www.homelab.lan", old.Fingerprint, old.NotAfter, 2),
		e.served("ep_down", "down.homelab.lan", renewed.Fingerprint, renewed.NotAfter, 6),
	}
	d := digest()
	if len(d.Events) != 2 {
		t.Fatalf("second digest: %+v", d.Events)
	}
	states := map[string]string{}
	for _, ev := range d.Events {
		states[ev.Kind] = ev.State
		if strings.Contains(ev.Detail, "CN=") {
			t.Errorf("a subject in the digest: %s", ev.Detail)
		}
	}
	if states[KindScanMismatch] != notify.Opened || states[KindScanUnreachable] != notify.Resolved {
		t.Errorf("states = %v", states)
	}
	// Nothing changed: no digest.
	if d = digest(); len(d.Events) != 0 {
		t.Errorf("third digest: %+v", d.Events)
	}
}
