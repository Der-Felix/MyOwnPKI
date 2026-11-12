package httpapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// endpointDomain adds a domain (with IP ranges for IP endpoints):
// an endpoint's host must lie in a domain of the PKI.
func (v *env) endpointDomain(t *testing.T, name string, ipRanges ...string) {
	t.Helper()
	issuing := "issuing"
	if _, err := v.engine.CreateDomain(t.Context(), ca.DomainRequest{
		Name: name, DomainSettings: ca.DomainSettings{CA: &issuing, IPRanges: ipRanges}, Who: testinstance.Console,
	}); err != nil {
		t.Fatal(err)
	}
}

// endpointAudit counts the endpoint entries of the tenant audit log by
// "action/result", after the outbox was delivered.
func (v *env) endpointAudit(t *testing.T) map[string]int {
	t.Helper()
	v.deliver(t)
	out := map[string]int{}
	for _, e := range v.audit(t, v.ta) {
		if strings.HasPrefix(e, "endpoint.") {
			out[e]++
		}
	}
	return out
}

func endpointList(t *testing.T, r *resp) []map[string]any {
	t.Helper()
	var list []map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil {
		t.Fatalf("no endpoint list (%d): %s", r.Code, r.Body.String())
	}
	return list
}

// endpointID adds an endpoint as admin and returns its ID.
func endpointID(t *testing.T, admin *client, host string, port int) string {
	t.Helper()
	r := admin.do(t, http.MethodPost, "/endpoints", map[string]any{"host": host, "port": port})
	id, _ := r.body["id"].(string)
	if r.Code != http.StatusCreated || !strings.HasPrefix(id, "ep_") {
		t.Fatalf("add %s:%d: %d %s", host, port, r.Code, r.Body.String())
	}
	return id
}

// serve records what a scan found, as the scanner would: the served leaf with
// this fingerprint, subject and end, seen twice, chain trusted.
func (v *env) serve(t *testing.T, id, fingerprint, subject, issuer string, notAfter time.Time) {
	t.Helper()
	now := v.clk.Now().UTC().Format("2006-01-02T15:04:05Z")
	_, err := v.in.PKIDB.Write.ExecContext(t.Context(), `UPDATE endpoints SET last_scan_at = ?, last_ok_at = ?, fail_streak = 0,
		last_error_kind = NULL, last_error = NULL, fingerprint = ?, serial = 'ABCD', subject = ?, issuer = ?, not_before = ?, not_after = ?,
		chain_len = 2, chain_state = 'trusted', tls_version = 'TLS 1.3', same_count = 2, fingerprint_since = ? WHERE id = ?`,
		now, now, fingerprint, subject, issuer, v.clk.Now().Add(-24*time.Hour).UTC().Format("2006-01-02T15:04:05Z"),
		notAfter.UTC().Format("2006-01-02T15:04:05Z"), now, id)
	if err != nil {
		t.Fatal(err)
	}
}

// TestEndpointRoles: a viewer and an operator read, an operator scans, only
// an admin adds and removes; a role limited to one CA and a user without a
// role are refused everywhere; created_by is for admins only; every
// refusal is on record exactly once (the service writes it, the handler does
// not).
func TestEndpointRoles(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin, viewer, operator, caAdmin, nobody, anon := alertClients(t, v)

	r := admin.do(t, http.MethodPost, "/endpoints", map[string]any{"host": "proxy.homelab.lan", "port": 443})
	if r.Code != http.StatusCreated {
		t.Fatalf("admin add: %d %s", r.Code, r.Body.String())
	}
	id, _ := r.body["id"].(string)
	for field, want := range map[string]any{
		"host": "proxy.homelab.lan", "port": float64(443), "sni": nil, "name": "proxy.homelab.lan", "source": "manual", "state": "pending",
		"expiry_severity": nil, "last_scan_at": nil, "last_ok_at": nil, "fail_streak": float64(0), "last_error_kind": nil, "served": nil,
		"created_by": "demo",
	} {
		if got := r.body[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	if len(r.body) != 16 {
		t.Errorf("fields: %v", r.body)
	}

	// Reading: viewer, operator and admin; created_by only for the admin.
	for name, c := range map[string]*client{"viewer": viewer, "operator": operator, "admin": admin} {
		list := endpointList(t, c.do(t, http.MethodGet, "/endpoints", nil))
		if len(list) != 1 || list[0]["id"] != id {
			t.Fatalf("%s: %v", name, list)
		}
		_, has := list[0]["created_by"]
		if has != (name == "admin") {
			t.Errorf("%s: created_by present = %v", name, has)
		}
	}
	for name, c := range map[string]*client{"caadmin": caAdmin, "nobody": nobody} {
		if r := c.do(t, http.MethodGet, "/endpoints", nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
			t.Errorf("%s list: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := anon.do(t, http.MethodGet, "/endpoints", nil); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list: %d", r.Code)
	}

	// Adding and removing: admin only.
	add := map[string]any{"host": "other.homelab.lan", "port": 443}
	for name, c := range map[string]*client{"viewer": viewer, "operator": operator, "caadmin": caAdmin, "nobody": nobody} {
		if r := c.do(t, http.MethodPost, "/endpoints", add); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
			t.Errorf("%s add: %d %s", name, r.Code, r.Body.String())
		}
		if r := c.do(t, http.MethodDelete, "/endpoints/"+id, nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
			t.Errorf("%s delete: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := anon.do(t, http.MethodPost, "/endpoints", add); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous add: %d", r.Code)
	}
	if got := len(endpointList(t, admin.do(t, http.MethodGet, "/endpoints", nil))); got != 1 {
		t.Fatalf("%d endpoints after the refusals", got)
	}

	// Scanning: operator and admin, not the others.
	for name, c := range map[string]*client{"viewer": viewer, "caadmin": caAdmin, "nobody": nobody} {
		if r := c.do(t, http.MethodPost, "/endpoints/"+id+"/scan", nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
			t.Errorf("%s scan: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := operator.do(t, http.MethodPost, "/endpoints/"+id+"/scan", nil); r.Code != http.StatusAccepted || r.Body.Len() != 0 {
		t.Errorf("operator scan: %d %s", r.Code, r.Body.String())
	}

	// The audit log: create once, the refusals once each, the scan once.
	want := map[string]int{
		"endpoint.create/success": 1, "endpoint.create/denied": 4, "endpoint.delete/denied": 4,
		"endpoint.scan/denied": 3, "endpoint.scan/success": 1,
	}
	got := v.endpointAudit(t)
	for k, n := range want {
		if got[k] != n {
			t.Errorf("audit %s = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("audit: %v", got)
	}
}

// TestEndpointCreateValidation is the validation table of docs/PHASE3.md
// §10.2: every refusal is a 422 that names the field and the rule, never
// echoes the input, is not stored and is on record as denied.
func TestEndpointCreateValidation(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)

	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".homelab.lan"
	refused := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{"localhost", map[string]any{"host": "localhost", "port": 443}, "/host"},
		{"loopback", map[string]any{"host": "127.0.0.1", "port": 443}, "/host"},
		{"loopback in brackets", map[string]any{"host": "[::1]", "port": 443}, "/host"},
		{"unspecified", map[string]any{"host": "0.0.0.0", "port": 443}, "/host"},
		{"metadata service", map[string]any{"host": "169.254.169.254", "port": 443}, "/host"},
		{"link-local with a zone", map[string]any{"host": "fe80::1%eth0", "port": 443}, "/host"},
		{"mapped loopback", map[string]any{"host": "::ffff:127.0.0.1", "port": 443}, "/host"},
		{"IPv4-compatible loopback", map[string]any{"host": "::7f00:1", "port": 443}, "/host"},
		{"NAT64 loopback", map[string]any{"host": "64:ff9b::7f00:1", "port": 443}, "/host"},
		{"6to4 loopback", map[string]any{"host": "2002:7f00:1::", "port": 443}, "/host"},
		{"a space", map[string]any{"host": "a b", "port": 443}, "/host"},
		{"a wildcard", map[string]any{"host": "*.homelab.lan", "port": 443}, "/host"},
		{"a leading hyphen", map[string]any{"host": "-x.homelab.lan", "port": 443}, "/host"},
		{"254 characters", map[string]any{"host": long, "port": 443}, "/host"},
		{"an empty host", map[string]any{"host": "", "port": 443}, "/host"},
		{"no host at all", map[string]any{"port": 443}, "/host"},
		{"xn-- garbage", map[string]any{"host": "xn--9.homelab.lan", "port": 443}, "/host"},
		{"a URL", map[string]any{"host": "http://proxy.homelab.lan", "port": 443}, "/host"},
		{"markup", map[string]any{"host": "<script>alert(1)</script>.homelab.lan", "port": 443}, "/host"},
		{"no domain covers it", map[string]any{"host": "proxy.example.net", "port": 443}, "/host"},
		{"an IP no domain covers", map[string]any{"host": "198.51.100.7", "port": 443}, "/host"},
		{"port 0", map[string]any{"host": "proxy.homelab.lan", "port": 0}, "/port"},
		{"no port at all", map[string]any{"host": "proxy.homelab.lan"}, "/port"},
		{"port 22", map[string]any{"host": "proxy.homelab.lan", "port": 22}, "/port"},
		{"port 80", map[string]any{"host": "proxy.homelab.lan", "port": 80}, "/port"},
		{"port 65536", map[string]any{"host": "proxy.homelab.lan", "port": 65536}, "/port"},
		{"port -1", map[string]any{"host": "proxy.homelab.lan", "port": -1}, "/port"},
		{"an SNI that is an IP", map[string]any{"host": "192.0.2.10", "port": 443, "sni": "192.0.2.11"}, "/sni"},
		{"an SNI with markup", map[string]any{"host": "proxy.homelab.lan", "port": 443, "sni": "<b>x</b>.homelab.lan"}, "/sni"},
	}
	for _, tc := range refused {
		r := admin.do(t, http.MethodPost, "/endpoints", tc.body)
		if r.Code != http.StatusUnprocessableEntity || r.problemType() != "policy-violation" {
			t.Errorf("%s: %d %s", tc.name, r.Code, r.Body.String())
			continue
		}
		errs, _ := r.body["errors"].([]any)
		first, _ := errs[0].(map[string]any)
		if len(errs) != 1 || first["field"] != tc.field || first["message"] == "" {
			t.Errorf("%s: errors %v, want field %s", tc.name, errs, tc.field)
		}
		if strings.Contains(r.Body.String(), "script") || strings.Contains(r.Body.String(), "<b>") {
			t.Errorf("%s: the answer echoes the input: %s", tc.name, r.Body.String())
		}
	}
	if got := len(endpointList(t, admin.do(t, http.MethodGet, "/endpoints", nil))); got != 0 {
		t.Fatalf("%d endpoints stored after the refusals", got)
	}
	if got := v.endpointAudit(t); got["endpoint.create/denied"] != len(refused) || len(got) != 1 {
		t.Errorf("audit: %v, want %d denied", got, len(refused))
	}

	// A trailing dot and upper case are cleaned; an IP in the domain's range works.
	r := admin.do(t, http.MethodPost, "/endpoints", map[string]any{"host": "Proxy.Homelab.LAN.", "port": 443})
	if r.Code != http.StatusCreated || r.body["host"] != "proxy.homelab.lan" {
		t.Errorf("trailing dot: %d %s", r.Code, r.Body.String())
	}
	r = admin.do(t, http.MethodPost, "/endpoints", map[string]any{"host": "192.0.2.10", "port": 8443, "sni": "web.homelab.lan"})
	if r.Code != http.StatusCreated || r.body["sni"] != "web.homelab.lan" || r.body["name"] != "web.homelab.lan" {
		t.Errorf("IP with an SNI: %d %s", r.Code, r.Body.String())
	}

	// A duplicate, and the limit.
	if r := admin.do(t, http.MethodPost, "/endpoints", map[string]any{"host": "proxy.homelab.lan", "port": 443}); r.Code != http.StatusConflict || r.problemType() != "conflict" ||
		!strings.Contains(r.Body.String(), "entered already") || strings.Contains(r.Body.String(), "conflict:") {
		t.Errorf("duplicate: %d %s", r.Code, r.Body.String())
	}
	v.scan.Settings.MaxEndpoints = 2
	if r := admin.do(t, http.MethodPost, "/endpoints", map[string]any{"host": "third.homelab.lan", "port": 443}); r.Code != http.StatusConflict ||
		!strings.Contains(r.Body.String(), "monitor.scan_max_endpoints") {
		t.Errorf("limit: %d %s", r.Code, r.Body.String())
	}
}

// TestEndpointCreateBody: the body rules of the API, with the 4 KiB limit of
// this operation named in the answer.
func TestEndpointCreateBody(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)

	big := `{"host":"proxy.homelab.lan","port":443,"sni":"` + strings.Repeat("a", 5000) + `"}`
	if r := admin.do(t, http.MethodPost, "/endpoints", big, "Content-Type", "application/json"); r.Code != http.StatusRequestEntityTooLarge || r.problemType() != "too-large" ||
		!strings.Contains(r.Body.String(), "larger than 4 KiB") {
		t.Errorf("5 KiB body: %d %s", r.Code, r.Body.String())
	}
	for name, tc := range map[string]struct {
		body any
		want int
		kind string
	}{
		"a port as text":     {map[string]any{"host": "proxy.homelab.lan", "port": "443"}, 400, "bad-request"},
		"a fractional port":  {map[string]any{"host": "proxy.homelab.lan", "port": 443.5}, 400, "bad-request"},
		"an unknown field":   {map[string]any{"host": "proxy.homelab.lan", "port": 443, "source": "agent"}, 400, "bad-request"},
		"an empty object":    {map[string]any{}, 422, "policy-violation"},
		"not JSON":           {"host=proxy.homelab.lan", 415, "unsupported-media-type"},
		"trailing data":      {`{"host":"proxy.homelab.lan","port":443} {}`, 400, "bad-request"},
		"an array":           {`[]`, 400, "bad-request"},
		"a host as a number": {map[string]any{"host": 12, "port": 443}, 400, "bad-request"},
	} {
		var header []string
		if s, ok := tc.body.(string); ok && strings.HasPrefix(s, "{") || ok && s == "[]" {
			header = []string{"Content-Type", "application/json"}
		}
		if r := admin.do(t, http.MethodPost, "/endpoints", tc.body, header...); r.Code != tc.want || r.problemType() != tc.kind {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	// Refused before the service: nothing to audit but the empty object.
	if got := v.endpointAudit(t); got["endpoint.create/denied"] != 1 || len(got) != 1 {
		t.Errorf("audit: %v", got)
	}
}

// TestScanEndpointNow: once per endpoint and 60 seconds (429 with
// Retry-After), the wait is no audit event, an unknown endpoint is a 404,
// switched-off scanning a 409, and the endpoint becomes due.
func TestScanEndpointNow(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin, _, operator, _, _, _ := alertClients(t, v)
	id := endpointID(t, admin, "proxy.homelab.lan", 443)
	other := endpointID(t, admin, "web.homelab.lan", 443)
	// The endpoint was entered a while ago; its next scan is far away.
	if _, err := v.in.PKIDB.Write.ExecContext(t.Context(), `UPDATE endpoints SET next_scan_at = '2099-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}

	if r := operator.do(t, http.MethodPost, "/endpoints/"+id+"/scan", nil); r.Code != http.StatusAccepted {
		t.Fatalf("first scan: %d %s", r.Code, r.Body.String())
	}
	due := func(want string) {
		t.Helper()
		list := endpointList(t, admin.do(t, http.MethodGet, "/endpoints", nil))
		for _, e := range list {
			if e["id"] == id && e["next_scan_at"] != want {
				t.Errorf("next_scan_at = %v, want %s", e["next_scan_at"], want)
			}
		}
	}
	due(v.clk.Now().UTC().Format(time.RFC3339))

	// Again at once: 429 with the seconds to wait, from any role; the other endpoint is not affected.
	for name, c := range map[string]*client{"operator": operator, "admin": admin} {
		r := c.do(t, http.MethodPost, "/endpoints/"+id+"/scan", nil)
		secs, _ := strconv.Atoi(r.Header().Get("Retry-After"))
		if r.Code != http.StatusTooManyRequests || r.problemType() != "rate-limited" || secs < 1 || secs > 60 {
			t.Errorf("%s again: %d, Retry-After %q, %s", name, r.Code, r.Header().Get("Retry-After"), r.Body.String())
		}
	}
	if r := operator.do(t, http.MethodPost, "/endpoints/"+other+"/scan", nil); r.Code != http.StatusAccepted {
		t.Errorf("other endpoint: %d %s", r.Code, r.Body.String())
	}
	v.clk.Advance(61 * time.Second)
	if r := operator.do(t, http.MethodPost, "/endpoints/"+id+"/scan", nil); r.Code != http.StatusAccepted {
		t.Errorf("after 60 seconds: %d %s", r.Code, r.Body.String())
	}

	// Unknown endpoints: 404, not audited.
	if r := operator.do(t, http.MethodPost, "/endpoints/ep_unknown/scan", nil); r.Code != http.StatusNotFound || r.problemType() != "not-found" {
		t.Errorf("unknown: %d %s", r.Code, r.Body.String())
	}
	if r := operator.do(t, http.MethodPost, "/endpoints/bad%20id/scan", nil); r.Code != http.StatusNotFound {
		t.Errorf("malformed ID: %d", r.Code)
	}

	// Scanning switched off: nothing to ask for.
	v.scan.Settings.Interval = 0
	v.clk.Advance(2 * time.Minute)
	if r := operator.do(t, http.MethodPost, "/endpoints/"+id+"/scan", nil); r.Code != http.StatusConflict || r.problemType() != "conflict" ||
		!strings.Contains(r.Body.String(), "monitor.scan_interval") {
		t.Errorf("off: %d %s", r.Code, r.Body.String())
	}
	// Adding and removing work with scanning off.
	if _, ok := endpointList(t, admin.do(t, http.MethodGet, "/endpoints", nil))[0]["id"].(string); !ok {
		t.Error("the list is unreadable while scanning is off")
	}

	// The audit log: the 3 scans that were accepted, the one refused while off;
	// the waits and the unknown endpoint are no events.
	got := v.endpointAudit(t)
	if got["endpoint.scan/success"] != 3 || got["endpoint.scan/failure"] != 1 || got["endpoint.create/success"] != 2 || len(got) != 3 {
		t.Errorf("audit: %v", got)
	}
}

// TestDeleteEndpoint: an admin removes it, the second try is a 404, the list
// is empty, the removal is audited once.
func TestDeleteEndpoint(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin, _, _, _, _, _ := alertClients(t, v)
	id := endpointID(t, admin, "proxy.homelab.lan", 443)
	if r := admin.do(t, http.MethodDelete, "/endpoints/"+id, nil); r.Code != http.StatusNoContent || r.Body.Len() != 0 {
		t.Fatalf("delete: %d %s", r.Code, r.Body.String())
	}
	if r := admin.do(t, http.MethodDelete, "/endpoints/"+id, nil); r.Code != http.StatusNotFound || r.problemType() != "not-found" {
		t.Errorf("second delete: %d %s", r.Code, r.Body.String())
	}
	if got := len(endpointList(t, admin.do(t, http.MethodGet, "/endpoints", nil))); got != 0 {
		t.Errorf("%d endpoints left", got)
	}
	if got := v.endpointAudit(t); got["endpoint.delete/success"] != 1 || got["endpoint.create/success"] != 1 || len(got) != 2 {
		t.Errorf("audit: %v", got)
	}
}

// TestEndpointServedCertificate: the list shows what the endpoint served and
// the state the alerts follow; a hostile subject is a plain JSON string; an
// API token of an admin works for every operation, a viewer's for reading.
func TestEndpointServedCertificate(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin, viewer, _, _, _, _ := alertClients(t, v)

	issued, err := v.engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"proxy.homelab.lan"}, ValidityDays: 90, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	okID := endpointID(t, admin, "proxy.homelab.lan", 443)
	v.clk.Advance(time.Minute)
	v.serve(t, okID, issued.Fingerprint, "CN=proxy.homelab.lan", "CN=Issuing CA", issued.NotAfter)

	find := func(c *client, id string) map[string]any {
		t.Helper()
		for _, e := range endpointList(t, c.do(t, http.MethodGet, "/endpoints", nil)) {
			if e["id"] == id {
				return e
			}
		}
		t.Fatalf("endpoint %s not listed", id)
		return nil
	}
	e := find(viewer, okID)
	served, _ := e["served"].(map[string]any)
	if e["state"] != "ok" || e["expiry_severity"] != nil || served["fingerprint"] != issued.Fingerprint || served["certificate_id"] != issued.ID ||
		served["chain_state"] != "trusted" || served["tls_version"] != "TLS 1.3" || served["seen_count"] != float64(2) || served["subject"] != "CN=proxy.homelab.lan" {
		t.Errorf("served: state %v, %v", e["state"], served)
	}

	// A foreign certificate that ends in 2 days, with a hostile subject and issuer.
	hostile := `<script>alert("x")</script>`
	foreignID := endpointID(t, admin, "web.homelab.lan", 443)
	v.serve(t, foreignID, strings.Repeat("AB", 32), hostile, hostile, v.clk.Now().Add(48*time.Hour))
	r := viewer.do(t, http.MethodGet, "/endpoints", nil)
	if strings.Contains(r.Body.String(), "<script>") {
		t.Errorf("markup left unescaped in the JSON: %s", r.Body.String())
	}
	e = find(viewer, foreignID)
	served, _ = e["served"].(map[string]any)
	if served["subject"] != hostile || served["certificate_id"] != nil || e["expiry_severity"] != "critical" || e["state"] == "ok" {
		t.Errorf("hostile endpoint: state %v, severity %v, served %v", e["state"], e["expiry_severity"], served)
	}

	// Failing scans: the last good data stays, the error kind is from the fixed vocabulary.
	failID := endpointID(t, admin, "nas.homelab.lan", 443)
	_, err = v.in.PKIDB.Write.ExecContext(t.Context(), `UPDATE endpoints SET last_scan_at = '2026-01-01T00:00:00Z', fail_streak = 3, last_error_kind = 'timed out', last_error = 'timed out' WHERE id = ?`, failID)
	if err != nil {
		t.Fatal(err)
	}
	e = find(viewer, failID)
	if e["state"] != "unreachable" || e["last_error_kind"] != "timed out" || e["fail_streak"] != float64(3) || e["served"] != nil {
		t.Errorf("unreachable endpoint: %v", e)
	}

	// API tokens: an admin's token adds and removes, a viewer's token reads only.
	admin.stepUp(t, "demo")
	tok := admin.do(t, http.MethodPost, "/tokens", map[string]any{"name": "endpoints", "expires_at": v.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"roles": []map[string]any{{"role": "admin", "scope": map[string]string{"type": "tenant"}}}})
	secret, _ := tok.body["secret"].(string)
	if tok.Code != http.StatusCreated || secret == "" {
		t.Fatalf("token: %d %s", tok.Code, tok.Body.String())
	}
	bot := v.client("192.0.2.77")
	bearer := []string{"Authorization", "Bearer " + secret}
	r = bot.do(t, http.MethodPost, "/endpoints", map[string]any{"host": "token.homelab.lan", "port": 443}, bearer...)
	tokenID, _ := r.body["id"].(string)
	if r.Code != http.StatusCreated || r.body["created_by"] == nil {
		t.Fatalf("token add: %d %s", r.Code, r.Body.String())
	}
	if r := bot.do(t, http.MethodPost, "/endpoints/"+tokenID+"/scan", nil, bearer...); r.Code != http.StatusAccepted {
		t.Errorf("token scan: %d %s", r.Code, r.Body.String())
	}
	if r := bot.do(t, http.MethodDelete, "/endpoints/"+tokenID, nil, bearer...); r.Code != http.StatusNoContent {
		t.Errorf("token delete: %d %s", r.Code, r.Body.String())
	}
	if !slices.ContainsFunc(endpointList(t, bot.do(t, http.MethodGet, "/endpoints", nil, bearer...)), func(m map[string]any) bool { return m["id"] == okID }) {
		t.Error("the token cannot read")
	}
}

// TestEndpointListNeedsTheTenantWideRole: the permission covers the whole tenant, so
// a user limited to one CA gets nothing, not even the empty list.
func TestEndpointListNeedsTheTenantWideRole(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	v.user(t, "rootview", false, authz.Binding{CA: "root", Role: authz.Viewer})
	c := v.client("192.0.2.3")
	c.signIn(t, "rootview", testPassword)
	if r := c.do(t, http.MethodGet, "/endpoints", nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
		t.Errorf("CA-limited viewer: %d %s", r.Code, r.Body.String())
	}
}

// TestEndpointMalformedIDChecksTheRoleFirst: a path ID that is not well-formed
// is an unknown endpoint for whoever may remove or scan, but the role comes
// first - a viewer is told 403, as for any other operation, not 404.
func TestEndpointMalformedIDChecksTheRoleFirst(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.endpointDomain(t, "homelab.lan", "192.0.2.0/24")
	admin, viewer, operator, caAdmin, nobody, anon := alertClients(t, v)
	_ = endpointID(t, admin, "proxy.homelab.lan", 443) // one endpoint that must survive
	for name, bad := range map[string]string{
		"a space": "a%20b", "a dot": "x.y", "over-long": strings.Repeat("a", 65), "control": "ep_%1b%5b31m", "bidi": "ep_%e2%80%ae1",
	} {
		for op, tc := range map[string]struct {
			method, suffix string
			denied         map[string]*client
		}{
			"delete": {http.MethodDelete, "", map[string]*client{"viewer": viewer, "operator": operator, "caadmin": caAdmin, "nobody": nobody}},
			"scan":   {http.MethodPost, "/scan", map[string]*client{"viewer": viewer, "caadmin": caAdmin, "nobody": nobody}},
		} {
			for who, c := range tc.denied {
				if r := c.do(t, tc.method, "/endpoints/"+bad+tc.suffix, nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
					t.Errorf("%s %s as %s: %d %s, want 403", op, name, who, r.Code, r.Body.String())
				}
			}
			if r := admin.do(t, tc.method, "/endpoints/"+bad+tc.suffix, nil); r.Code != http.StatusNotFound || r.problemType() != "not-found" {
				t.Errorf("%s %s as admin: %d %s, want 404", op, name, r.Code, r.Body.String())
			}
			if r := anon.do(t, tc.method, "/endpoints/"+bad+tc.suffix, nil); r.Code != http.StatusUnauthorized {
				t.Errorf("%s %s anonymous: %d, want 401", op, name, r.Code)
			}
		}
	}
	if got := len(endpointList(t, admin.do(t, http.MethodGet, "/endpoints", nil))); got != 1 {
		t.Errorf("%d endpoints left, want the one", got)
	}
}
