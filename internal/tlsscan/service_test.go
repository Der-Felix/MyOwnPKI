package tlsscan

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func testSettings() Settings {
	return Settings{
		Interval: 15 * time.Minute, Timeout: 10 * time.Second, MaxEndpoints: 100,
		Ports: []int{443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443},
	}
}

type env struct {
	inst *testinstance.Instance
	svc  *Service
}

// newEnv is an unsealed instance with the domain homelab.lan (internal
// addresses, IP range 192.0.2.0/24) and pub.lan (public addresses only, IP
// range 10.1.0.0/16 – a misconfiguration the guard still catches).
func newEnv(t *testing.T) *env {
	t.Helper()
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	issuing := "issuing"
	public := ca.AddressPublic
	for _, d := range []ca.DomainRequest{
		{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing, IPRanges: []string{"192.0.2.0/24"}}, Who: testinstance.Console},
		{Name: "pub.lan", DomainSettings: ca.DomainSettings{CA: &issuing, AddressPolicy: &public, IPRanges: []string{"10.1.0.0/16"}}, Who: testinstance.Console},
	} {
		if _, err := inst.Engine.CreateDomain(t.Context(), d); err != nil {
			t.Fatal(err)
		}
	}
	return &env{inst: inst, svc: &Service{
		PKI: inst.PKIDB.Write, Tenant: "default", Engine: inst.Engine, Clock: inst.Clock, Settings: testSettings(),
	}}
}

func who(role authz.Role, caName string) keys.Who {
	return keys.Who{
		Actor:     audit.Actor{Type: audit.ActorUser, Name: string(role)},
		Principal: &authz.Principal{Kind: authz.KindUser, Username: string(role), Bindings: []authz.Binding{{Tenant: "default", CA: caName, Role: role}}},
	}
}

// auditList is the endpoint entries of the tenant audit log ("action/result").
func (e *env) auditList(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, a := range testinstance.Audit(t, e.inst.TenantAudit) {
		if strings.HasPrefix(a, "endpoint.") {
			out = append(out, a)
		}
	}
	return out
}

func (e *env) count(t *testing.T) int {
	t.Helper()
	list, err := e.svc.List(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

// TestCreateValidationTable is the validation table of docs/PHASE3.md
// §10.2: every refused input once, each naming the field and the rule, none
// stored, each audited as denied.
func TestCreateValidationTable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, tc := range []struct {
		name  string
		req   Request
		field string
	}{
		{"localhost", Request{Host: "localhost", Port: 443}, "host"},
		{"loopback", Request{Host: "127.0.0.1", Port: 443}, "host"},
		{"loopback in brackets", Request{Host: "[::1]", Port: 443}, "host"},
		{"loopback v6", Request{Host: "::1", Port: 443}, "host"},
		{"unspecified", Request{Host: "0.0.0.0", Port: 443}, "host"},
		{"metadata service", Request{Host: "169.254.169.254", Port: 443}, "host"},
		{"link-local with zone", Request{Host: "fe80::1%eth0", Port: 443}, "host"},
		{"mapped loopback", Request{Host: "::ffff:127.0.0.1", Port: 443}, "host"},
		{"multicast", Request{Host: "224.0.0.1", Port: 443}, "host"},
		{"reserved", Request{Host: "240.0.0.1", Port: 443}, "host"},
		{"space in the name", Request{Host: "a b", Port: 443}, "host"},
		{"wildcard", Request{Host: "*.homelab.lan", Port: 443}, "host"},
		{"leading hyphen", Request{Host: "-x.homelab.lan", Port: 443}, "host"},
		{"254 characters", Request{Host: strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".homelab.lan", Port: 443}, "host"},
		{"empty host", Request{Host: "", Port: 443}, "host"},
		{"only a space", Request{Host: "  ", Port: 443}, "host"},
		{"xn-- alone", Request{Host: "xn--.homelab.lan", Port: 443}, "host"},
		{"xn-- garbage", Request{Host: "xn--9.homelab.lan", Port: 443}, "host"},
		{"unicode", Request{Host: "b" + string(rune(0xfc)) + "cher.homelab.lan", Port: 443}, "host"},
		{"a URL", Request{Host: "http://proxy.homelab.lan", Port: 443}, "host"},
		{"host with a port", Request{Host: "proxy.homelab.lan:443", Port: 443}, "host"},
		{"a path", Request{Host: "proxy.homelab.lan/x", Port: 443}, "host"},
		{"control character", Request{Host: "proxy.home\alab.lan", Port: 443}, "host"},
		{"5000 characters", Request{Host: strings.Repeat("a", 5000), Port: 443}, "host"},
		{"a double dot", Request{Host: "proxy..homelab.lan", Port: 443}, "host"},
		{"two trailing dots", Request{Host: "proxy.homelab.lan..", Port: 443}, "host"},
		{"a host no domain covers", Request{Host: "proxy.example.net", Port: 443}, "host"},
		{"an IP no domain covers", Request{Host: "198.51.100.7", Port: 443}, "host"},
		{"a private IP under the policy public", Request{Host: "10.1.2.3", Port: 443}, "host"},
		{"port 0", Request{Host: "proxy.homelab.lan", Port: 0}, "port"},
		{"port 22", Request{Host: "proxy.homelab.lan", Port: 22}, "port"},
		{"port 80", Request{Host: "proxy.homelab.lan", Port: 80}, "port"},
		{"port 65536", Request{Host: "proxy.homelab.lan", Port: 65536}, "port"},
		{"port -1", Request{Host: "proxy.homelab.lan", Port: -1}, "port"},
		{"SNI that is no name", Request{Host: "proxy.homelab.lan", Port: 443, SNI: "a b"}, "sni"},
		{"SNI that is an IP", Request{Host: "192.0.2.10", Port: 443, SNI: "192.0.2.11"}, "sni"},
		{"SNI that is a wildcard", Request{Host: "proxy.homelab.lan", Port: 443, SNI: "*.homelab.lan"}, "sni"},
	} {
		before := e.count(t)
		auditBefore := len(e.auditList(t))
		_, err := e.svc.Create(t.Context(), testinstance.Console, tc.req)
		var ie *InvalidError
		if !errors.As(err, &ie) || !errors.Is(err, ErrInvalid) || ie.Field != tc.field || ie.Rule == "" {
			t.Errorf("%s: err = %v, want a refusal of %q", tc.name, err, tc.field)
			continue
		}
		if e.count(t) != before {
			t.Errorf("%s: an endpoint was stored", tc.name)
		}
		if got := e.auditList(t); len(got) != auditBefore+1 || got[len(got)-1] != "endpoint.create/denied" {
			t.Errorf("%s: audit = %v", tc.name, got)
		}
		// The refusal names the rule, not an address that was resolved.
		if strings.Contains(ie.Rule, "192.0.2.") && tc.req.Host != "192.0.2.10" {
			t.Errorf("%s: the rule names an address: %q", tc.name, ie.Rule)
		}
	}
	if got := e.count(t); got != 0 {
		t.Fatalf("%d endpoints stored by refused requests", got)
	}
}

func TestCreateAcceptsTheForms(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, tc := range []struct {
		req       Request
		host, sni string
	}{
		{Request{Host: "proxy.homelab.lan.", Port: 443}, "proxy.homelab.lan", ""},                          // the dot is trimmed
		{Request{Host: " Mail.HomeLab.LAN ", Port: 993}, "mail.homelab.lan", ""},                           // lower case, trimmed
		{Request{Host: "192.0.2.10", Port: 8443, SNI: "App.homelab.lan"}, "192.0.2.10", "app.homelab.lan"}, // an IP with a name
		{Request{Host: "::ffff:192.0.2.11", Port: 443}, "192.0.2.11", ""},                                  // unmapped
		{Request{Host: "xn--bcher-kva.homelab.lan", Port: 443}, "xn--bcher-kva.homelab.lan", ""},           // valid punycode
		{Request{Host: "same.homelab.lan", Port: 443, SNI: "same.homelab.lan"}, "same.homelab.lan", ""},    // SNI = host is no SNI
		{Request{Host: "sub.deep.homelab.lan", Port: 9443}, "sub.deep.homelab.lan", ""},                    // below the domain
		{Request{Host: "proxy.homelab.lan", Port: 8443, SNI: "alias.homelab.lan"}, "proxy.homelab.lan", "alias.homelab.lan"},
	} {
		ep, err := e.svc.Create(t.Context(), testinstance.Console, tc.req)
		if err != nil {
			t.Errorf("%+v: %v", tc.req, err)
			continue
		}
		if ep.Host != tc.host || ep.SNI != tc.sni || ep.Source != SourceManual || ep.Scanned() || !ep.NextScanAt.Equal(e.inst.Clock.Now().Truncate(time.Second)) {
			t.Errorf("%+v: stored %+v", tc.req, ep)
		}
		if !strings.HasPrefix(ep.ID, "ep_") {
			t.Errorf("id %q", ep.ID)
		}
	}
	// The audit log has one entry per endpoint.
	if got := e.auditList(t); len(got) != 0 {
		t.Errorf("direct audit entries for successes: %v", got) // successes go through the outbox
	}
	e.inst.Deliver(t)
	if got := e.auditList(t); len(got) != 8 || slices.ContainsFunc(got, func(s string) bool { return s != "endpoint.create/success" }) {
		t.Errorf("audit = %v", got)
	}
}

func TestCreateDuplicateAndLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	req := Request{Host: "proxy.homelab.lan", Port: 443}
	if _, err := e.svc.Create(t.Context(), testinstance.Console, req); err != nil {
		t.Fatal(err)
	}
	for _, dup := range []Request{req, {Host: "PROXY.homelab.lan.", Port: 443}, {Host: "proxy.homelab.lan", Port: 443, SNI: "proxy.homelab.lan"}} {
		if _, err := e.svc.Create(t.Context(), testinstance.Console, dup); !errors.Is(err, ErrConflict) {
			t.Errorf("duplicate %+v: %v", dup, err)
		}
	}
	// Another port, or another SNI on the same host and port, is another endpoint.
	for _, other := range []Request{{Host: "proxy.homelab.lan", Port: 8443}, {Host: "proxy.homelab.lan", Port: 443, SNI: "alias.homelab.lan"}} {
		if _, err := e.svc.Create(t.Context(), testinstance.Console, other); err != nil {
			t.Errorf("%+v: %v", other, err)
		}
	}
	// The 101st is refused with a conflict, the 100th is fine.
	for i := e.count(t); i < 100; i++ {
		if _, err := e.svc.Create(t.Context(), testinstance.Console, Request{Host: fmt.Sprintf("h%d.homelab.lan", i), Port: 443}); err != nil {
			t.Fatalf("endpoint %d: %v", i+1, err)
		}
	}
	_, err := e.svc.Create(t.Context(), testinstance.Console, Request{Host: "one-too-many.homelab.lan", Port: 443})
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "limit of 100") || e.count(t) != 100 {
		t.Fatalf("the 101st: %v (count %d)", err, e.count(t))
	}
	got := e.auditList(t)
	if got[len(got)-1] != "endpoint.create/failure" {
		t.Errorf("audit of the limit = %v", got[len(got)-3:])
	}
}

func TestPermissions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ep, err := e.svc.Create(t.Context(), testinstance.Console, Request{Host: "proxy.homelab.lan", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		who                       keys.Who
		list, create, del, scanOK bool
	}
	n := 0
	for name, tc := range map[string]row{
		"viewer":                   {who(authz.Viewer, ""), true, false, false, false},
		"operator":                 {who(authz.Operator, ""), true, false, false, true},
		"admin":                    {who(authz.Admin, ""), true, true, true, true},
		"admin of one CA only":     {who(authz.Admin, "issuing"), false, false, false, false},
		"operator of one CA only":  {who(authz.Operator, "issuing"), false, false, false, false},
		"nobody (no principal)":    {keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "x"}}, false, false, false, false},
		"the console":              {testinstance.Console, true, true, true, true},
		"the system (monitor job)": {keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "monitor"}, Principal: authz.System("monitor")}, true, true, true, true},
	} {
		// A fresh clock second per role: scan now is rate limited.
		e.inst.Clock.Advance(2 * ScanNowEvery)
		n++
		check := func(what string, got error, want bool) {
			t.Helper()
			if want && got != nil || !want && !errors.Is(got, authz.ErrDenied) {
				t.Errorf("%s / %s: err = %v, want allowed = %v", name, what, got, want)
			}
		}
		_, lerr := e.svc.List(t.Context(), tc.who)
		check("list", lerr, tc.list)
		_, gerr := e.svc.Get(t.Context(), tc.who, ep.ID)
		check("get", gerr, tc.list)
		_, cerr := e.svc.Create(t.Context(), tc.who, Request{Host: fmt.Sprintf("r%d.homelab.lan", n), Port: 443})
		check("create", cerr, tc.create)
		check("scan now", e.svc.ScanNow(t.Context(), tc.who, ep.ID), tc.scanOK)
		if tc.del {
			victim, err := e.svc.Create(t.Context(), testinstance.Console, Request{Host: fmt.Sprintf("victim%d.homelab.lan", n), Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			check("delete", e.svc.Delete(t.Context(), tc.who, victim.ID), true)
		} else {
			check("delete", e.svc.Delete(t.Context(), tc.who, ep.ID), false)
		}
	}
	if _, err := e.svc.Get(t.Context(), testinstance.Console, ep.ID); err != nil {
		t.Fatalf("the endpoint is gone: %v", err)
	}
	// The refusals are in the audit log.
	denied := 0
	for _, a := range e.auditList(t) {
		if strings.HasSuffix(a, "/denied") {
			denied++
		}
	}
	if denied < 10 {
		t.Errorf("only %d denied entries: %v", denied, e.auditList(t))
	}
}

func TestScanNowIsRateLimitedPerEndpointAndSurvivesARestart(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, _ := e.svc.Create(t.Context(), testinstance.Console, Request{Host: "a.homelab.lan", Port: 443})
	b, _ := e.svc.Create(t.Context(), testinstance.Console, Request{Host: "b.homelab.lan", Port: 443})
	op := who(authz.Operator, "")
	if err := e.svc.ScanNow(t.Context(), op, a.ID); err != nil {
		t.Fatal(err)
	}
	e.inst.Clock.Advance(59 * time.Second)
	// Another Service value over the same database: the limit is in the row.
	again := *e.svc
	err := again.ScanNow(t.Context(), op, a.ID)
	var wait *WaitError
	if !errors.As(err, &wait) || wait.RetryAfter != time.Second {
		t.Fatalf("after 59 seconds: %v", err)
	}
	if err := again.ScanNow(t.Context(), op, b.ID); err != nil {
		t.Fatalf("another endpoint: %v", err)
	}
	e.inst.Clock.Advance(time.Second)
	if err := again.ScanNow(t.Context(), op, a.ID); err != nil {
		t.Fatalf("after 60 seconds: %v", err)
	}
	if err := again.ScanNow(t.Context(), op, "ep_unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown endpoint: %v", err)
	}
	got, _ := again.Get(t.Context(), op, a.ID)
	if !got.NextScanAt.Equal(e.inst.Clock.Now().Truncate(time.Second)) || got.RequestedAt.IsZero() {
		t.Errorf("scan now did not make it due: %+v", got)
	}
	// A too-eager click is no audit event; the accepted ones are.
	e.inst.Deliver(t)
	if n := countAction(e.auditList(t), "endpoint.scan/success"); n != 3 {
		t.Errorf("audit = %v", e.auditList(t))
	}
	// Scanning off: scan now says so.
	again.Settings.Interval = 0
	if err := again.ScanNow(t.Context(), op, a.ID); !errors.Is(err, ErrOff) || !errors.Is(err, ErrConflict) {
		t.Errorf("scan off: %v", err)
	}
	// Kick runs after an accepted request only.
	var kicks int
	again.Settings.Interval = time.Minute
	again.Kick = func() { kicks++ }
	e.inst.Clock.Advance(time.Hour)
	if err := again.ScanNow(t.Context(), op, a.ID); err != nil || kicks != 1 {
		t.Fatalf("kick: %v, %d", err, kicks)
	}
	if err := again.ScanNow(t.Context(), op, a.ID); err == nil || kicks != 1 {
		t.Fatalf("a refused request kicked: %v, %d", err, kicks)
	}
}

func countAction(list []string, want string) int {
	n := 0
	for _, a := range list {
		if a == want {
			n++
		}
	}
	return n
}

func TestDelete(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, _ := e.svc.Create(t.Context(), testinstance.Console, Request{Host: "a.homelab.lan", Port: 443})
	admin := who(authz.Admin, "")
	if err := e.svc.Delete(t.Context(), admin, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(t.Context(), admin, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("twice: %v", err)
	}
	if _, err := e.svc.Get(t.Context(), admin, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get: %v", err)
	}
	e.inst.Deliver(t)
	got := e.auditList(t)
	if !slices.Equal(got, []string{"endpoint.create/success", "endpoint.delete/success"}) {
		t.Errorf("audit = %v", got)
	}
}

// TestAuditNeverCarriesJunkFromTheRequest: the host of a refused request is
// admin input; it is clipped and cleaned before it is logged.
func TestAuditDetailsOfARefusalAreClean(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, _ = e.svc.Create(t.Context(), testinstance.Console, Request{Host: "evil\x00\x1b[31m" + strings.Repeat("x", 600) + ".homelab.lan" + string(rune(0x202e)), Port: 443})
	var details string
	if err := e.inst.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT details_json FROM audit_entries WHERE action = 'endpoint.create'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if len(details) > 1200 || strings.ContainsAny(details, "\x1b"+string(rune(0x202e))) || strings.Contains(details, `\u0000`) {
		t.Errorf("details = %q", details)
	}
}

// hostileIDs are what a form post or a hand-made request can put in "id".
func hostileIDs() map[string]string {
	return map[string]string{
		"escape sequence": "ep_\x1b[31mred",
		"nul":             "ep_\x00x",
		"newline":         "ep_1\nendpoint.delete/success",
		"bidi override":   "ep_" + string(rune(0x202e)) + "1",
		"line separator":  "ep_" + string(rune(0x2028)) + "1",
		"over-long":       strings.Repeat("a", 300),
		"path":            "../../etc/passwd",
		"space":           "ep 1",
		"non-ASCII":       "ep_" + string(rune(0xe9)),
		"empty":           "",
		"invalid UTF-8":   "ep_\xff\xfe",
	}
}

type auditTarget struct{ typ, id, details string }

// endpointTargets reads the target and details of every endpoint entry
// directly from the tenant audit log (denied and failed entries are appended
// at once, without the outbox).
func (e *env) endpointTargets(t *testing.T) []auditTarget {
	t.Helper()
	rows, err := e.inst.TenantAudit.Read.QueryContext(t.Context(), `SELECT target_type, target_id, details_json FROM audit_entries WHERE action LIKE 'endpoint.%' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditTarget
	for rows.Next() {
		var a auditTarget
		if err := rows.Scan(&a.typ, &a.id, &a.details); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHostileIDsNeverBecomeAnAuditTarget: the endpoint ID of a UI form is
// attacker input. Whoever lacks the role gets the refusal (403 comes first)
// and the audit entry names no target ID that is not a well-formed ID; whoever
// has the role gets a plain "not found" and nothing is audited.
func TestHostileIDsNeverBecomeAnAuditTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	real, err := e.svc.Create(t.Context(), testinstance.Console, Request{Host: "a.homelab.lan", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	e.inst.Deliver(t)
	base := len(e.endpointTargets(t))
	viewer, operator, admin := who(authz.Viewer, ""), who(authz.Operator, ""), who(authz.Admin, "")
	wellFormed := regexp.MustCompile(`^[0-9A-Za-z_-]{0,64}$`)

	for name, id := range hostileIDs() {
		for action, call := range map[string]func(keys.Who) error{
			"delete": func(w keys.Who) error { return e.svc.Delete(t.Context(), w, id) },
			"scan":   func(w keys.Who) error { return e.svc.ScanNow(t.Context(), w, id) },
		} {
			// The role is checked first: 403 for everybody who lacks it.
			denied := []keys.Who{viewer}
			if action == "delete" {
				denied = append(denied, operator)
			}
			for _, w := range denied {
				if err := call(w); !errors.Is(err, authz.ErrDenied) {
					t.Errorf("%s/%s as %s: %v, want denied", action, name, w.Actor.Name, err)
				}
			}
			// With the role an invalid ID is simply unknown.
			if err := call(admin); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s/%s as admin: %v, want not found", action, name, err)
			}
		}
	}
	targets := e.endpointTargets(t)
	if len(targets) <= base {
		t.Fatalf("the refusals are not on record: %d entries", len(targets))
	}
	for _, a := range targets[base:] {
		if a.typ != "endpoint" || !wellFormed.MatchString(a.id) {
			t.Errorf("audit target %q %q is not a clean endpoint ID", a.typ, a.id)
		}
		if strings.ContainsAny(a.details, "\x1b"+string(rune(0x202e))+string(rune(0x2028))+string(rune(0xfffd))) || strings.Contains(a.details, `\u0000`) || strings.Contains(a.details, `\u001b`) || len(a.details) > 600 {
			t.Errorf("audit details are not clean: %q", a.details)
		}
	}
	// 6 refusals per hostile ID (viewer: delete, scan; operator: delete) are
	// all that was written; the admin's "not found" is no event.
	if want := len(hostileIDs()) * 3; len(targets)-base != want {
		t.Errorf("%d new audit entries, want %d", len(targets)-base, want)
	}

	// A refusal for a real ID keeps the ID: that is what the log is for.
	if err := e.svc.Delete(t.Context(), viewer, real.ID); !errors.Is(err, authz.ErrDenied) {
		t.Fatal(err)
	}
	last := e.endpointTargets(t)
	if got := last[len(last)-1]; got.id != real.ID {
		t.Errorf("target of a refusal for a real ID: %q, want %q", got.id, real.ID)
	}
}
