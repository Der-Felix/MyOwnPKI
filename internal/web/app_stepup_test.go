package web

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

var rePendingID = regexp.MustCompile(`name="pending_id" value="([^"]+)"`)

func pendingID(t *testing.T, b *browser) string {
	t.Helper()
	r := b.get(t, "/step-up")
	if r.Code != http.StatusOK {
		t.Fatalf("pending page: %d %s", r.Code, r.html())
	}
	match := rePendingID.FindStringSubmatch(r.html())
	if match == nil {
		t.Fatalf("no pending ID in the POST form: %s", r.html())
	}
	return match[1]
}

func confirmPending(t *testing.T, b *browser, csrf, username string) page {
	t.Helper()
	id := pendingID(t, b)
	b.v.Clock.Advance(30 * time.Second)
	return b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {b.v.Code(username)}})
}

func stepUpCertificate(t *testing.T, v *uiEnv, commonName string) *ca.Issued {
	t.Helper()
	issued, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{commonName}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func beginRevoke(t *testing.T, b *browser, id, csrf, reason string) page {
	t.Helper()
	b.v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, "/certificates/"+id+"/revoke", url.Values{"csrf_token": {csrf}, "reason": {reason}, "confirm": {"yes"}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("begin revocation: %d %q %s", r.Code, r.location(), r.html())
	}
	return r
}

func certificateStatus(t *testing.T, v *uiEnv, id string) string {
	t.Helper()
	info, err := v.Engine.Certificate(t.Context(), testinstance.Console, id)
	if err != nil {
		t.Fatal(err)
	}
	return info.Status
}

func TestStepUpContinuesRevocationOnce(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	issued := stepUpCertificate(t, v, "once.homelab.lan")
	beginRevoke(t, b, issued.ID, csrf, "superseded")

	challenge := b.get(t, "/step-up")
	id := rePendingID.FindStringSubmatch(challenge.html())[1]
	if !strings.Contains(challenge.html(), "Revoke certificate once.homelab.lan (serial "+issued.SerialHex+"); reason superseded") {
		t.Errorf("action summary: %s", challenge.html())
	}
	if strings.Count(challenge.html(), id) != 1 || !strings.Contains(challenge.html(), `type="hidden" name="pending_id" value="`+id+`"`) {
		t.Errorf("pending ID is not confined to the POST field: %s", challenge.html())
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(decoded) != 32 {
		t.Errorf("pending ID is not 256 random bits: %x %v", decoded, err)
	}
	if wrong := b.post(t, "/step-up", url.Values{"csrf_token": {"wrong"}, "pending_id": {id}, "code": {v.Code("demo")}}); wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF: %d", wrong.Code)
	}
	if pendingID(t, b) != id {
		t.Fatal("wrong CSRF consumed the action")
	}

	r := confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusSeeOther || r.location() != "/certificates/"+issued.ID {
		t.Fatalf("continued revocation: %d %q %s", r.Code, r.location(), r.html())
	}
	if got := certificateStatus(t, v, issued.ID); got != ca.CertRevoked {
		t.Fatalf("certificate status %q", got)
	}
	replay := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {v.Code("demo")}})
	if replay.Code != http.StatusBadRequest || replay.location() != "" {
		t.Errorf("replay: %d %q", replay.Code, replay.location())
	}
	if strings.Contains(replay.location(), id) || strings.Contains(v.logs.String(), id) {
		t.Error("pending ID appeared in a URL or log")
	}
	v.Deliver(t)
	count := 0
	for _, entry := range testinstance.Audit(t, v.TenantAudit) {
		if entry == "certificate.revoke/success" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("business audit entries: %d", count)
	}
}

func TestStepUpBindingExpiryAndRestart(t *testing.T) {
	t.Run("foreign session of the same user", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		first := v.browser("192.0.2.1")
		first.signIn(t, "demo", v.DemoPassword)
		csrf := first.csrf(t)
		issued := stepUpCertificate(t, v, "foreign.homelab.lan")
		beginRevoke(t, first, issued.ID, csrf, "superseded")
		id := pendingID(t, first)
		other := v.browser("192.0.2.2")
		other.signIn(t, "demo", v.DemoPassword)
		otherCSRF := other.csrf(t)
		r := other.post(t, "/step-up", url.Values{"csrf_token": {otherCSRF}, "pending_id": {id}, "code": {v.Code("demo")}})
		if r.Code != http.StatusBadRequest || certificateStatus(t, v, issued.ID) != ca.CertValid {
			t.Fatalf("foreign continuation: %d status %q", r.Code, certificateStatus(t, v, issued.ID))
		}
		if r := confirmPending(t, first, csrf, "demo"); r.Code != http.StatusSeeOther {
			t.Fatalf("original session could not continue: %d", r.Code)
		}
	})

	t.Run("credentials epoch", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		issued := stepUpCertificate(t, v, "epoch.homelab.lan")
		beginRevoke(t, b, issued.ID, csrf, "superseded")
		id := pendingID(t, b)
		if _, err := v.SystemDB.Write.ExecContext(t.Context(), `UPDATE users SET credentials_epoch = credentials_epoch + 1 WHERE username = 'demo'`); err != nil {
			t.Fatal(err)
		}
		v.Clock.Advance(30 * time.Second)
		r := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {v.Code("demo")}})
		if r.Code != http.StatusBadRequest || certificateStatus(t, v, issued.ID) != ca.CertValid {
			t.Fatalf("epoch continuation: %d status %q", r.Code, certificateStatus(t, v, issued.ID))
		}
	})

	t.Run("five minute expiry with sixty minute proofs", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		settings := &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}
		current, err := settings.Get(t.Context(), store.DefaultTenant, testinstance.Console)
		if err != nil {
			t.Fatal(err)
		}
		sixty := 60
		current.StepUpMinutes = &sixty
		if err := settings.Set(t.Context(), store.DefaultTenant, *current, testinstance.Console); err != nil {
			t.Fatal(err)
		}
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		issued := stepUpCertificate(t, v, "expiry.homelab.lan")
		v.Clock.Advance(25 * time.Minute)
		b.get(t, "/")
		v.Clock.Advance(25 * time.Minute)
		b.get(t, "/")
		v.Clock.Advance(10*time.Minute + time.Second)
		r := b.post(t, "/certificates/"+issued.ID+"/revoke", url.Values{"csrf_token": {csrf}, "reason": {"superseded"}, "confirm": {"yes"}})
		if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
			t.Fatalf("begin expiration test: %d %q", r.Code, r.location())
		}
		id := pendingID(t, b)
		v.Clock.Advance(pendingActionTTL)
		if r := b.get(t, "/step-up"); r.Code != http.StatusBadRequest {
			t.Fatalf("expired page: %d", r.Code)
		}
		if r := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {v.Code("demo")}}); r.Code != http.StatusBadRequest {
			t.Fatalf("expired continuation: %d", r.Code)
		}
		if certificateStatus(t, v, issued.ID) != ca.CertValid {
			t.Error("expired action executed")
		}
	})

	t.Run("fresh handler", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		issued := stepUpCertificate(t, v, "restart.homelab.lan")
		beginRevoke(t, b, issued.ID, csrf, "superseded")
		id := pendingID(t, b)
		h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: &AppDeps{
			Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
			Settings: &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read,
		}})
		if err != nil {
			t.Fatal(err)
		}
		v.h = h
		v.Clock.Advance(30 * time.Second)
		r := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {v.Code("demo")}})
		if r.Code != http.StatusBadRequest || certificateStatus(t, v, issued.ID) != ca.CertValid {
			t.Fatalf("restart continuation: %d status %q", r.Code, certificateStatus(t, v, issued.ID))
		}
	})
}

func TestStepUpBusinessFailureAndAuthorizationRerun(t *testing.T) {
	t.Run("business failure consumes", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		issued := stepUpCertificate(t, v, "failure.homelab.lan")
		beginRevoke(t, b, issued.ID, csrf, "not-a-reason")
		id := pendingID(t, b)
		r := confirmPending(t, b, csrf, "demo")
		if r.Code != http.StatusSeeOther || r.location() != "/certificates/"+issued.ID+"/revoke" {
			t.Fatalf("business failure response: %d %q", r.Code, r.location())
		}
		if !strings.Contains(flashOf(t, b, r.location()), "reason") {
			t.Error("business error was not returned by the original handler")
		}
		if replay := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}}); replay.Code != http.StatusBadRequest {
			t.Errorf("business failure replay: %d", replay.Code)
		}
	})

	t.Run("authorization rerun", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		issued := stepUpCertificate(t, v, "authorization.homelab.lan")
		beginRevoke(t, b, issued.ID, csrf, "superseded")
		if _, err := v.SystemDB.Write.ExecContext(t.Context(), `UPDATE role_bindings SET role = 'viewer' WHERE user_id = (SELECT id FROM users WHERE username = 'demo') AND tenant_id = 'default'`); err != nil {
			t.Fatal(err)
		}
		r := confirmPending(t, b, csrf, "demo")
		if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, r.location()), "role") {
			t.Fatalf("changed role was not enforced: %d %q", r.Code, r.location())
		}
		if certificateStatus(t, v, issued.ID) != ca.CertValid {
			t.Error("action executed after authorization was removed")
		}
		if r := b.get(t, "/step-up"); r.Code != http.StatusBadRequest {
			t.Errorf("denied business action remained pending: %d", r.Code)
		}
	})
}

func TestStepUpConcurrentDoubleClick(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	issued := stepUpCertificate(t, v, "double-click.homelab.lan")
	beginRevoke(t, b, issued.ID, csrf, "superseded")
	id := pendingID(t, b)
	v.Clock.Advance(30 * time.Second)
	form := url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {v.Code("demo")}}
	cookies := func() map[string]string {
		out := make(map[string]string, len(b.cookies))
		for name, value := range b.cookies {
			out[name] = value
		}
		return out
	}
	answers := make(chan page, 2)
	var wg sync.WaitGroup
	for range 2 {
		click := &browser{v: v, ip: b.ip, cookies: cookies()}
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers <- click.post(t, "/step-up", form)
		}()
	}
	wg.Wait()
	close(answers)
	continued := 0
	for answer := range answers {
		if answer.Code == http.StatusSeeOther && answer.location() == "/certificates/"+issued.ID {
			continued++
		}
	}
	if continued != 1 || certificateStatus(t, v, issued.ID) != ca.CertRevoked {
		t.Errorf("double click continued %d times, status %q", continued, certificateStatus(t, v, issued.ID))
	}
}

func TestPendingActionConcurrentConsumption(t *testing.T) {
	t.Parallel()
	store := newPendingActions()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	binding := auth.SessionBinding{SessionIDHash: "session", CredentialsEpoch: 7}
	id, err := store.put(&pendingAction{sessionIDHash: binding.SessionIDHash, userID: "user", credentialsEpoch: binding.CredentialsEpoch,
		createdAt: now, expiresAt: now.Add(pendingActionTTL), action: "POST /certificates/{id}/revoke"})
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.consume(id, binding, binding, "user", now); err == nil {
				runs.Add(1)
			}
		}()
	}
	wg.Wait()
	if runs.Load() != 1 {
		t.Errorf("consumed %d times", runs.Load())
	}
}

func testPendingEntry(session string, now time.Time, archiveBytes int) *pendingAction {
	return &pendingAction{sessionIDHash: session, userID: "user-" + session, credentialsEpoch: 1,
		createdAt: now, expiresAt: now.Add(pendingActionTTL), action: "POST /certificates/{id}/revoke", archive: make([]byte, archiveBytes)}
}

func testPendingBinding(session string) auth.SessionBinding {
	return auth.SessionBinding{SessionIDHash: session, CredentialsEpoch: 1}
}

func TestPendingActionReplacedBySameSession(t *testing.T) {
	t.Parallel()
	store := newPendingActions()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	first, err := store.put(testPendingEntry("session", now, 3))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.put(testPendingEntry("session", now, 5))
	if err != nil {
		t.Fatal(err)
	}
	binding := testPendingBinding("session")
	if _, err := store.get(first, binding, "user-session", now); !errors.Is(err, errPendingAction) {
		t.Errorf("replaced ID remains valid: %v", err)
	}
	if _, err := store.get(second, binding, "user-session", now); err != nil {
		t.Fatalf("replacement is invalid: %v", err)
	}
	if len(store.entries) != 1 || store.archiveBytes != 5 {
		t.Errorf("replacement accounting: %d entries, %d bytes", len(store.entries), store.archiveBytes)
	}
}

func TestPendingActionGlobalEntryLimit(t *testing.T) {
	t.Parallel()
	store := newPendingActions()
	store.maxEntries = 2
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	first, err := store.put(testPendingEntry("one", now, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.put(testPendingEntry("two", now, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.put(testPendingEntry("three", now, 3)); !errors.Is(err, errTooManyPendingActions) {
		t.Fatalf("entry limit: %v", err)
	}
	if len(store.entries) != 2 || store.archiveBytes != 3 {
		t.Errorf("failed put grew state: %d entries, %d bytes", len(store.entries), store.archiveBytes)
	}
	if _, err := store.get(first, testPendingBinding("one"), "user-one", now); err != nil {
		t.Errorf("failed put removed an existing entry: %v", err)
	}
	if _, err := store.put(testPendingEntry("one", now, 4)); err != nil {
		t.Errorf("replacement at the entry limit must be allowed: %v", err)
	}
	if len(store.entries) != 2 || store.archiveBytes != 6 {
		t.Errorf("replacement at limit: %d entries, %d bytes", len(store.entries), store.archiveBytes)
	}
}

func TestPendingActionGlobalArchiveLimit(t *testing.T) {
	t.Parallel()
	store := newPendingActions()
	store.maxArchiveBytes = 10
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	first, err := store.put(testPendingEntry("one", now, 8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.put(testPendingEntry("two", now, 3)); !errors.Is(err, errTooManyPendingActions) {
		t.Fatalf("archive limit: %v", err)
	}
	if len(store.entries) != 1 || store.archiveBytes != 8 {
		t.Errorf("failed archive put grew state: %d entries, %d bytes", len(store.entries), store.archiveBytes)
	}
	second, err := store.put(testPendingEntry("one", now, 10))
	if err != nil {
		t.Fatalf("archive replacement: %v", err)
	}
	if _, err := store.get(first, testPendingBinding("one"), "user-one", now); !errors.Is(err, errPendingAction) {
		t.Errorf("replaced archive ID remains valid: %v", err)
	}
	if _, err := store.put(testPendingEntry("one", now, 11)); !errors.Is(err, errTooManyPendingActions) {
		t.Fatalf("oversized replacement: %v", err)
	}
	if _, err := store.get(second, testPendingBinding("one"), "user-one", now); err != nil {
		t.Errorf("failed replacement removed the current entry: %v", err)
	}
	if len(store.entries) != 1 || store.archiveBytes != 10 {
		t.Errorf("archive replacement accounting: %d entries, %d bytes", len(store.entries), store.archiveBytes)
	}
}

func TestPendingActionExpirySweepOutsidePut(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"get", "consume"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			store := newPendingActions()
			now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
			if _, err := store.put(testPendingEntry("one", now, 2)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.put(testPendingEntry("two", now, 3)); err != nil {
				t.Fatal(err)
			}
			expired := now.Add(pendingActionTTL)
			binding := testPendingBinding("missing")
			if method == "get" {
				_, _ = store.get("missing", binding, "nobody", expired)
			} else {
				_, _ = store.consume("missing", binding, binding, "nobody", expired)
			}
			if len(store.entries) != 0 || store.archiveBytes != 0 {
				t.Errorf("expiry sweep: %d entries, %d bytes", len(store.entries), store.archiveBytes)
			}
		})
	}
}

func TestStepUpRejectsInjectedActionsAndFields(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	issued := stepUpCertificate(t, v, "injected.homelab.lan")
	r := b.post(t, "/certificates/"+issued.ID+"/revoke", url.Values{"csrf_token": {csrf}, "reason": {"superseded"}, "confirm": {"yes"}, "action": {"POST /admin/settings"}})
	if r.Code != http.StatusBadRequest || certificateStatus(t, v, issued.ID) != ca.CertValid {
		t.Fatalf("injected field: %d", r.Code)
	}
	if r := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {strings.Repeat("A", 43)}, "action": {"POST /admin/settings"}}); r.Code != http.StatusBadRequest {
		t.Errorf("unknown action ID: %d", r.Code)
	}
	a := &app{actions: map[string]actionSpec{}}
	c := &rc{a: a, w: httptest.NewRecorder()}
	if c.executePending(&pendingAction{action: "POST /admin/settings"}) {
		t.Error("an unallowlisted action executed")
	}
}

func TestStepUpSummaryOmitsSecrets(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	issued := stepUpCertificate(t, v, "summary.homelab.lan")
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	const password = "do-not-show-this-p12-password"
	r := b.post(t, "/certificates/"+issued.ID+"/export", url.Values{"csrf_token": {csrf}, "format": {"pkcs12"}, "password": {password}, "password2": {password}, "delete": {"yes"}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("export challenge: %d %q", r.Code, r.location())
	}
	challenge := b.get(t, "/step-up")
	id := rePendingID.FindStringSubmatch(challenge.html())[1]
	for _, want := range []string{"summary.homelab.lan", issued.SerialHex, "pkcs12", "delete the stored key"} {
		if !strings.Contains(challenge.html(), want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	for _, secret := range []string{password, "BEGIN PRIVATE KEY"} {
		if strings.Contains(challenge.html(), secret) || strings.Contains(v.logs.String(), secret) {
			t.Errorf("sensitive value %q appeared in the challenge or log", secret)
		}
	}
	if strings.Contains(v.logs.String(), id) || strings.Contains(challenge.location(), id) || strings.Count(challenge.html(), id) != 1 {
		t.Error("pending ID leaked outside its POST field")
	}
}

func TestStepUpOneTimeSecretAndMultipart(t *testing.T) {
	t.Run("one-time join token", func(t *testing.T) {
		v, _ := newAgentsUIEnv(t)
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		v.Clock.Advance(authz.StepUpWindow + time.Second)
		r := b.post(t, "/agents/tokens", url.Values{"csrf_token": {csrf}, "label": {"proxy"}, "names": {"proxy.homelab.lan"}, "hours": {"2"}})
		if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
			t.Fatalf("join-token challenge: %d %q", r.Code, r.location())
		}
		challenge := b.get(t, "/step-up").html()
		if !strings.Contains(challenge, "proxy.homelab.lan") || strings.Contains(challenge, "mjt_") {
			t.Errorf("join-token summary: %s", challenge)
		}
		r = confirmPending(t, b, csrf, "demo")
		secret := reSecret.FindString(r.html())
		if r.Code != http.StatusOK || secret == "" || r.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("continued join token: %d %s", r.Code, r.html())
		}
		if strings.Contains(b.get(t, "/agents/tokens").html(), secret) {
			t.Error("one-time join token was shown again")
		}
	})

	t.Run("multipart legacy import", func(t *testing.T) {
		v := newUIEnv(t)
		v.Unseal(t)
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		csrf := b.csrf(t)
		fx := legacytest.Write(t, filepath.Join(t.TempDir(), "pki"), v.Clock.Now())
		archive := tarGz(t, fx.Dir)
		v.Clock.Advance(authz.StepUpWindow + time.Second)
		r := b.postFile(t, "/admin/import", url.Values{"csrf_token": {csrf}, "dry_run": {"yes"}, "root_key": {"offline"}, "ca_pass": {"root=not-in-summary"}, "key_pass": {"not-in-summary"}}, "archive", "pki.tar.gz", archive)
		if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
			t.Fatalf("import challenge: %d %q %s", r.Code, r.location(), r.html())
		}
		challenge := b.get(t, "/step-up").html()
		if !strings.Contains(challenge, "Legacy PKI dry run") || strings.Contains(challenge, "not-in-summary") {
			t.Errorf("import summary: %s", challenge)
		}
		r = confirmPending(t, b, csrf, "demo")
		if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/admin/import/imp_") {
			t.Fatalf("continued import: %d %q %s", r.Code, r.location(), r.html())
		}
		if page := b.get(t, r.location()).html(); !strings.Contains(page, "exists already") {
			t.Errorf("import report: %s", page)
		}
	})
}
