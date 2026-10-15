package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// fastParams keep tests fast; TestProductionParams pins the real ones.
var fastParams = Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

func testKey(t *testing.T) *Key {
	t.Helper()
	raw := make([]byte, keySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k, err := newKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "auth.key")
	if err := CreateKeyFile(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateKeyFile(path, nil); !errors.Is(err, ErrKeyExists) {
		t.Errorf("second create: %v", err)
	}
	k, warnings, err := LoadKey(path)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("load: %v %v", err, warnings)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", info.Mode().Perm())
		}
		if cerr := os.Chmod(path, 0o644); cerr != nil { // #nosec G302 -- wrong permissions on purpose
			t.Fatal(cerr)
		}
		if _, w, lerr := LoadKey(path); lerr != nil || len(w) != 1 {
			t.Errorf("readable by others: want a warning, got %v %v", w, lerr)
		}
		if cerr := os.Chmod(path, 0o666); cerr != nil { // #nosec G302 -- wrong permissions on purpose
			t.Fatal(cerr)
		}
		if _, _, lerr := LoadKey(path); lerr == nil || !strings.Contains(lerr.Error(), "writable") {
			t.Errorf("writable by others: %v", lerr)
		}
		_ = os.Chmod(path, 0o600)
	}

	// A sealed secret opens only for its user and with its key.
	sealed, err := k.sealTOTP(nil, "usr-1", []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.openTOTP("usr-1", sealed); err != nil || string(got) != "12345678901234567890" {
		t.Errorf("open: %q %v", got, err)
	}
	if _, err := k.openTOTP("usr-2", sealed); !errors.Is(err, ErrUnreadableSecret) {
		t.Errorf("secret moved to another user opens: %v", err)
	}
	if _, err := testKey(t).openTOTP("usr-1", sealed); !errors.Is(err, ErrUnreadableSecret) {
		t.Errorf("other key opens: %v", err)
	}
	if k.recoveryHash("usr-1", "X") == testKey(t).recoveryHash("usr-1", "X") || k.recoveryHash("usr-1", "X") == k.recoveryHash("usr-2", "X") {
		t.Error("recovery hash must depend on key and user")
	}

	for name, content := range map[string]string{"empty": "", "other header": "ssh-ed25519 AAAA", "short key": keyFileHeader + " c2hvcnQ="} {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadKey(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestPasswordHashing(t *testing.T) {
	t.Parallel()
	h := NewHasher(fastParams, 2, time.Second)
	hash, err := h.Hash(t.Context(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Errorf("hash %s", hash)
	}
	if ok, rehash, err := h.Verify(t.Context(), hash, "correct horse battery staple"); !ok || rehash || err != nil {
		t.Errorf("verify: %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := h.Verify(t.Context(), hash, "correct horse battery stapler"); ok {
		t.Error("wrong password accepted")
	}
	// New defaults: the old hash still works and asks for a rehash.
	stronger := NewHasher(Params{Time: 2, MemoryKiB: 8 * 1024, Threads: 1}, 1, time.Second)
	if ok, rehash, _ := stronger.Verify(t.Context(), hash, "correct horse battery staple"); !ok || !rehash {
		t.Errorf("after a parameter change: ok %v rehash %v", ok, rehash)
	}
	// A tampered hash must not make the server allocate gigabytes.
	for _, bad := range []string{
		"$argon2id$v=19$m=4194304,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=8192,t=1000,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$2y$10$abcdefghijklmnopqrstuv", "",
	} {
		if _, _, err := h.Verify(t.Context(), bad, "x"); !errors.Is(err, errBadHash) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestProductionParams(t *testing.T) {
	t.Parallel()
	if DefaultParams != (Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}) || MaxParallelHashes != 4 {
		t.Errorf("production parameters changed: %+v, %d slots – update PHASE1 step 10", DefaultParams, MaxParallelHashes)
	}
}

// TestHasherSlots: at most N hashes at once; the next caller waits briefly
// and gets ErrBusy (owner decision a).
func TestHasherSlots(t *testing.T) {
	t.Parallel()
	h := NewHasher(fastParams, 1, 50*time.Millisecond)
	if err := h.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := h.Hash(t.Context(), "another long password"); !errors.Is(err, ErrBusy) {
		t.Errorf("all slots taken: %v", err)
	}
	if waited := time.Since(start); waited < 40*time.Millisecond || waited > 2*time.Second {
		t.Errorf("waited %v", waited)
	}
	h.release()
	if _, err := h.Hash(t.Context(), "another long password"); err != nil {
		t.Errorf("after release: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.acquire(ctx); err == nil {
		h.release()
	}
}

func TestPasswordPolicy(t *testing.T) {
	t.Parallel()
	for pw, want := range map[string]string{
		"short":                        "at least 12 characters",
		strings.Repeat("x", 257):       "at most 256",
		"alice-is-the-best-2026":       "user name",
		"MyOwnPKI-rocks-2026":          "product name",
		"aaaaaaaaaaaaaa":               "repeated character",
		"abcdefghijklmnop":             "sequence",
		"987654321098":                 "",
		"1qaz2wsx3edc":                 "leaked password lists",
		"1QAZ2WSX3EDC":                 "leaked password lists", // case-insensitive
		"PasswordPassword":             "leaked password lists",
		"tab\there and long enough":    "control characters",
		"correct horse battery staple": "",
		"Ünïcödé pässwörd ok":          "",
	} {
		err := CheckPassword("alice", pw)
		switch {
		case want == "" && err != nil:
			t.Errorf("%q refused: %v", pw, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want) || !errors.Is(err, ErrWeakPassword)):
			t.Errorf("%q: %v, want %q", pw, err, want)
		}
	}
	if n := len(commonPasswords()); n < 40000 {
		t.Errorf("common password list has %d entries", n)
	}
}

func TestUsernames(t *testing.T) {
	t.Parallel()
	for name, ok := range map[string]bool{
		"alice": true, "a.b@c-d_e": true, "it-admin": true, "x": true, "0day": true,
		"Alice": false, "-x": false, ".x": false, "": false, "a b": false, "аdmin": false, // Cyrillic а
		strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
	} {
		if err := CheckUsername(name); (err == nil) != ok {
			t.Errorf("%q: %v, want ok=%v", name, err, ok)
		}
	}
}

// TestTOTPVectors: RFC 4226 appendix D (HOTP) and RFC 6238 appendix B
// (TOTP, SHA-1, 8 digits).
func TestTOTPVectors(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := hotp(secret, uint64(i), 6); got != want {
			t.Errorf("HOTP %d: %s, want %s", i, got, want)
		}
	}
	for unix, want := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		if got := hotp(secret, counter(time.Unix(unix, 0)), 8); got != want {
			t.Errorf("TOTP at %d: %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPMatching(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	now := time.Unix(1_800_000_000, 0)
	code := func(d time.Duration) string { return hotp(secret, counter(now.Add(d)), 6) }
	for d, ok := range map[time.Duration]bool{0: true, -30 * time.Second: true, 30 * time.Second: true, -60 * time.Second: false, 60 * time.Second: false} {
		if _, got := matchTOTP(secret, code(d), now, 0); got != ok {
			t.Errorf("code from %v: %v, want %v", d, got, ok)
		}
	}
	step, ok := matchTOTP(secret, code(0), now, 0)
	if !ok {
		t.Fatal("current code refused")
	}
	if _, ok := matchTOTP(secret, code(0), now, step); ok {
		t.Error("a used code works twice")
	}
	if _, ok := matchTOTP(secret, code(-30*time.Second), now, step); ok {
		t.Error("an older code works after a newer one")
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456", "１２３４５６"} {
		if _, ok := matchTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if normalizeTOTPCode(" 123 456 ") != "123456" {
		t.Error("spaces from authenticator apps")
	}
}

func TestEnrollment(t *testing.T) {
	t.Parallel()
	secret, err := newTOTPSecret(nil)
	if err != nil || len(secret) != 20 {
		t.Fatalf("secret: %d bytes, %v", len(secret), err)
	}
	e := newEnrollment("MyOwnPKI", "usr-1", "alice@homelab", secret)
	u, err := url.Parse(e.URI)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/MyOwnPKI:alice@homelab" || q.Get("issuer") != "MyOwnPKI" ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" || len(q.Get("secret")) != 32 {
		t.Errorf("uri %s", e.URI)
	}
	if strings.ReplaceAll(e.Secret, " ", "") != q.Get("secret") || len(strings.Fields(e.Secret)) != 8 {
		t.Errorf("secret for typing: %q", e.Secret)
	}
}

func TestRecoveryCodes(t *testing.T) {
	t.Parallel()
	codes, err := newRecoveryCodes(nil, RecoveryCodeCount)
	if err != nil || len(codes) != 10 {
		t.Fatal(codes, err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		canon, ok := normalizeRecoveryCode(c)
		if !ok || len(c) != 23 || seen[canon] {
			t.Errorf("code %q", c)
		}
		seen[canon] = true
	}
	// 20 symbols of 32 = 100 bits (owner decision: at least 80).
	if recoveryCodeLen*5 < 80 {
		t.Error("recovery codes below 80 bits")
	}
	canon, _ := normalizeRecoveryCode("0123A-BCDEF-GHJKM-NPQRS")
	for _, typed := range []string{"0123abcdefghjkmnpqrs", "o123A BCDEF GHJKM NPQRS", "0123a-bcdef-ghjkm-npqrs"} {
		if got, ok := normalizeRecoveryCode(typed); !ok || got != canon {
			t.Errorf("%q: %q %v, want %q", typed, got, ok, canon)
		}
	}
	if got, _ := normalizeRecoveryCode("I1L1I-1L1I1-L1I1L-1I1L1"); got != strings.Repeat("1", 20) {
		t.Errorf("I and L as 1: %q", got)
	}
	for _, bad := range []string{"", "0123A-BCDEF-GHJKM", "0123A-BCDEF-GHJKM-NPQRSU", "0123A-BCDEF-GHJKM-NPQR!"} {
		if _, ok := normalizeRecoveryCode(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClientIP(t *testing.T) {
	t.Parallel()
	proxies, err := config.ParseProxies("10.0.0.5, 10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		remote, xff string
		trusted     []netip.Prefix
		want        string
	}{
		{"203.0.113.9:4000", "1.2.3.4", nil, "203.0.113.9"},                             // no proxies: header ignored
		{"203.0.113.9:4000", "1.2.3.4", proxies, "203.0.113.9"},                         // peer is not a proxy
		{"10.0.0.5:4000", "198.51.100.20", proxies, "198.51.100.20"},                    // one proxy
		{"10.0.0.5:4000", "6.6.6.6, 198.51.100.20, 10.1.2.3", proxies, "198.51.100.20"}, // spoofed left part ignored
		{"10.0.0.5:4000", "", proxies, "10.0.0.5"},
		{"10.0.0.5:4000", "garbage, 198.51.100.20", proxies, "198.51.100.20"},
		{"10.0.0.5:4000", "198.51.100.20, garbage", proxies, "10.0.0.5"},
		{"10.0.0.5:4000", "10.1.9.9", proxies, "10.1.9.9"}, // all trusted: the leftmost
		{"[::ffff:10.0.0.5]:4000", "2001:db8::1", proxies, "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r, c.trusted); got.String() != c.want {
			t.Errorf("%s / %q: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestCSRF(t *testing.T) {
	t.Parallel()
	const token = "the-session-token"
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		func(r *http.Request) (string, bool) {
			if r.Header.Get("Cookie") == "" {
				return "", false
			}
			return token, true
		})
	do := func(method string, header map[string]string, body string) int {
		r := httptest.NewRequestWithContext(t.Context(), method, "https://pki.homelab.lan/x", strings.NewReader(body))
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	session := map[string]string{"Cookie": "s=1", "Sec-Fetch-Site": "same-origin"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range session {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for name, c := range map[string]struct {
		method string
		header map[string]string
		body   string
		want   int
	}{
		"GET needs nothing":            {http.MethodGet, session, "", http.StatusNoContent},
		"POST without token":           {http.MethodPost, session, "", http.StatusForbidden},
		"POST with header":             {http.MethodPost, with(map[string]string{CSRFHeader: token}), "", http.StatusNoContent},
		"POST with wrong token":        {http.MethodPost, with(map[string]string{CSRFHeader: "nope"}), "", http.StatusForbidden},
		"POST with form field":         {http.MethodPost, with(map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), CSRFField + "=" + token, http.StatusNoContent},
		"cross-site, valid token":      {http.MethodPost, with(map[string]string{CSRFHeader: token, "Sec-Fetch-Site": "cross-site"}), "", http.StatusForbidden},
		"login form, no session":       {http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, "", http.StatusNoContent},
		"login form from another site": {http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, "", http.StatusForbidden},
		"foreign Origin, old browser":  {http.MethodPost, map[string]string{"Origin": "https://evil.example"}, "", http.StatusForbidden},
	} {
		if got := do(c.method, c.header, c.body); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	if !bytes.Contains([]byte(ErrCSRF.Error()), []byte("reload")) {
		t.Error("message")
	}
}

// counter is the HOTP counter of the TOTP step at t (never negative here).
func counter(t time.Time) uint64 {
	step := totpStep(t)
	if step < 0 {
		return 0
	}
	return uint64(step)
}

func TestThrottle(t *testing.T) {
	t.Parallel()
	th := NewThrottle()
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	for i := range 4 {
		th.Failure("192.0.2.1", "alice", true, now)
		if w := th.Wait("192.0.2.1", "alice", true, now); w != 0 {
			t.Fatalf("after %d failures: wait %v", i+1, w)
		}
	}
	th.Failure("192.0.2.1", "alice", true, now)
	if w := th.Wait("192.0.2.1", "ALICE", true, now); w != time.Second {
		t.Errorf("after 5 failures: %v, want 1s (and case-insensitive)", w)
	}
	if w := th.Wait("192.0.2.2", "alice", true, now); w != 0 {
		t.Errorf("another IP is slowed down after 5 failures: %v", w)
	}
	for range 20 {
		th.Failure("192.0.2.1", "alice", true, now)
	}
	if w := th.Wait("192.0.2.1", "alice", true, now); w != 15*time.Minute {
		t.Errorf("cap: %v", w)
	}
	// The per-user counter (20 free) catches a distributed attack.
	if w := th.Wait("198.51.100.7", "alice", true, now); w == 0 {
		t.Error("25 failures for alice, but a new IP may go on")
	}
	th.Success("192.0.2.1", "alice")
	if w := th.Wait("198.51.100.7", "alice", true, now); w == 0 {
		t.Error("a success of the real user cleared the per-user counter")
	}
	if w := th.Wait("198.51.100.7", "alice", true, now.Add(time.Hour)); w != 0 {
		t.Errorf("not forgotten after an hour: %v", w)
	}
	th.Forget("alice")
	if w := th.Wait("198.51.100.7", "alice", true, now); w != 0 {
		t.Errorf("after unlock: %v", w)
	}
}

// TestThrottleUnknownNames: invented names share one counter per address –
// they can neither fill the table nor escape the throttle by rotating.
func TestThrottleUnknownNames(t *testing.T) {
	t.Parallel()
	th := NewThrottle()
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	for i := range 1000 {
		th.Failure("203.0.113.5", fmt.Sprintf("fake%d", i), false, now)
	}
	if len(th.entries) != 1 {
		t.Errorf("1000 invented names from one address: %d entries, want 1", len(th.entries))
	}
	if w := th.Wait("203.0.113.5", "fake-new", false, now); w == 0 {
		t.Error("a new invented name from the same address is not slowed down")
	}
	if w := th.Wait("203.0.113.5", "admin", true, now); w != 0 {
		t.Errorf("a real user from that address is slowed down by invented names: %v", w)
	}
}

// TestThrottleFloodKeepsBrakingEntries: a flood from rotating addresses fills
// the table, but pruning drops the entries with the fewest failures first and
// never one that is braking – the counter of admin survives.
func TestThrottleFloodKeepsBrakingEntries(t *testing.T) {
	t.Parallel()
	th := NewThrottle()
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	for range 6 {
		th.Failure("192.0.2.66", "admin", true, now)
	}
	before := th.Wait("192.0.2.66", "admin", true, now)
	if before == 0 {
		t.Fatal("admin's attacker is not slowed down")
	}
	for i := range maxThrottleEntries + 20_000 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		th.Failure(ip.String(), fmt.Sprintf("fake%d", i), false, now)
	}
	if len(th.entries) > maxThrottleEntries {
		t.Errorf("%d entries after the flood", len(th.entries))
	}
	if w := th.Wait("192.0.2.66", "admin", true, now); w != before {
		t.Errorf("admin's counter was pruned: wait %v, want %v", w, before)
	}
	if w := th.Wait("198.51.100.1", "admin", true, now); w != 0 {
		t.Errorf("per-user counter below its free failures must not brake: %v", w)
	}
}

// TestThrottleIPv6: one /64 is one client; IPv4-mapped IPv6 counts as IPv4.
func TestThrottleIPv6(t *testing.T) {
	t.Parallel()
	th := NewThrottle()
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	for i := range strictRule.free {
		th.Failure(fmt.Sprintf("2001:db8:1:2::%x", i+1), "alice", true, now)
	}
	if w := th.Wait("2001:db8:1:2:ffff::1", "alice", true, now); w == 0 {
		t.Error("addresses of one /64 are counted apart")
	}
	if w := th.Wait("2001:db8:1:3::1", "alice", true, now); w != 0 {
		t.Errorf("the next /64 is slowed down: %v", w)
	}
	for range strictRule.free {
		th.Failure("::ffff:192.0.2.9", "bob", true, now)
	}
	if w := th.Wait("192.0.2.9", "bob", true, now); w == 0 {
		t.Error("IPv4-mapped IPv6 is not counted as IPv4")
	}
	for ip, want := range map[string]string{
		"192.0.2.9": "192.0.2.9", "::ffff:192.0.2.9": "192.0.2.9", "2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"fe80::1%eth0": "fe80::/64", "not an ip": "not an ip",
	} {
		if got := ipKey(ip); got != want {
			t.Errorf("ipKey(%q) = %q, want %q", ip, got, want)
		}
	}
}
