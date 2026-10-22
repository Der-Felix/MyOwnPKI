package acme

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// registerEAB registers with an external account binding (RFC 8555 §7.3.4).
func (c *client) registerEAB(kid, hmacB64 string) *answer {
	c.t.Helper()
	url := testBase + "/new-account"
	mac, err := base64.RawURLEncoding.DecodeString(hmacB64)
	if err != nil {
		c.t.Fatal(err)
	}
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": kid, "url": url})
	ph, pl := b64(h), b64([]byte(c.jwk))
	m := hmac.New(sha256.New, mac)
	m.Write([]byte(ph + "." + pl))
	eab := map[string]string{"protected": ph, "payload": pl, "signature": b64(m.Sum(nil))}
	a := c.postRaw(url, c.jws(url, map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": eab}, true))
	if a.code == http.StatusCreated {
		c.kid = a.header.Get("Location")
	}
	return a
}

// TestEABKeys (PHASE2 step 13, owner Q2): an admin creates a key, shown
// once; an account that brings it is approved at once; a key binds one
// account, expires, and is never stored or logged in plain text.
func TestEABKeys(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalAccount)
	ctx := t.Context()
	who := testinstance.Console
	for _, bad := range []struct {
		label string
		days  int
	}{{"", 7}, {strings.Repeat("x", 65), 7}, {"nas", 0}, {"nas", 91}, {"bad\nlabel", 7}} {
		if _, err := v.s.CreateEABKey(ctx, bad.label, bad.days, who); err == nil {
			t.Errorf("label %q, %d days: accepted", bad.label, bad.days)
		}
	}
	key, err := v.s.CreateEABKey(ctx, "nas.homelab.lan", 7, who)
	if err != nil {
		t.Fatal(err)
	}

	// Without EAB the account waits; with it, it orders at once.
	waiting := v.client(t)
	waiting.register()
	if o := waiting.order("nas.homelab.lan"); o.code != http.StatusForbidden {
		t.Errorf("unapproved account ordered: %d %s", o.code, o.body)
	}
	bad := v.client(t)
	wrong := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if a := bad.registerEAB(key.KID, wrong); a.code != http.StatusUnauthorized {
		t.Errorf("wrong MAC: %d %s", a.code, a.body)
	}
	c := v.client(t)
	if a := c.registerEAB(key.KID, key.HMAC); a.code != http.StatusCreated {
		t.Fatalf("register with EAB: %d %s", a.code, a.body)
	}
	if o := c.order("nas.homelab.lan"); o.code != http.StatusCreated {
		t.Errorf("EAB account can't order: %d %s", o.code, o.body)
	}
	if a := v.client(t).registerEAB(key.KID, key.HMAC); a.code != http.StatusUnauthorized || !strings.Contains(string(a.body), "used already") {
		t.Errorf("key used twice: %d %s", a.code, a.body)
	}
	list, err := v.s.EABKeys(ctx, who)
	if err != nil || len(list) != 1 || list[0].UsedBy == "" || list[0].Label != "nas.homelab.lan" {
		t.Errorf("EAB list: %v %+v", err, list)
	}

	// Expiry.
	old, err := v.s.CreateEABKey(ctx, "later", 1, who)
	if err != nil {
		t.Fatal(err)
	}
	v.Clock.Advance(25 * time.Hour)
	if a := v.client(t).registerEAB(old.KID, old.HMAC); a.code != http.StatusUnauthorized || !strings.Contains(string(a.body), "expired") {
		t.Errorf("expired key: %d %s", a.code, a.body)
	}

	// The MAC appears nowhere: not in the audit log, not in the database.
	v.Deliver(t)
	rows, err := v.TenantAudit.Read.QueryContext(ctx, `SELECT action || ' ' || details_json FROM audit_entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	created := 0
	for rows.Next() {
		var line string
		if serr := rows.Scan(&line); serr != nil {
			t.Fatal(serr)
		}
		if strings.HasPrefix(line, ActionEABCreate) {
			created++
		}
		if strings.Contains(line, key.HMAC) || strings.Contains(line, old.HMAC) {
			t.Errorf("audit holds a MAC key: %s", line)
		}
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatal(rerr)
	}
	if created != 2 {
		t.Errorf("%d acme.eab.create entries, want 2", created)
	}
	var stored int
	if err := v.Engine.PKI.QueryRowContext(ctx, `SELECT count(*) FROM acme_eab_keys WHERE instr(hex(mac_ciphertext), hex(?)) > 0`,
		mustB64(t, old.HMAC)).Scan(&stored); err != nil || stored != 0 {
		t.Errorf("the MAC is stored in plain text: %v %d", err, stored)
	}

	// Sealed: no new keys.
	if err := v.Ring.Seal(ctx, who); err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.CreateEABKey(ctx, "sealed", 7, who); !errors.Is(err, keys.ErrSealed) {
		t.Errorf("sealed: %v", err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
