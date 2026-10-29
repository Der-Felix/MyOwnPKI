package monitor

import (
	"database/sql"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/notify"
)

// TestDigest: a new alert is reported once, a rise again, a reminder after
// repeat_every, the end once; nothing without a change; nothing at all and
// nothing marked without a channel.
func TestDigest(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.inst.Clock.Now()
	opt := DigestOptions{Server: "pki01", RepeatEvery: 24 * time.Hour, Channels: []string{"email", "webhook"},
		Link: func(p string) string { return "https://pki.homelab.lan:9443" + p }}
	step := func(at time.Time, fs []Finding, o DigestOptions) notify.Digest {
		t.Helper()
		if _, err := e.store.Sync(t.Context(), at, fs); err != nil {
			t.Fatal(err)
		}
		d, err := e.store.Digest(t.Context(), at, o)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	states := func(d notify.Digest) map[string]string {
		out := map[string]string{}
		for _, ev := range d.Events {
			out[ev.Subject] = ev.State
		}
		return out
	}
	a := Finding{Key: "x:a", Kind: "x", Subject: "A", Severity: Warning, Detail: "a", Href: "/a"}
	b := Finding{Key: "x:b", Kind: "x", Subject: "B", Severity: Warning, Detail: "b"}

	// Without a channel nothing is marked …
	if d := step(now, []Finding{a}, DigestOptions{RepeatEvery: opt.RepeatEvery}); len(d.Events) != 0 {
		t.Fatalf("no channel: %+v", d)
	}
	// … so the first message with a channel lists the open alert.
	d := step(now.Add(time.Minute), []Finding{a, b}, opt)
	if s := states(d); len(s) != 2 || s["A"] != notify.Opened || s["B"] != notify.Opened {
		t.Fatalf("first digest: %v", s)
	}
	if d.Events[0].Link != "https://pki.homelab.lan:9443/a" && d.Events[1].Link != "https://pki.homelab.lan:9443/a" {
		t.Errorf("links: %+v", d.Events)
	}
	if n := queued(t, e, "email") + queued(t, e, "webhook"); n != 2 {
		t.Errorf("queued %d messages, want one per channel", n)
	}
	if d := step(now.Add(2*time.Minute), []Finding{a, b}, opt); len(d.Events) != 0 {
		t.Fatalf("no change, but: %+v", d.Events)
	}

	aCrit := a
	aCrit.Severity = Critical
	if s := states(step(now.Add(3*time.Minute), []Finding{aCrit, b}, opt)); len(s) != 1 || s["A"] != notify.Raised {
		t.Fatalf("raised: %v", s)
	}
	// Down and up again: the fall is silent, the second rise is reported.
	if d := step(now.Add(4*time.Minute), []Finding{a, b}, opt); len(d.Events) != 0 {
		t.Fatalf("lowered: %+v", d.Events)
	}
	if s := states(step(now.Add(5*time.Minute), []Finding{aCrit, b}, opt)); s["A"] != notify.Raised {
		t.Fatalf("raised again: %v", s)
	}

	// B was reported at +1 minute: its reminder is due 24 hours later.
	if d := step(now.Add(24*time.Hour), []Finding{aCrit, b}, opt); len(d.Events) != 0 {
		t.Fatalf("reminder too early: %+v", d.Events)
	}
	if s := states(step(now.Add(24*time.Hour+time.Minute), []Finding{aCrit, b}, opt)); len(s) != 1 || s["B"] != notify.Reminder {
		t.Fatalf("reminder: %v", s)
	}

	// A was last reported at +5 minutes, so its reminder joins this digest.
	if s := states(step(now.Add(25*time.Hour), []Finding{aCrit}, opt)); len(s) != 2 || s["B"] != notify.Resolved || s["A"] != notify.Reminder {
		t.Fatalf("resolved: %v", s)
	}
	if d := step(now.Add(25*time.Hour+time.Minute), []Finding{aCrit}, opt); len(d.Events) != 0 {
		t.Fatalf("resolved twice: %+v", d.Events)
	}

	// An alert that came and went between two digests is never reported.
	c := Finding{Key: "x:c", Kind: "x", Subject: "C", Severity: Warning}
	if _, err := e.store.Sync(t.Context(), now.Add(26*time.Hour), []Finding{aCrit, c}); err != nil {
		t.Fatal(err)
	}
	if d := step(now.Add(26*time.Hour+time.Minute), []Finding{aCrit}, opt); len(d.Events) != 0 {
		t.Fatalf("unreported alert: %+v", d.Events)
	}
}

func queued(t *testing.T, e *env, channel string) int {
	t.Helper()
	var n int
	if err := e.inst.SystemDB.Write.QueryRowContext(t.Context(), "SELECT count(*) FROM notifications WHERE channel = ?", channel).Scan(&n); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return n
}
