package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
)

var t0 = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

const tenantScope = "tenant:default"

// env is a migrated data directory with the writers of every database.
type env struct {
	clk                              *clock.Fake
	system, instAudit, pki, tenAudit *sql.DB
}

func newEnv(t *testing.T) env {
	t.Helper()
	l := store.Layout{DataDir: t.TempDir()}
	clk := clock.NewFake(t0)
	if _, err := store.Migrate(t.Context(), l, store.DefaultTenant, clk.Now); err != nil {
		t.Fatal(err)
	}
	open := func(path string) *sql.DB {
		db, err := store.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db.Write
	}
	pki, _ := l.TenantDB(store.DefaultTenant, store.KindPKI)
	tenAudit, _ := l.TenantDB(store.DefaultTenant, store.KindAudit)
	return env{clk: clk, system: open(l.SystemDB()), instAudit: open(l.InstanceAuditDB()), pki: open(pki), tenAudit: open(tenAudit)}
}

func (e env) deliverer() *Deliverer {
	return &Deliverer{
		Routes: []Route{
			{Source: "system", From: e.system, To: e.instAudit, Scope: store.InstanceScope},
			{Source: "pki", From: e.pki, To: e.tenAudit, Scope: tenantScope},
		},
		Clock: e.clk,
		Log:   slog.New(slog.DiscardHandler),
	}
}

func entry(n int) Entry {
	return Entry{
		Time:     t0.Add(time.Duration(n) * time.Minute),
		Actor:    Actor{Type: ActorUser, ID: "u-1", Name: "it-admin"},
		Action:   "certificate.issue",
		Target:   Target{Type: "certificate", ID: "c-" + string(rune('a'+n%26))},
		Result:   ResultSuccess,
		SourceIP: "192.0.2.10",
		Details:  map[string]any{"preset": "server", "n": n},
	}
}

func appendN(t *testing.T, db *sql.DB, scope string, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, _, err := Append(t.Context(), db, scope, entry(i), ""); err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, db *sql.DB, scope string) Report {
	t.Helper()
	r, err := Verify(t.Context(), db, scope)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// tamper runs SQL with the append-only triggers removed – what someone with
// write access to the file could do.
func tamper(t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()
	for _, s := range append([]string{
		`DROP TRIGGER audit_entries_no_update`, `DROP TRIGGER audit_entries_no_delete`,
	}, statements...) {
		if _, err := db.ExecContext(t.Context(), s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func TestAppendAndVerify(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if r := verify(t, e.tenAudit, tenantScope); r.Entries != 0 || r.Break != nil || r.Head.Hash != Genesis(tenantScope) {
		t.Errorf("empty log: %+v", r)
	}
	appendN(t, e.tenAudit, tenantScope, 5)
	r := verify(t, e.tenAudit, tenantScope)
	if r.Entries != 5 || r.Break != nil || r.Head.Seq != 5 || len(r.Head.Hash) != 64 {
		t.Errorf("report = %+v", r)
	}
	var first string
	if err := e.tenAudit.QueryRowContext(t.Context(), `SELECT prev_hash FROM audit_entries WHERE seq = 1`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first != Genesis(tenantScope) {
		t.Error("first entry does not start at the scope's genesis value")
	}
}

func TestTamperingIsFoundAtTheRightSeq(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		statements []string
		wantSeq    int64
		wantReason string
	}{
		{"modified entry", []string{`UPDATE audit_entries SET actor_name = 'someone-else' WHERE seq = 7`}, 7, "entry modified"},
		{"modified details", []string{`UPDATE audit_entries SET details_json = '{"n":7,"preset":"codesign"}' WHERE seq = 7`}, 7, "entry modified"},
		{"deleted entry", []string{`DELETE FROM audit_entries WHERE seq = 4`}, 4, "entry missing"},
		{"deleted first entry", []string{`DELETE FROM audit_entries WHERE seq = 1`}, 1, "entry missing"},
		{"hash replaced", []string{`UPDATE audit_entries SET hash = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0' WHERE seq = 7`}, 7, "entry modified"},
		{"swapped order", []string{
			`UPDATE audit_entries SET seq = 100 WHERE seq = 5`, `UPDATE audit_entries SET seq = 5 WHERE seq = 6`, `UPDATE audit_entries SET seq = 6 WHERE seq = 100`,
		}, 5, "link broken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			appendN(t, e.tenAudit, tenantScope, 10)
			tamper(t, e.tenAudit, tt.statements...)
			r := verify(t, e.tenAudit, tenantScope)
			if r.Break == nil || r.Break.Seq != tt.wantSeq || !strings.Contains(r.Break.Reason, tt.wantReason) {
				t.Errorf("break = %+v, want seq %d (%s)", r.Break, tt.wantSeq, tt.wantReason)
			}
		})
	}
}

func TestLogIsAppendOnlyInTheDatabase(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 2)
	for _, s := range []string{`UPDATE audit_entries SET result = 'denied' WHERE seq = 1`, `DELETE FROM audit_entries WHERE seq = 2`} {
		if _, err := e.tenAudit.ExecContext(t.Context(), s); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want the append-only trigger", s, err)
		}
	}
}

func TestLogCannotMoveToAnotherScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 3)
	if r := verify(t, e.tenAudit, "tenant:other"); r.Break == nil || r.Break.Seq != 1 {
		t.Errorf("verified as another scope: %+v", r)
	}
	if Genesis(store.InstanceScope) == Genesis(tenantScope) {
		t.Error("instance and tenant logs start at the same value")
	}
}

func TestEntryValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Entry)
		wantErr string
	}{
		{"valid", func(*Entry) {}, ""},
		{"password in details", func(e *Entry) { e.Details = map[string]any{"Export_Password": "x"} }, "looks like a secret"},
		{"nested secret", func(e *Entry) { e.Details = map[string]any{"key": map[string]any{"private_key_pem": "x"}} }, "looks like a secret"},
		{"secret in a list", func(e *Entry) { e.Details = map[string]any{"items": []any{map[string]any{"passphrase": "x"}}} }, "looks like a secret"},
		{"token", func(e *Entry) { e.Details = map[string]any{"token": "x"} }, "looks like a secret"},
		{"token name is fine", func(e *Entry) { e.Details = map[string]any{"token_name": "ci"} }, ""},
		{"ip with port", func(e *Entry) { e.SourceIP = "192.0.2.1:443" }, "not an IP address"},
		{"host name", func(e *Entry) { e.SourceIP = "admin-pc.lan" }, "not an IP address"},
		{"ipv6", func(e *Entry) { e.SourceIP = "2001:db8::1" }, ""},
		{"action", func(e *Entry) { e.Action = "Issue certificate" }, "action"},
		{"actor type", func(e *Entry) { e.Actor.Type = "robot" }, "unknown actor type"},
		{"result", func(e *Entry) { e.Result = "ok" }, "unknown result"},
		{"no time", func(e *Entry) { e.Time = time.Time{} }, "time is missing"},
		{"no actor name", func(e *Entry) { e.Actor.Name = "" }, "actor name is missing"},
		{"huge details", func(e *Entry) { e.Details = map[string]any{"x": strings.Repeat("a", 9000)} }, "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			en := entry(1)
			tt.mutate(&en)
			_, err := en.validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (!errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want ErrInvalid containing %q", err, tt.wantErr)
			}
		})
	}
}

// enqueue writes a business row and its audit event in one pki.db transaction.
func enqueue(t *testing.T, e env, n int, commit bool) {
	t.Helper()
	tx, err := e.pki.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = Enqueue(t.Context(), tx, e.clk.Now(), entry(n)); err != nil {
		t.Fatal(err)
	}
	if commit {
		err = tx.Commit()
	} else {
		err = tx.Rollback()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOutboxDeliversExactlyOnceAfterACrash(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for i := 1; i <= 3; i++ {
		enqueue(t, e, i, true)
	}

	// First run "crashes" right after appending the second entry, before
	// its outbox row is marked delivered.
	d := e.deliverer()
	calls := 0
	d.afterAppend = func() error {
		calls++
		if calls == 2 {
			return errors.New("simulated crash")
		}
		return nil
	}
	if _, err := d.DeliverPending(t.Context()); err == nil {
		t.Fatal("simulated crash not reported")
	}
	if got := count(t, e.tenAudit, `SELECT count(*) FROM audit_entries`); got != 2 {
		t.Fatalf("after the crash: %d audit entries, want 2", got)
	}
	if got := count(t, e.pki, `SELECT count(*) FROM outbox WHERE delivered_at IS NULL`); got != 2 {
		t.Fatalf("after the crash: %d undelivered rows, want 2 (row 2 appended but not marked)", got)
	}

	// Restart: row 2 is delivered again and recognized, row 3 is new.
	d.afterAppend = nil
	added, err := d.DeliverPending(t.Context())
	if err != nil || added != 1 {
		t.Fatalf("second run: added %d, %v; want 1 (row 2 is a duplicate)", added, err)
	}
	if got := count(t, e.tenAudit, `SELECT count(*) FROM audit_entries`); got != 3 {
		t.Errorf("%d audit entries, want exactly 3", got)
	}
	if got := count(t, e.pki, `SELECT count(*) FROM outbox WHERE delivered_at IS NULL`); got != 0 {
		t.Errorf("%d rows still undelivered", got)
	}
	if got := count(t, e.tenAudit, `SELECT count(DISTINCT outbox_id) FROM audit_entries WHERE outbox_id LIKE 'pki:%'`); got != 3 {
		t.Errorf("%d distinct outbox ids, want 3", got)
	}
	if r := verify(t, e.tenAudit, tenantScope); r.Break != nil || r.Entries != 3 {
		t.Errorf("chain after redelivery: %+v", r)
	}
	if added, _ := d.DeliverPending(t.Context()); added != 0 {
		t.Errorf("third run added %d", added)
	}
}

func TestRolledBackChangeLeavesNoAuditEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	enqueue(t, e, 1, false)
	if added, err := e.deliverer().DeliverPending(t.Context()); err != nil || added != 0 {
		t.Errorf("delivered %d, %v – the event of a rolled-back change must not be logged", added, err)
	}
}

func TestEventsGoToTheirOwnLog(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tx, err := e.system.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	login := entry(1)
	login.Action, login.Target = "user.login", Target{Type: "user", ID: "u-1"}
	if err := Enqueue(t.Context(), tx, e.clk.Now(), login); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	enqueue(t, e, 2, true)
	if _, err := e.deliverer().DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, e.instAudit, `SELECT count(*) FROM audit_entries WHERE action = 'user.login' AND outbox_id = 'system:1'`); got != 1 {
		t.Error("login event is not in the instance log")
	}
	if got := count(t, e.tenAudit, `SELECT count(*) FROM audit_entries WHERE action = 'user.login'`); got != 0 {
		t.Error("login event leaked into the tenant log")
	}
}

func TestCleanupKeepsUndeliveredRows(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.deliverer()
	enqueue(t, e, 1, true)
	if _, err := d.DeliverPending(t.Context()); err != nil { // delivered at t0
		t.Fatal(err)
	}
	e.clk.Advance(20 * 24 * time.Hour)
	enqueue(t, e, 2, true)
	if _, err := d.DeliverPending(t.Context()); err != nil { // delivered at t0+20d
		t.Fatal(err)
	}
	enqueue(t, e, 3, true) // created at t0+20d, never delivered

	e.clk.Advance(15 * 24 * time.Hour) // now t0+35d
	deleted, err := d.Cleanup(t.Context())
	if err != nil || deleted != 1 {
		t.Fatalf("deleted %d, %v; want 1 (only the row delivered 35 days ago)", deleted, err)
	}
	if got := count(t, e.pki, `SELECT count(*) FROM outbox WHERE delivered_at IS NULL`); got != 1 {
		t.Error("an undelivered row was deleted")
	}
	e.clk.Advance(365 * 24 * time.Hour)
	if _, err := d.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, e.pki, `SELECT count(*) FROM outbox WHERE delivered_at IS NULL`); got != 1 {
		t.Error("an undelivered row was deleted after a year")
	}
}

func TestDeletedOutboxIDsAreNotReused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.deliverer()
	enqueue(t, e, 1, true)
	if _, err := d.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(OutboxRetention + time.Hour)
	if _, err := d.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	enqueue(t, e, 2, true)
	if added, err := d.DeliverPending(t.Context()); err != nil || added != 1 {
		t.Errorf("new event after cleanup: added %d, %v – a reused outbox id would hide it as a duplicate", added, err)
	}
}

func TestConcurrentAppendsKeepTheChain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			if _, _, err := Append(t.Context(), e.tenAudit, tenantScope, entry(i), ""); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if r := verify(t, e.tenAudit, tenantScope); r.Entries != 40 || r.Break != nil {
		t.Errorf("after concurrent appends: %+v", r)
	}
}

func TestCheckHead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 8)
	anchor := verify(t, e.tenAudit, tenantScope).Head // noted down at seq 8
	appendN(t, e.tenAudit, tenantScope, 2)
	if err := CheckHead(t.Context(), e.tenAudit, Head{Seq: anchor.Seq, Hash: anchor.Hash[:12]}); err != nil {
		t.Errorf("growing log against an older head: %v", err)
	}

	tamper(t, e.tenAudit, `DELETE FROM audit_entries WHERE seq >= 7`) // cut off the end
	if r := verify(t, e.tenAudit, tenantScope); r.Break != nil {
		t.Fatalf("a cut-off end is invisible to the chain alone, got %+v", r.Break)
	}
	if err := CheckHead(t.Context(), e.tenAudit, anchor); err == nil || !strings.Contains(err.Error(), "cut off") {
		t.Errorf("cut-off end: err = %v", err)
	}
}

func TestParseHead(t *testing.T) {
	t.Parallel()
	h, err := ParseHead(" 1284:3F9A0B1C2D3E4F ")
	if err != nil || h.Seq != 1284 || h.Hash != "3f9a0b1c2d3e4f" {
		t.Errorf("ParseHead = %+v, %v", h, err)
	}
	for _, bad := range []string{"", "1284", "1284:3f9a", "0:3f9a0b1c2d3e4f", "x:3f9a0b1c2d3e4f", "12:zzzzzzzzzzzzzz"} {
		if _, err := ParseHead(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLogHeadsAndRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var buf bytes.Buffer
	var mu sync.Mutex
	d := e.deliverer()
	d.Log = slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil))

	enqueue(t, e, 1, true)
	ctx, cancel := context.WithCancel(t.Context())
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { d.Run(ctx, wake, time.Hour); close(done) }()

	enqueue(t, e, 2, true)
	wake <- struct{}{}
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for count(t, e.tenAudit, `SELECT count(*) FROM audit_entries`) < 2 {
		select {
		case <-deadline:
			t.Fatal("Run did not deliver after wake")
		case <-tick.C:
		}
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"audit chain head", "scope=instance", "scope=tenant:default"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("process log lacks %q:\n%s", want, buf.String())
		}
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Someone who changes entry 7 and recomputes its hash correctly hides the
// change in 7 – but entry 8 still points to the old hash.
func TestRecomputedEntryBreaksTheNextLink(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 10)
	rows, err := auditdb.New(e.tenAudit).ListEntriesFrom(t.Context(), auditdb.ListEntriesFromParams{Seq: 7, Limit: 1})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	forged := rows[0]
	forged.ActorName = "someone-else"
	forged.Hash = entryHash(forged)
	tamper(t, e.tenAudit, `UPDATE audit_entries SET actor_name = 'someone-else', hash = '`+forged.Hash+`' WHERE seq = 7`)

	r := verify(t, e.tenAudit, tenantScope)
	if r.Break == nil || r.Break.Seq != 8 || !strings.Contains(r.Break.Reason, "link broken") {
		t.Errorf("break = %+v, want seq 8 (link broken)", r.Break)
	}
}
