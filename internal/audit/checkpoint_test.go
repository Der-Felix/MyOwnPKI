package audit

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
)

// testSigner stands in for the keyring.
type testSigner struct {
	priv   ed25519.PrivateKey
	sealed bool
}

func newSigner(seed byte) *testSigner {
	return &testSigner{priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))}
}

func (s *testSigner) SignCheckpoint(msg []byte) ([]byte, ed25519.PublicKey, error) {
	if s.sealed {
		return nil, nil, fmt.Errorf("the server is sealed (%w)", ErrNoSigner)
	}
	return ed25519.Sign(s.priv, msg), ed25519.PublicKey(s.priv[ed25519.SeedSize:]), nil
}

func (s *testSigner) fingerprint() string {
	return KeyFingerprint(ed25519.PublicKey(s.priv[ed25519.SeedSize:]))
}

func checkpoint(t *testing.T, db *sql.DB, s Signer, at time.Time) CheckpointResult {
	t.Helper()
	res, err := Checkpoint(t.Context(), db, tenantScope, s, at)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCheckpointIsSignedAndVerified(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := newSigner(1)
	if res := checkpoint(t, e.tenAudit, s, t0); res.Made {
		t.Error("checkpoint in an empty log")
	}
	appendN(t, e.tenAudit, tenantScope, 4)
	res := checkpoint(t, e.tenAudit, s, t0.Add(time.Hour))
	if !res.Made || res.Head.Seq != 5 || res.Key != s.fingerprint() {
		t.Fatalf("checkpoint = %+v", res)
	}
	if again := checkpoint(t, e.tenAudit, s, t0.Add(2*time.Hour)); again.Made {
		t.Error("checkpoint of a checkpoint – nothing new happened")
	}
	appendN(t, e.tenAudit, tenantScope, 2)
	checkpoint(t, e.tenAudit, s, t0.Add(3*time.Hour))

	r, err := VerifyWith(t.Context(), e.tenAudit, tenantScope, VerifyOptions{CheckpointKey: s.fingerprint()[:16]})
	if err != nil {
		t.Fatal(err)
	}
	if r.Break != nil || r.Checkpoints != 2 || r.LastCheckpoint == nil || r.LastCheckpoint.Seq != 8 || r.CheckpointKey != s.fingerprint() {
		t.Errorf("report = %+v, break %+v", r, r.Break)
	}
}

// rewrite changes entry seq and recomputes every following hash, like an
// attacker with write access to the file. Checkpoint entries get their
// covers_hash adjusted and – with resign – a new signature from s.
func rewrite(t *testing.T, db *sql.DB, seq int64, resign *testSigner) {
	t.Helper()
	tamper(t, db)
	rows, err := auditdb.New(db).ListEntriesFrom(t.Context(), auditdb.ListEntriesFromParams{Seq: 1, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	prev := Genesis(tenantScope)
	for _, row := range rows {
		row.PrevHash = prev
		if row.Seq == seq {
			row.ActorName = "someone-else"
		}
		if row.Action == ActionCheckpoint && row.Seq > seq {
			var d checkpointDetails
			if err := json.Unmarshal([]byte(row.DetailsJson), &d); err != nil {
				t.Fatal(err)
			}
			d.CoversHash = prev
			if resign != nil {
				sig, pub, _ := resign.SignCheckpoint(checkpointMessage(tenantScope, d.CoversSeq, d.CoversHash, row.Time))
				d.Signature, d.PublicKey = hex.EncodeToString(sig), hex.EncodeToString(pub)
			}
			b, _ := json.Marshal(map[string]any{"covers_seq": d.CoversSeq, "covers_hash": d.CoversHash, "public_key": d.PublicKey, "signature": d.Signature})
			row.DetailsJson = string(b)
		}
		row.Hash = entryHash(row)
		if _, err := db.ExecContext(t.Context(), `UPDATE audit_entries SET actor_name = ?, details_json = ?, prev_hash = ?, hash = ? WHERE seq = ?`,
			row.ActorName, row.DetailsJson, row.PrevHash, row.Hash, row.Seq); err != nil {
			t.Fatal(err)
		}
		prev = row.Hash
	}
}

func TestRecomputedChainIsCaughtByTheCheckpoint(t *testing.T) {
	t.Parallel()
	// Without a checkpoint, a fully recomputed chain looks intact – that is
	// the gap checkpoints close.
	plain := newEnv(t)
	appendN(t, plain.tenAudit, tenantScope, 6)
	rewrite(t, plain.tenAudit, 3, nil)
	if r := verify(t, plain.tenAudit, tenantScope); r.Break != nil {
		t.Fatalf("recomputed chain without checkpoint: %+v", r.Break)
	}

	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 6)
	checkpoint(t, e.tenAudit, newSigner(1), t0.Add(time.Hour))
	rewrite(t, e.tenAudit, 3, nil)
	r := verify(t, e.tenAudit, tenantScope)
	if r.Break == nil || r.Break.Seq != 7 || !strings.Contains(r.Break.Reason, "signature invalid") {
		t.Errorf("break = %+v, want the checkpoint at seq 7 (signature invalid)", r.Break)
	}
}

func TestResignedWithOwnKeyNeedsThePinnedKey(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	real := newSigner(1)
	appendN(t, e.tenAudit, tenantScope, 6)
	checkpoint(t, e.tenAudit, real, t0.Add(time.Hour))
	rewrite(t, e.tenAudit, 3, newSigner(2)) // attacker signs with an own key

	if r := verify(t, e.tenAudit, tenantScope); r.Break != nil {
		t.Fatalf("unpinned: %+v – a re-signed chain is consistent in itself", r.Break)
	}
	r, err := VerifyWith(t.Context(), e.tenAudit, tenantScope, VerifyOptions{CheckpointKey: real.fingerprint()[:16]})
	if err != nil {
		t.Fatal(err)
	}
	if r.Break == nil || r.Break.Seq != 7 || !strings.Contains(r.Break.Reason, "not the expected key") {
		t.Errorf("pinned: break = %+v, want the foreign key at seq 7", r.Break)
	}
}

func TestCheckpointsMustUseOneKey(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 2)
	checkpoint(t, e.tenAudit, newSigner(1), t0.Add(time.Hour))
	appendN(t, e.tenAudit, tenantScope, 2)
	checkpoint(t, e.tenAudit, newSigner(2), t0.Add(2*time.Hour))
	if r := verify(t, e.tenAudit, tenantScope); r.Break == nil || r.Break.Seq != 6 || !strings.Contains(r.Break.Reason, "another key") {
		t.Errorf("break = %+v", r.Break)
	}
}

func TestFakeCheckpointIsRejected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	appendN(t, e.tenAudit, tenantScope, 2)
	fake := Entry{
		Time: t0, Actor: Actor{Type: ActorSystem, Name: "system"}, Action: ActionCheckpoint, Result: ResultSuccess,
		Details: map[string]any{"covers_seq": 2, "covers_hash": "00", "public_key": "00", "signature": "00"},
	}
	if _, _, err := Append(t.Context(), e.tenAudit, tenantScope, fake, ""); err != nil {
		t.Fatal(err)
	}
	if r := verify(t, e.tenAudit, tenantScope); r.Break == nil || r.Break.Seq != 3 {
		t.Errorf("unsigned checkpoint accepted: %+v", r)
	}
}

func TestCheckpointer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := newSigner(1)
	var buf bytes.Buffer
	var mu sync.Mutex
	c := &Checkpointer{
		Logs:   []CheckpointLog{{DB: e.instAudit, Scope: "instance"}, {DB: e.tenAudit, Scope: tenantScope}},
		Signer: s, Clock: e.clk, Every: 5,
		Log: slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil)),
	}
	appendN(t, e.tenAudit, tenantScope, 4)
	if err := c.MaybeEvery(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := verify(t, e.tenAudit, tenantScope); r.Checkpoints != 0 {
		t.Error("checkpoint before 5 new entries")
	}
	appendN(t, e.tenAudit, tenantScope, 1)
	if err := c.MaybeEvery(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := verify(t, e.tenAudit, tenantScope); r.Checkpoints != 1 {
		t.Errorf("checkpoints after 5 entries: %d", r.Checkpoints)
	}

	s.sealed = true
	appendN(t, e.tenAudit, tenantScope, 1)
	if err := c.MakeAll(t.Context(), "daily"); err != nil {
		t.Errorf("sealed signer is an error: %v", err)
	}
	if r := verify(t, e.tenAudit, tenantScope); r.Checkpoints != 1 {
		t.Error("checkpoint made while sealed")
	}

	s.sealed = false
	if err := c.MakeAll(t.Context(), "unseal"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(buf.String(), "audit checkpoint") || !strings.Contains(buf.String(), "reason=unseal") ||
		!strings.Contains(buf.String(), "key="+s.fingerprint()) {
		t.Errorf("process log:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "scope=instance") {
		t.Error("checkpoint for the empty instance log")
	}
	if errors.Is(nil, ErrNoSigner) {
		t.Error("unreachable")
	}
}
