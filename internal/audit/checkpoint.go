package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
)

// ActionCheckpoint marks a signed checkpoint (PHASE1 step 6a). It is a
// normal entry of the chain: it signs the entry right before it, and
// deleting or changing it breaks the chain like any other entry. Rewriting
// the chain before a checkpoint needs its signing key, which only exists
// while the server is unsealed.
const ActionCheckpoint = "audit.checkpoint"

// CheckpointEvery: a checkpoint is made after this many new entries, besides
// the ones at unseal, before seal and once a day.
const CheckpointEvery = 1000

// Signer signs checkpoints; *keys.Keyring implements it with an Ed25519 key
// derived from the root key.
type Signer interface {
	SignCheckpoint(msg []byte) (sig []byte, pub ed25519.PublicKey, err error)
}

type checkpointDetails struct {
	CoversSeq  int64  `json:"covers_seq"`
	CoversHash string `json:"covers_hash"`
	PublicKey  string `json:"public_key"` // hex Ed25519
	Signature  string `json:"signature"`  // hex
}

// checkpointMessage is what a checkpoint signs, length-prefixed like the
// chain hash.
func checkpointMessage(scope string, coversSeq int64, coversHash, at string) []byte {
	return encodeFields("MYOWNPKI-AUDIT-CHECKPOINT-V1", scope, strconv.FormatInt(coversSeq, 10), coversHash, at)
}

func encodeFields(fields ...string) []byte {
	var out []byte
	var n [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		out = append(out, n[:]...)
		out = append(out, f...)
	}
	return out
}

// KeyFingerprint is how a checkpoint key is shown and pinned: the first 16
// bytes of SHA-256 over the public key, in hex.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// ErrNoSigner means no checkpoint key is available – the server is sealed.
// The Signer wraps it into its own error.
var ErrNoSigner = errors.New("checkpoint key unavailable")

// CheckpointResult describes a new checkpoint.
type CheckpointResult struct {
	Made bool
	Head Head   // the checkpoint entry itself
	Key  string // fingerprint of the signing key
}

// Checkpoint appends a signed checkpoint covering the current head of the
// log. It does nothing (Made=false) for an empty log or when the head is a
// checkpoint already.
func Checkpoint(ctx context.Context, db *sql.DB, scope string, s Signer, now time.Time) (res CheckpointResult, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("audit checkpoint: %w", err)
	}
	defer func() {
		if err != nil || !res.Made {
			_ = tx.Rollback()
		}
	}()
	q := auditdb.New(tx)
	cur, err := q.GetHead(ctx)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && cur.Action == ActionCheckpoint) {
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("audit checkpoint: %w", err)
	}

	at := now.UTC().Format(TimeFormat)
	sig, pub, err := s.SignCheckpoint(checkpointMessage(scope, cur.Seq, cur.Hash, at))
	if err != nil {
		return res, err
	}
	e := Entry{
		Time:   now,
		Actor:  Actor{Type: ActorSystem, Name: "system"},
		Action: ActionCheckpoint,
		Target: Target{Type: "audit_log", ID: scope},
		Result: ResultSuccess,
		Details: map[string]any{
			"covers_seq": cur.Seq, "covers_hash": cur.Hash,
			"public_key": hex.EncodeToString(pub), "signature": hex.EncodeToString(sig),
		},
	}
	details, err := e.validate()
	if err != nil {
		return res, err
	}
	seq, err := insert(ctx, q, scope, e, details, "")
	if err != nil {
		return res, err
	}
	h, err := q.GetHead(ctx)
	if err != nil {
		return res, fmt.Errorf("audit checkpoint: %w", err)
	}
	res = CheckpointResult{Made: true, Head: Head{Seq: seq, Hash: h.Hash}, Key: KeyFingerprint(pub)}
	if err = tx.Commit(); err != nil {
		return CheckpointResult{}, fmt.Errorf("audit checkpoint: %w", err)
	}
	return res, nil
}

// verifyCheckpoint checks a checkpoint entry: it must cover exactly the
// entry before it, carry a valid signature, use the same key as earlier
// checkpoints and – if pinned – the expected key.
func verifyCheckpoint(scope string, row auditdb.AuditEntry, r *Report, pinned string) string {
	var d checkpointDetails
	if err := json.Unmarshal([]byte(row.DetailsJson), &d); err != nil {
		return "checkpoint unreadable"
	}
	if d.CoversSeq != row.Seq-1 || d.CoversHash != row.PrevHash {
		return "checkpoint does not cover the entry before it"
	}
	pub, err := hex.DecodeString(d.PublicKey)
	sig, err2 := hex.DecodeString(d.Signature)
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize {
		return "checkpoint key or signature malformed"
	}
	if !ed25519.Verify(pub, checkpointMessage(scope, d.CoversSeq, d.CoversHash, row.Time), sig) {
		return "checkpoint signature invalid"
	}
	fp := KeyFingerprint(pub)
	switch {
	case r.CheckpointKey == "":
		r.CheckpointKey = fp
	case r.CheckpointKey != fp:
		return "checkpoint signed by another key than the earlier ones"
	}
	if pinned != "" && !strings.HasPrefix(fp, strings.ToLower(pinned)) {
		return fmt.Sprintf("checkpoint key %s… is not the expected key %s…", fp[:16], pinned)
	}
	r.Checkpoints++
	r.LastCheckpoint = &CheckpointInfo{Seq: row.Seq, Time: row.Time}
	return ""
}

// CheckpointLog is one audit log the Checkpointer signs.
type CheckpointLog struct {
	DB    *sql.DB // writer of the audit log
	Scope string
}

// Checkpointer makes checkpoints for several logs. The server calls MakeAll
// after unseal, before seal and daily, and MaybeEvery after deliveries.
type Checkpointer struct {
	Logs   []CheckpointLog
	Signer Signer
	Clock  clock.Clock
	Log    *slog.Logger
	Every  int64 // 0 = CheckpointEvery
}

// MakeAll makes a checkpoint in every log that has new entries. A sealed
// keyring is not an error: there is just no checkpoint.
func (c *Checkpointer) MakeAll(ctx context.Context, reason string) error {
	var errs []error
	for _, l := range c.Logs {
		if err := c.make(ctx, l, reason); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// MaybeEvery makes a checkpoint in every log with at least CheckpointEvery
// entries since its last checkpoint.
func (c *Checkpointer) MaybeEvery(ctx context.Context) error {
	var errs []error
	for _, l := range c.Logs {
		q := auditdb.New(l.DB)
		head, err := q.GetHead(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		last, err := q.GetLastCheckpointSeq(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			errs = append(errs, err)
			continue
		}
		every := c.Every
		if every <= 0 {
			every = CheckpointEvery
		}
		if head.Seq-last >= every {
			if err := c.make(ctx, l, "every "+strconv.FormatInt(every, 10)+" entries"); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Checkpointer) make(ctx context.Context, l CheckpointLog, reason string) error {
	res, err := Checkpoint(ctx, l.DB, l.Scope, c.Signer, c.Clock.Now())
	switch {
	case errors.Is(err, ErrNoSigner):
		return nil // sealed: no checkpoint possible
	case err != nil:
		return fmt.Errorf("checkpoint %s: %w", l.Scope, err)
	case res.Made:
		// The process log line is an anchor outside the database file.
		c.Log.InfoContext(ctx, "audit checkpoint", slog.String("scope", l.Scope), slog.String("reason", reason),
			slog.String("head", res.Head.String()), slog.String("key", res.Key))
	}
	return nil
}
