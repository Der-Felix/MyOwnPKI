package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
)

// Domain separation: these prefixes make the hashes of this log useless
// anywhere else, and a new format would get a new version string.
const (
	hashVersion   = "MYOWNPKI-AUDIT-V1"
	genesisPrefix = "MYOWNPKI-AUDIT-GENESIS"
)

// Genesis is prev_hash of the first entry of the log of scope. Binding the
// start to the scope means a log can't be passed off as another scope's log.
func Genesis(scope string) string {
	return hashFields(genesisPrefix, scope)
}

// entryHash is SHA-256 over the version, prev_hash and every column, each
// prefixed with its length: moving bytes from one field to the next always
// changes the hash, which plain concatenation or JSON would not guarantee.
func entryHash(r auditdb.AuditEntry) string {
	return hashFields(hashVersion,
		r.PrevHash,
		strconv.FormatInt(r.Seq, 10),
		r.OutboxID.String, // "" for direct entries
		r.Time,
		r.ActorType, r.ActorID, r.ActorName,
		r.Action,
		r.TargetType, r.TargetID,
		r.Result,
		r.SourceIp,
		r.DetailsJson,
	)
}

func hashFields(fields ...string) string {
	h := sha256.New()
	var n [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Append adds e to the log of scope in its own transaction and returns its
// seq. db must be the log's single writer connection. With a non-empty
// outboxID an entry that is already in the log is not added again: then
// Append returns its existing seq and appended=false.
func Append(ctx context.Context, db *sql.DB, scope string, e Entry, outboxID string) (seq int64, appended bool, err error) {
	details, err := e.validate()
	if err != nil {
		return 0, false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("audit append: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	q := auditdb.New(tx)

	if outboxID != "" {
		n, cerr := q.CountOutboxID(ctx, sql.NullString{String: outboxID, Valid: true})
		if cerr != nil {
			return 0, false, fmt.Errorf("audit append: %w", cerr)
		}
		if n > 0 {
			return 0, false, tx.Commit() // delivered before – nothing to do
		}
	}

	prev, last := Genesis(scope), int64(0)
	head, err := q.GetHead(ctx)
	switch {
	case err == nil:
		prev, last = head.Hash, head.Seq
	case !errors.Is(err, sql.ErrNoRows):
		return 0, false, fmt.Errorf("audit append: %w", err)
	}

	row := auditdb.AuditEntry{
		Seq:         last + 1,
		OutboxID:    sql.NullString{String: outboxID, Valid: outboxID != ""},
		Time:        e.Time.UTC().Format(TimeFormat),
		ActorType:   string(e.Actor.Type),
		ActorID:     e.Actor.ID,
		ActorName:   e.Actor.Name,
		Action:      e.Action,
		TargetType:  e.Target.Type,
		TargetID:    e.Target.ID,
		Result:      string(e.Result),
		SourceIp:    e.SourceIP,
		DetailsJson: details,
		PrevHash:    prev,
	}
	row.Hash = entryHash(row)
	if err = q.InsertEntry(ctx, auditdb.InsertEntryParams(row)); err != nil {
		return 0, false, fmt.Errorf("audit append: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("audit append: %w", err)
	}
	return row.Seq, true, nil
}

// Head identifies the newest entry of a chain: "seq:hash".
type Head struct {
	Seq  int64
	Hash string
}

func (h Head) String() string { return strconv.FormatInt(h.Seq, 10) + ":" + h.Hash }

var headPattern = regexp.MustCompile(`^([0-9]+):([0-9a-f]{12,64})$`)

// ParseHead reads "seq:hash"; a hash prefix of at least 12 hex digits is
// enough, so a head can be noted down by hand.
func ParseHead(s string) (Head, error) {
	m := headPattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return Head{}, fmt.Errorf("head %q: want SEQ:HASH with at least 12 hex digits of the hash", s)
	}
	seq, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || seq < 1 {
		return Head{}, fmt.Errorf("head %q: seq must be a positive number", s)
	}
	return Head{Seq: seq, Hash: m[2]}, nil
}

// Break describes the first entry where a chain doesn't hold.
type Break struct {
	Seq    int64
	Reason string
}

// Report is the result of Verify.
type Report struct {
	Entries int64
	Head    Head   // Seq 0 = empty log
	Break   *Break // nil = intact
}

const verifyBatch = 500

// Verify walks the whole log of scope and reports the first broken entry:
// a gap in seq (deleted entry), a prev_hash that doesn't match the previous
// entry (deleted, inserted or reordered entries) or a hash that doesn't match
// the entry's content (modified entry). It only reads.
func Verify(ctx context.Context, q auditdb.DBTX, scope string) (Report, error) {
	r := Report{Head: Head{Hash: Genesis(scope)}}
	queries := auditdb.New(q)
	next := int64(1)
	for {
		rows, err := queries.ListEntriesFrom(ctx, auditdb.ListEntriesFromParams{Seq: next, Limit: verifyBatch})
		if err != nil {
			return r, fmt.Errorf("audit verify: %w", err)
		}
		for _, row := range rows {
			switch {
			case row.Seq != next:
				r.Break = &Break{Seq: next, Reason: fmt.Sprintf("entry missing (gap: the next entry is seq %d)", row.Seq)}
			case row.PrevHash != r.Head.Hash:
				r.Break = &Break{Seq: row.Seq, Reason: "link broken (prev_hash does not match the previous entry)"}
			case entryHash(row) != row.Hash:
				r.Break = &Break{Seq: row.Seq, Reason: "entry modified (hash mismatch)"}
			}
			if r.Break != nil {
				return r, nil
			}
			r.Entries++
			r.Head = Head{Seq: row.Seq, Hash: row.Hash}
			next++
		}
		if len(rows) < verifyBatch {
			return r, nil
		}
	}
}

// CheckHead compares the log with a head noted earlier (process log, backup
// manifest): the entry at that seq must still exist and have that hash.
// This catches what the chain alone can't – a cut-off end, or a chain that
// was recomputed from that entry on.
func CheckHead(ctx context.Context, q auditdb.DBTX, want Head) error {
	got, err := auditdb.New(q).GetEntry(ctx, want.Seq)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("the log ends before seq %d – entries were cut off", want.Seq)
	case err != nil:
		return fmt.Errorf("check head: %w", err)
	case !strings.HasPrefix(got.Hash, want.Hash):
		return fmt.Errorf("entry %d has hash %s…, expected %s… – the log was rewritten", want.Seq, got.Hash[:12], want.Hash[:12])
	}
	return nil
}
