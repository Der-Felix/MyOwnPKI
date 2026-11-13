package settingsver

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Kinds of versioned objects. The table does not restrict kind; Go does.
const (
	KindDomain = "domain" // pki.db, object ID = the domain ID
	KindTenant = "tenant" // system.db, object ID = the tenant ID
)

// Change says how a version came about.
const (
	ChangeCreate   = "create"
	ChangeUpdate   = "update"
	ChangeDelete   = "delete" // the snapshot is the deleted state
	ChangeRestore  = "restore"
	ChangeBaseline = "baseline" // the state before the first recorded change
)

// Actor types, the same set as the audit log.
const (
	ActorUser        = "user"
	ActorToken       = "token"
	ActorSystem      = "system"
	ActorACMEAccount = "acme_account"
	ActorAgent       = "agent"
)

// Limits.
const (
	// MaxReason is the longest reason, in characters (the schema checks it too).
	MaxReason = 200
	// MaxSnapshotBytes caps a snapshot; a domain with many IP ranges is far below.
	MaxSnapshotBytes = 64 << 10
	// DefaultListLimit and MaxListLimit bound List.
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// dbTime is the stored time format: UTC, whole seconds (as domains).
const dbTime = "2006-01-02T15:04:05Z"

var (
	// ErrNotFound: no such object history or version.
	ErrNotFound = errors.New("settings version not found")
	// ErrConflict: the object changed since the caller read it.
	ErrConflict = errors.New("settings changed since they were read")
	// ErrInvalid wraps every refused argument.
	ErrInvalid = errors.New("invalid settings version")
	// ErrUnknownSchema: a snapshot of a schema number this build does not know.
	ErrUnknownSchema = errors.New("unknown snapshot schema")
	// ErrCorrupt: a stored snapshot does not match its hash or its type.
	ErrCorrupt = errors.New("stored snapshot is damaged")
)

// ConflictError is ErrConflict with what the caller needs to say who
// changed the object and when (a 412 answer or a 409 page).
type ConflictError struct {
	Expected int64   // the number the caller based its change on (0 = none yet)
	Latest   Version // the newest version; zero Number when none exists
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%v: expected version %d, latest is %d", ErrConflict, e.Expected, e.Latest.Number)
}

// Is makes errors.Is(err, ErrConflict) true.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// Actor is who made a change. IDs and names are data (a user name can be
// anything an admin typed); they are stored and returned unchanged.
type Actor struct {
	Type string
	ID   string
	Name string
}

// BaselineActor is the actor of a baseline version.
var BaselineActor = Actor{Type: ActorSystem, Name: "system, before history"}

// Version is one row of settings_versions.
type Version struct {
	ID           int64
	Kind         string
	ObjectID     string
	Number       int64 // 1, 2, 3 ... per object, no gaps
	Change       string
	Schema       int
	Snapshot     []byte // canonical JSON of the snapshot
	SHA256       string // hex SHA-256 of Snapshot
	Actor        Actor
	Reason       string // free text: never goes into the audit log
	RestoredFrom int64  // 0 unless Change is ChangeRestore
	CreatedAt    time.Time
}

// Backend is the table of one database, bound to the caller's transaction
// (or to a read connection for reads). The two implementations are in
// backends.go.
type Backend interface {
	// Insert stores v (ID is assigned) and returns it as stored. A duplicate
	// (kind, object, number) returns ErrConflict.
	Insert(ctx context.Context, v Version) (Version, error)
	// Latest returns the newest version of an object, or ErrNotFound.
	Latest(ctx context.Context, kind, objectID string) (Version, error)
	// Get returns one version, or ErrNotFound.
	Get(ctx context.Context, kind, objectID string, number int64) (Version, error)
	// List returns up to limit versions, newest first; before = 0 starts at
	// the newest, otherwise below that number.
	List(ctx context.Context, kind, objectID string, before int64, limit int) ([]Version, error)
	// LatestOfKind returns the newest version of every object of a kind.
	LatestOfKind(ctx context.Context, kind string) ([]Version, error)
}
