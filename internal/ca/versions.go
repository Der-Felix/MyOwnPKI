package ca

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// ChangeOptions are the optional extras of a change to a versioned object
// (PHASE3 section 16, step 62). The zero value is the behavior of the
// released API: no concurrency check, no reason.
type ChangeOptions struct {
	// ExpectedVersion, when set, is the version number the caller based the
	// change on (the ETag it read; 0 = the object has no history yet). When
	// it is not the newest version, nothing is written and the change
	// returns an error that matches settingsver.ErrConflict.
	ExpectedVersion *int64
	// Reason is optional free text for the history (at most
	// settingsver.MaxReason characters, no control characters). It is kept
	// with the version and never goes to the audit log.
	Reason string
	// restore is set only by RestoreDomain: the change is then a restore of a
	// version of the domain, run through the ordinary writer.
	restore *restoreOf
}

// restoreOf says that a change is the restore of a stored version.
type restoreOf struct {
	from int64  // the version that is copied
	id   string // the domain ID (a deleted domain is created again under it)
	dry  bool   // check everything, write nothing (DomainRestoreCheck)
}

// domainSnapshot is the versioned state of a domain: the settings, the CA by
// ID (a CA rename is no change of the domain), never the timestamps.
func domainSnapshot(d *Domain) settingsver.DomainSnapshot {
	ranges := make([]string, 0, len(d.IPRanges))
	for _, r := range d.IPRanges {
		ranges = append(ranges, r.String())
	}
	return settingsver.DomainSnapshot{
		Name: d.Name, CAID: d.CAID, IncludeSubdomains: d.IncludeSubdomains, Wildcards: d.Wildcards,
		ChallengeTypes: slices.Clone(d.ChallengeTypes), Approval: d.Approval, Preset: d.Preset,
		ValidityDays: d.ValidityDays, AddressPolicy: d.AddressPolicy, IPRanges: ranges,
	}
}

// versionActor is the actor of a version, taken from the audit actor of the
// request (the same person or token the audit entry names).
func versionActor(who keys.Who) settingsver.Actor {
	return settingsver.Actor{Type: string(who.Actor.Type), ID: who.Actor.ID, Name: who.Actor.Name}
}

// recordDomain writes the version of a domain change inside the change's
// transaction (Append checks the expected version again and writes the
// baseline of a domain that has no history) and adds "version" and
// "snapshot_sha256" to the audit details, so the audit entry names the
// version it belongs to. The reason is not added: it is free text.
func recordDomain(ctx context.Context, q *pkidb.Queries, entry settingsver.Entry, details map[string]any) (settingsver.Result, error) {
	res, err := settingsver.Append(ctx, settingsver.PKIBackend(q), entry)
	if err != nil {
		return res, err
	}
	details["version"] = res.Version.Number
	details["snapshot_sha256"] = res.Version.SHA256
	return res, nil
}

// domainBefore reads the domain as it is inside the writer's transaction: the
// state a history starts from (the baseline), and the proof that the domain
// still exists (another request may have deleted it since the caller loaded
// it). The CA name is not needed for a snapshot and stays empty.
func domainBefore(ctx context.Context, q *pkidb.Queries, id string) (*Domain, error) {
	r, err := q.GetDomain(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return domainFromRow(r, "")
}

// DomainVersion returns the newest version number of a domain, the number
// of its ETag: 0 when it has no history yet. A domain the caller may not
// read is ErrNotFound, as for GetDomain.
func (e *Engine) DomainVersion(ctx context.Context, who keys.Who, id string) (int64, error) {
	q := pkidb.New(e.PKI)
	if _, err := e.loadDomain(ctx, q, who, id); err != nil {
		return 0, err
	}
	return settingsver.Current(ctx, settingsver.PKIBackend(q), settingsver.KindDomain, id)
}
