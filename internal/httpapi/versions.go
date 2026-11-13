package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
)

// Optimistic concurrency of the versioned objects (domains, tenant settings;
// PHASE3 section 16, step 62). The ETag of such an object is its newest
// version number as a quoted decimal ("7"; "0" = it has no history yet). A
// writer may send it back as If-Match; when it is not the newest version,
// the change is refused with 412 and nothing is written.

// etagPattern is the only If-Match value that is accepted: one ETag of this
// API, strong ("7") or weak (W/"7": a proxy that compresses the answer, nginx
// gzip, turns a strong ETag weak, and the client sends it back as it got it).
// A weak tag counts as the strong one. A list, "*" and anything else are
// refused as a bad request instead of being guessed at.
var etagPattern = regexp.MustCompile(`^(?:W/)?"([0-9]{1,15})"$`)

// ifMatch returns the version the caller expects, nil when the header is
// absent (the released behavior: the last writer wins).
func (c *call) ifMatch() (*int64, error) {
	values := c.r.Header.Values("If-Match")
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 1 {
		return nil, badRequest("If-Match", "send one ETag, as the ETag header of the last read gave it (for example \"7\")")
	}
	m := etagPattern.FindStringSubmatch(values[0])
	if m == nil {
		return nil, badRequest("If-Match", "not an ETag of this API: send the ETag header of the last read unchanged, for example \"7\"")
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return nil, badRequest("If-Match", "not an ETag of this API")
	}
	return &n, nil
}

// setETag sets the ETag header to a version number.
func (c *call) setETag(version int64) {
	c.w.Header().Set("ETag", `"`+strconv.FormatInt(version, 10)+`"`)
}

// preconditionDoc is the answer to a failed If-Match: the current version, so
// the caller can read the object again and decide.
type preconditionDoc struct {
	problemDoc
	CurrentVersion int64      `json:"current_version"`
	ChangedBy      string     `json:"changed_by,omitempty"`
	ChangedAt      *time.Time `json:"changed_at,omitempty"`
}

// preconditionFailed answers 412 for a settingsver.ConflictError and
// reports whether err was one.
func (c *call) preconditionFailed(err error) bool {
	var ce *settingsver.ConflictError
	if !errors.As(err, &ce) {
		return false
	}
	doc := preconditionDoc{
		problemDoc: problemDoc{
			Type: problemPrefix + "precondition-failed", Title: http.StatusText(http.StatusPreconditionFailed),
			Status: http.StatusPreconditionFailed, RequestID: c.reqID,
			Detail: "the object was changed after you read it (If-Match " + strconv.FormatInt(ce.Expected, 10) +
				", current version " + strconv.FormatInt(ce.Latest.Number, 10) + "); read it again and retry",
		},
		CurrentVersion: ce.Latest.Number,
	}
	if ce.Latest.Number > 0 {
		// Who changed it is personal data: only a caller with the tenant-wide
		// audit right (the one who may read the history) is told.
		if c.canReadAudit() {
			doc.ChangedBy = ce.Latest.Actor.Name
		}
		at := ce.Latest.CreatedAt.UTC()
		doc.ChangedAt = &at
	}
	c.status = http.StatusPreconditionFailed
	c.w.Header().Set("Content-Type", "application/problem+json")
	c.w.WriteHeader(http.StatusPreconditionFailed)
	_ = json.NewEncoder(c.w).Encode(doc)
	return true
}

// canReadAudit reports whether the caller holds the tenant-wide audit right,
// which decides whether names of other users may be shown to it.
func (c *call) canReadAudit() bool {
	if c.session == nil || c.session.Principal == nil {
		return false
	}
	return c.session.Principal.Check(authz.ReadAudit, authz.Resource{Tenant: c.api.d.Tenant}, c.api.now()) == nil
}
