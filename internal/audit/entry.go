// Package audit writes and verifies the hash-chained audit logs (PLAN §5,
// security.md "Audit log").
//
// There are two kinds of log: the instance log (<data>/audit.db: logins,
// users, unseal) and one per tenant. Entries that belong to a business change
// are written to the outbox of the same database in the same transaction
// (Enqueue) and delivered exactly once by the Deliverer; events without a
// business change (a failed login, a denied request) are appended directly
// (Append). Verify walks a chain and finds the first broken entry.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ErrInvalid is wrapped by every error about an entry that may not be logged.
var ErrInvalid = errors.New("invalid audit entry")

// TimeFormat is used for every time in the audit log and the outbox: UTC
// with milliseconds and a fixed width, so text order is time order.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// ActorType says who acted.
type ActorType string

// Actor types (CHECK constraint in schema/audit/0002).
const (
	ActorUser        ActorType = "user"
	ActorToken       ActorType = "token"
	ActorSystem      ActorType = "system"
	ActorACMEAccount ActorType = "acme_account"
	ActorAgent       ActorType = "agent"
)

var actorTypes = []ActorType{ActorUser, ActorToken, ActorSystem, ActorACMEAccount, ActorAgent}

// Result is the outcome of the action.
type Result string

// Results: denied = refused by policy or permissions, failure = attempted
// but failed (e.g. wrong password, signing error).
const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

var results = []Result{ResultSuccess, ResultFailure, ResultDenied}

// Actor is who acted. Name is what an auditor reads (user name, token name).
type Actor struct {
	Type ActorType
	ID   string
	Name string
}

// Target is the object acted on, e.g. {certificate c-0101}.
type Target struct {
	Type string
	ID   string
}

// Entry is one event before it gets a place in the chain.
type Entry struct {
	Time     time.Time
	Actor    Actor
	Action   string // dotted, e.g. "certificate.issue"
	Target   Target
	Result   Result
	SourceIP string         // IP address only (no port, no host name); "" if none
	Details  map[string]any // never secrets – see forbiddenKey
}

var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

const (
	maxField   = 256
	maxDetails = 8 << 10
)

// forbiddenKey reports detail keys that suggest a secret. Callers must never
// log secrets; this is the second line of defense (security.md).
func forbiddenKey(key string) bool {
	k := strings.ToLower(key)
	for _, word := range []string{"password", "passphrase", "secret", "private", "credential"} {
		if strings.Contains(k, word) {
			return true
		}
	}
	return k == "token" || k == "pin" || k == "otp" || k == "totp_code" || k == "recovery_code"
}

// validate checks e and returns its details as JSON (keys sorted, so the same
// details always give the same text).
func (e Entry) validate() (string, error) {
	var problems []string
	if e.Time.IsZero() {
		problems = append(problems, "time is missing")
	}
	if !slices.Contains(actorTypes, e.Actor.Type) {
		problems = append(problems, fmt.Sprintf("unknown actor type %q", e.Actor.Type))
	}
	if e.Actor.Name == "" {
		problems = append(problems, "actor name is missing")
	}
	if len(e.Action) > 64 || !actionPattern.MatchString(e.Action) {
		problems = append(problems, fmt.Sprintf("action %q: want lower-case dotted words like certificate.issue", e.Action))
	}
	if !slices.Contains(results, e.Result) {
		problems = append(problems, fmt.Sprintf("unknown result %q", e.Result))
	}
	if e.SourceIP != "" {
		if _, err := netip.ParseAddr(e.SourceIP); err != nil {
			problems = append(problems, fmt.Sprintf("source IP %q is not an IP address", e.SourceIP))
		}
	}
	for name, v := range map[string]string{
		"actor id": e.Actor.ID, "actor name": e.Actor.Name, "target type": e.Target.Type, "target id": e.Target.ID,
	} {
		if len(v) > maxField {
			problems = append(problems, fmt.Sprintf("%s is longer than %d bytes", name, maxField))
		}
	}
	if key := findForbidden(e.Details); key != "" {
		problems = append(problems, fmt.Sprintf("details key %q looks like a secret – secrets are never logged", key))
	}
	details := []byte("{}")
	if len(e.Details) > 0 {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			problems = append(problems, "details: "+err.Error())
		} else if len(details) > maxDetails {
			problems = append(problems, fmt.Sprintf("details are larger than %d bytes", maxDetails))
		}
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return string(details), nil
}

// findForbidden returns the first secret-looking key, also in nested maps and lists.
func findForbidden(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for k, inner := range t {
			if forbiddenKey(k) {
				return k
			}
			if bad := findForbidden(inner); bad != "" {
				return bad
			}
		}
	case []any:
		for _, inner := range t {
			if bad := findForbidden(inner); bad != "" {
				return bad
			}
		}
	}
	return ""
}
