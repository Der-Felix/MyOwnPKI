package settingsver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// SchemaVersion is the schema number of every snapshot type in this build.
// A changed field list gets number 2 and a decoder for both; old rows keep
// their number, so they stay readable.
const SchemaVersion = 1

// Snapshot is the full state of one versioned object. It is a closed
// interface (unexported method): only the types in this package are
// snapshots, and each is an explicit struct with a fixed field list, never a
// map and never a copy of a table row. That makes "a secret cannot enter a
// snapshot" a property of the type; TestSnapshotsHaveNoSecrets and
// TestEveryColumnIsClassified keep it true when a field or column is added.
type Snapshot interface {
	// Kind is KindDomain or KindTenant.
	Kind() string
	// SchemaVersion is the number stored next to the snapshot.
	SchemaVersion() int
	// Fields lists every field for Diff and for display, in display order.
	Fields() []Field
	// normalized returns a copy in canonical form (nil lists become empty).
	normalized() Snapshot
}

// Field is one setting of a snapshot as the UI shows it. Values is the field's
// value as text; a list has one entry per element, and a field that is unset
// (an empty string, the default validity) has none.
type Field struct {
	Key    string // stable machine name, "acme.orders_per_account"
	Label  string // what an admin reads
	Values []string
}

// DomainSnapshot is the state of a domain (table domains of pki.db). The ID
// is the object ID and the timestamps are not settings, so neither is part of
// it.
type DomainSnapshot struct {
	Name              string   `json:"name"`
	CAID              string   `json:"ca_id"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	Wildcards         bool     `json:"wildcards"`
	ChallengeTypes    []string `json:"challenge_types"`
	Approval          string   `json:"approval"`
	Preset            string   `json:"preset"`
	ValidityDays      int      `json:"validity_days"` // 0 = the default
	AddressPolicy     string   `json:"address_policy"`
	IPRanges          []string `json:"ip_ranges"`
}

// ACMELimitsSnapshot are the ACME rate limits of a tenant, per hour.
type ACMELimitsSnapshot struct {
	OrdersPerAccount int `json:"orders_per_account"`
	FailedPerName    int `json:"failed_per_name"`
	AccountsPerIP    int `json:"accounts_per_ip"`
}

// PredecessorSnapshot is a default for the old certificate on renewal.
type PredecessorSnapshot struct {
	Choice string `json:"choice"`
	Days   int    `json:"days"`
}

// TenantSnapshot is the state of a tenant's settings (the setting columns of
// the table tenants in system.db). Identity, name and creation time are not
// part of it.
type TenantSnapshot struct {
	AllowServerKeygen  bool                `json:"allow_server_keygen"`
	Organization       string              `json:"organization"`
	OrganizationalUnit string              `json:"organizational_unit"`
	Locality           string              `json:"locality"`
	State              string              `json:"state"`
	Country            string              `json:"country"`
	ACME               ACMELimitsSnapshot  `json:"acme"`
	TrustPage          bool                `json:"trust_page"`
	AgentEnrollment    string              `json:"agent_enrollment"`
	StepUpMinutes      int                 `json:"step_up_minutes"`
	AgentPredecessor   PredecessorSnapshot `json:"agent_predecessor"`
	OtherPredecessor   PredecessorSnapshot `json:"other_predecessor"`
}

// Kind implements Snapshot.
func (DomainSnapshot) Kind() string { return KindDomain }

// SchemaVersion implements Snapshot.
func (DomainSnapshot) SchemaVersion() int { return SchemaVersion }

func (s DomainSnapshot) normalized() Snapshot {
	if s.ChallengeTypes == nil {
		s.ChallengeTypes = []string{}
	}
	if s.IPRanges == nil {
		s.IPRanges = []string{}
	}
	return s
}

// Fields implements Snapshot.
func (s DomainSnapshot) Fields() []Field {
	validity := ""
	if s.ValidityDays > 0 {
		validity = strconv.Itoa(s.ValidityDays)
	}
	return []Field{
		scalar("name", "Domain name", s.Name),
		scalar("ca_id", "CA", s.CAID),
		scalar("include_subdomains", "Include subdomains", yesNo(s.IncludeSubdomains)),
		scalar("wildcards", "Wildcards", yesNo(s.Wildcards)),
		{Key: "challenge_types", Label: "Challenge types", Values: cloneValues(s.ChallengeTypes)},
		scalar("approval", "Approval", s.Approval),
		scalar("preset", "Preset", s.Preset),
		scalar("validity_days", "Validity in days", validity),
		scalar("address_policy", "Address policy", s.AddressPolicy),
		{Key: "ip_ranges", Label: "IP ranges", Values: cloneValues(s.IPRanges)},
	}
}

// Kind implements Snapshot.
func (TenantSnapshot) Kind() string { return KindTenant }

// SchemaVersion implements Snapshot.
func (TenantSnapshot) SchemaVersion() int { return SchemaVersion }

func (s TenantSnapshot) normalized() Snapshot { return s }

// Fields implements Snapshot.
func (s TenantSnapshot) Fields() []Field {
	return []Field{
		scalar("allow_server_keygen", "Server may generate keys", yesNo(s.AllowServerKeygen)),
		scalar("organization", "Organization (O)", s.Organization),
		scalar("organizational_unit", "Organizational unit (OU)", s.OrganizationalUnit),
		scalar("locality", "Locality (L)", s.Locality),
		scalar("state", "State (ST)", s.State),
		scalar("country", "Country (C)", s.Country),
		scalar("acme.orders_per_account", "ACME: orders per account and hour", strconv.Itoa(s.ACME.OrdersPerAccount)),
		scalar("acme.failed_per_name", "ACME: failed validations per name and hour", strconv.Itoa(s.ACME.FailedPerName)),
		scalar("acme.accounts_per_ip", "ACME: new accounts per address and hour", strconv.Itoa(s.ACME.AccountsPerIP)),
		scalar("trust_page", "Public trust page", yesNo(s.TrustPage)),
		scalar("agent_enrollment", "Agent enrollment", s.AgentEnrollment),
		scalar("step_up_minutes", "Second-factor proof lifetime in minutes", strconv.Itoa(s.StepUpMinutes)),
		scalar("agent_predecessor.choice", "Agent renewals: old certificate", s.AgentPredecessor.Choice),
		scalar("agent_predecessor.days", "Agent renewals: days to keep it", strconv.Itoa(s.AgentPredecessor.Days)),
		scalar("other_predecessor.choice", "Other renewals: old certificate", s.OtherPredecessor.Choice),
		scalar("other_predecessor.days", "Other renewals: days to keep it", strconv.Itoa(s.OtherPredecessor.Days)),
	}
}

// scalar is a Field with at most one value; an empty value means unset.
func scalar(key, label, value string) Field {
	f := Field{Key: key, Label: label}
	if value != "" {
		f.Values = []string{value}
	}
	return f
}

func cloneValues(v []string) []string { return append([]string(nil), v...) }

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Canonical returns the canonical JSON of s and its hex SHA-256: struct
// field order, nil lists as [], no HTML escaping, no trailing newline. The
// same state always gives the same bytes, which is what the hash and the
// audit entries rely on.
func Canonical(s Snapshot) ([]byte, string, error) {
	if s == nil {
		return nil, "", fmt.Errorf("%w: no snapshot", ErrInvalid)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s.normalized()); err != nil {
		return nil, "", fmt.Errorf("encode %s snapshot: %w", s.Kind(), err)
	}
	data := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(data) > MaxSnapshotBytes {
		return nil, "", fmt.Errorf("%w: snapshot is %d bytes, at most %d", ErrInvalid, len(data), MaxSnapshotBytes)
	}
	return data, hashHex(data), nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Decode parses stored snapshot JSON of a kind and schema. Unknown fields
// and trailing data are refused: a snapshot is exactly its closed type.
func Decode(kind string, schema int, data []byte) (Snapshot, error) {
	if schema != SchemaVersion {
		return nil, fmt.Errorf("%w: %d (this build reads %d)", ErrUnknownSchema, schema, SchemaVersion)
	}
	var out Snapshot
	var err error
	switch kind {
	case KindDomain:
		var s DomainSnapshot
		err = strictJSON(data, &s)
		out = s.normalized()
	case KindTenant:
		var s TenantSnapshot
		err = strictJSON(data, &s)
		out = s
	default:
		return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s snapshot: %w", ErrCorrupt, kind, err)
	}
	return out, nil
}

func strictJSON(data []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the snapshot")
	}
	return nil
}

// Decoded parses the stored snapshot of v after checking its hash.
func (v Version) Decoded() (Snapshot, error) {
	if hashHex(v.Snapshot) != v.SHA256 {
		return nil, fmt.Errorf("%w: %s %s version %d does not match its hash", ErrCorrupt, v.Kind, v.ObjectID, v.Number)
	}
	return Decode(v.Kind, v.Schema, v.Snapshot)
}
