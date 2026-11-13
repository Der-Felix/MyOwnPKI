package settingsver

import (
	"reflect"
	"testing"
)

func baseDomain() DomainSnapshot {
	return DomainSnapshot{
		Name: "homelab.example", CAID: "ca_1", IncludeSubdomains: true,
		ChallengeTypes: []string{"http-01", "dns-01"}, Approval: "account", Preset: "server",
		AddressPolicy: "internal", IPRanges: []string{},
	}
}

func baseTenant() TenantSnapshot {
	return TenantSnapshot{
		AllowServerKeygen: true, ACME: ACMELimitsSnapshot{OrdersPerAccount: 300, FailedPerName: 5, AccountsPerIP: 10},
		TrustPage: true, AgentEnrollment: "verified", StepUpMinutes: 5,
		AgentPredecessor: PredecessorSnapshot{Choice: "now", Days: 7}, OtherPredecessor: PredecessorSnapshot{Choice: "after", Days: 7},
	}
}

func TestDiffDomain(t *testing.T) {
	t.Parallel()
	mod := func(f func(*DomainSnapshot)) DomainSnapshot { d := baseDomain(); f(&d); return d }
	for _, tc := range []struct {
		name string
		a, b Snapshot
		want []FieldChange
	}{
		{"identical", baseDomain(), baseDomain(), nil},
		{"scalar changed", baseDomain(), mod(func(d *DomainSnapshot) { d.Approval = "open" }),
			[]FieldChange{{Key: "approval", Label: "Approval", Before: []string{"account"}, After: []string{"open"}, Kind: Changed}}},
		{"bool changed", baseDomain(), mod(func(d *DomainSnapshot) { d.Wildcards = true }),
			[]FieldChange{{Key: "wildcards", Label: "Wildcards", Before: []string{"no"}, After: []string{"yes"}, Kind: Changed}}},
		{"unset to set is added", baseDomain(), mod(func(d *DomainSnapshot) { d.ValidityDays = 30 }),
			[]FieldChange{{Key: "validity_days", Label: "Validity in days", Before: nil, After: []string{"30"}, Kind: Added}}},
		{"set to unset is removed", mod(func(d *DomainSnapshot) { d.ValidityDays = 30 }), baseDomain(),
			[]FieldChange{{Key: "validity_days", Label: "Validity in days", Before: []string{"30"}, After: nil, Kind: Removed}}},
		{"list shrinks", baseDomain(), mod(func(d *DomainSnapshot) { d.ChallengeTypes = []string{"dns-01"} }),
			[]FieldChange{{Key: "challenge_types", Label: "Challenge types", Before: []string{"http-01", "dns-01"}, After: []string{"dns-01"}, Kind: Changed}}},
		{"list reordered is no change", baseDomain(), mod(func(d *DomainSnapshot) { d.ChallengeTypes = []string{"dns-01", "http-01"} }), nil},
		{"list duplicates are no change", baseDomain(), mod(func(d *DomainSnapshot) { d.ChallengeTypes = []string{"dns-01", "http-01", "dns-01"} }), nil},
		{"nil list equals empty list", mod(func(d *DomainSnapshot) { d.IPRanges = nil }), baseDomain(), nil},
		{"list added", baseDomain(), mod(func(d *DomainSnapshot) { d.IPRanges = []string{"192.0.2.0/24"} }),
			[]FieldChange{{Key: "ip_ranges", Label: "IP ranges", Before: nil, After: []string{"192.0.2.0/24"}, Kind: Added}}},
		{"list removed", mod(func(d *DomainSnapshot) { d.IPRanges = []string{"192.0.2.0/24", "198.51.100.0/24"} }), baseDomain(),
			[]FieldChange{{Key: "ip_ranges", Label: "IP ranges", Before: []string{"192.0.2.0/24", "198.51.100.0/24"}, After: nil, Kind: Removed}}},
		{"several, in field order", baseDomain(), mod(func(d *DomainSnapshot) { d.Preset = "client"; d.Name = "lab.example"; d.CAID = "ca_2" }),
			[]FieldChange{
				{Key: "name", Label: "Domain name", Before: []string{"homelab.example"}, After: []string{"lab.example"}, Kind: Changed},
				{Key: "ca_id", Label: "CA", Before: []string{"ca_1"}, After: []string{"ca_2"}, Kind: Changed},
				{Key: "preset", Label: "Preset", Before: []string{"server"}, After: []string{"client"}, Kind: Changed},
			}},
		{"nothing before: every set field is added", nil, DomainSnapshot{Name: "a.example", CAID: "ca_1", Approval: "open", Preset: "server", AddressPolicy: "internal"},
			[]FieldChange{
				{Key: "name", Label: "Domain name", After: []string{"a.example"}, Kind: Added},
				{Key: "ca_id", Label: "CA", After: []string{"ca_1"}, Kind: Added},
				{Key: "include_subdomains", Label: "Include subdomains", After: []string{"no"}, Kind: Added},
				{Key: "wildcards", Label: "Wildcards", After: []string{"no"}, Kind: Added},
				{Key: "approval", Label: "Approval", After: []string{"open"}, Kind: Added},
				{Key: "preset", Label: "Preset", After: []string{"server"}, Kind: Added},
				{Key: "address_policy", Label: "Address policy", After: []string{"internal"}, Kind: Added},
			}},
		{"nothing after: every set field is removed", DomainSnapshot{Name: "a.example"}, nil,
			[]FieldChange{
				{Key: "name", Label: "Domain name", Before: []string{"a.example"}, Kind: Removed},
				{Key: "include_subdomains", Label: "Include subdomains", Before: []string{"no"}, Kind: Removed},
				{Key: "wildcards", Label: "Wildcards", Before: []string{"no"}, Kind: Removed},
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Diff(tc.a, tc.b)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Diff:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestDiffTenantNestedFields(t *testing.T) {
	t.Parallel()
	b := baseTenant()
	b.ACME.OrdersPerAccount = 50
	b.AgentPredecessor = PredecessorSnapshot{Choice: "after", Days: 14}
	b.Country = "DE"
	b.AllowServerKeygen = false
	got := Diff(baseTenant(), b)
	want := []FieldChange{
		{Key: "allow_server_keygen", Label: "Server may generate keys", Before: []string{"yes"}, After: []string{"no"}, Kind: Changed},
		{Key: "country", Label: "Country (C)", After: []string{"DE"}, Kind: Added},
		{Key: "acme.orders_per_account", Label: "ACME: orders per account and hour", Before: []string{"300"}, After: []string{"50"}, Kind: Changed},
		{Key: "agent_predecessor.choice", Label: "Agent renewals: old certificate", Before: []string{"now"}, After: []string{"after"}, Kind: Changed},
		{Key: "agent_predecessor.days", Label: "Agent renewals: days to keep it", Before: []string{"7"}, After: []string{"14"}, Kind: Changed},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff:\n got %+v\nwant %+v", got, want)
	}
	if d := Diff(baseTenant(), baseTenant()); len(d) != 0 {
		t.Errorf("identical tenant snapshots differ: %+v", d)
	}
}

// Fields only one side has (a future schema, or two kinds) come out as added
// and removed; the diff never fails.
func TestDiffFieldsOnlyOneSideHas(t *testing.T) {
	t.Parallel()
	got := Diff(DomainSnapshot{Name: "a.example"}, TenantSnapshot{Organization: "Lab"})
	var removed, added int
	for _, c := range got {
		switch c.Kind {
		case Removed:
			removed++
		case Added:
			added++
		}
	}
	if removed == 0 || added == 0 || removed+added != len(got) {
		t.Errorf("want only added and removed changes, got %+v", got)
	}
}

// The diff does not copy hostile text anywhere but into the values: no
// formatting, no escaping, no truncation (whoever renders it escapes).
func TestDiffKeepsHostileValuesAsData(t *testing.T) {
	t.Parallel()
	hostile := `<script>alert(1)</script>'; DROP TABLE domains;-- {{.}} %s ` + "\n\x00" + string(rune(0x202e))
	a, b := baseTenant(), baseTenant()
	b.Organization = hostile
	got := Diff(a, b)
	if len(got) != 1 || got[0].Kind != Added || len(got[0].After) != 1 || got[0].After[0] != hostile {
		t.Errorf("Diff = %+v", got)
	}
}

func TestDiffDoesNotAliasItsInputs(t *testing.T) {
	t.Parallel()
	a, b := baseDomain(), baseDomain()
	b.ChallengeTypes = []string{"dns-01"}
	got := Diff(a, b)
	got[0].Before[0] = "changed"
	if a.ChallengeTypes[0] != "http-01" {
		t.Error("the diff shares memory with the snapshot")
	}
}
