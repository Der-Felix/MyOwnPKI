package ca

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Bounds of a domain's snapshot: the IP range cap, and domains stored before
// it existed (release 0.3.10, review).

// longRanges are n IPv6 host ranges of the longest text form (43 characters).
func longRanges(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("1111:2222:3333:4444:5555:6666:7777:%04x/128", 0x1000+i))
	}
	return out
}

// oversizedDomain stores a domain with more IP ranges than the cap and
// without a history, as an older release could (it had no cap).
func (v *env) oversizedDomain(t *testing.T, name string, ranges int) *Domain {
	t.Helper()
	d := v.legacyDomain(t, name)
	for _, r := range longRanges(ranges) {
		d.IPRanges = append(d.IPRanges, netip.MustParsePrefix(r))
	}
	row := domainRow(d)
	if err := pkidb.New(v.pki).UpdateDomain(t.Context(), pkidb.UpdateDomainParams{
		CaID: row.CaID, IncludeSubdomains: row.IncludeSubdomains, Wildcards: row.Wildcards, ChallengeTypes: row.ChallengeTypes,
		Approval: row.Approval, Preset: row.Preset, ValidityDays: row.ValidityDays, AddressPolicy: row.AddressPolicy,
		IpRanges: row.IpRanges, UpdatedAt: row.UpdatedAt, ID: d.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalSize(domainSnapshot(d)); err == nil {
		t.Fatalf("%d ranges fit in a snapshot, the test needs more", ranges)
	}
	return d
}

func canonicalSize(s settingsver.Snapshot) (int, error) {
	data, _, err := settingsver.Canonical(s)
	return len(data), err
}

func TestDomainIPRangeCap(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	ca := ptr("open")

	if _, err := v.e.CreateDomain(ctx, DomainRequest{Name: "big.lan", DomainSettings: DomainSettings{CA: ca, IPRanges: longRanges(MaxDomainIPRanges + 1)}, Who: tester}); !deniedWith(err, "at most 256 IP ranges") {
		t.Fatalf("257 ranges: %v, want a policy refusal", err)
	}
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "big.lan", DomainSettings: DomainSettings{CA: ca, IPRanges: longRanges(MaxDomainIPRanges)}, Who: tester})
	if err != nil {
		t.Fatalf("256 ranges of the longest form: %v", err)
	}
	// The cap keeps the worst case far below the snapshot limit.
	n, err := canonicalSize(domainSnapshot(d))
	if err != nil || n > settingsver.MaxSnapshotBytes/4 {
		t.Errorf("worst-case snapshot: %d bytes, %v", n, err)
	}
	// The audit entry (at most 8 KiB of details) shows the first ranges and counts the rest.
	if got, _ := v.auditFor(t, ActionDomainCreate, d.ID)["ip_ranges"].(string); !strings.HasSuffix(got, "… and 240 more") {
		t.Errorf("audit ip_ranges ends in %q", got[max(0, len(got)-30):])
	}
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{IPRanges: longRanges(MaxDomainIPRanges + 1)}, tester); !deniedWith(err, "at most 256 IP ranges") {
		t.Errorf("update to 257 ranges: %v", err)
	}
	if err := v.e.DeleteDomain(ctx, d.ID, tester); err != nil {
		t.Errorf("delete of a domain with the most ranges: %v", err)
	}
}

func TestOversizedDomainCanBeDeleted(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.oversizedDomain(t, "huge.lan", 2000)

	if err := v.e.DeleteDomain(ctx, d.ID, tester); err != nil {
		t.Fatalf("delete of an oversized domain: %v", err)
	}
	hist := v.domainHistory(t, d.ID)
	if len(hist) != 2 || hist[0].Change != settingsver.ChangeBaseline || hist[1].Change != settingsver.ChangeDelete {
		t.Fatalf("history: %+v", hist)
	}
	for _, ver := range hist {
		if snap := snapshotOf(t, ver); snap.Name != "huge.lan" || len(snap.IPRanges) != MaxDomainIPRanges {
			t.Errorf("version %d keeps %q with %d ranges, want the name and %d ranges", ver.Number, snap.Name, len(snap.IPRanges), MaxDomainIPRanges)
		}
	}
	details := v.auditFor(t, ActionDomainDelete, d.ID)
	if details["history_ip_ranges_kept"] != float64(MaxDomainIPRanges) || details["ip_ranges_total"] != float64(2000) {
		t.Errorf("the audit entry does not say the history was cut: %v", details)
	}
}

func TestOversizedDomainCanBeTrimmed(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.oversizedDomain(t, "huge.lan", 2000)

	// Any other change is refused with the reason until the list is short enough.
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); !deniedWith(err, "at most 256 IP ranges (this one has 2000)") {
		t.Fatalf("update without trimming: %v", err)
	}
	trimmed, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{IPRanges: longRanges(3)}, tester)
	if err != nil || len(trimmed.IPRanges) != 3 {
		t.Fatalf("trim: %+v %v", trimmed, err)
	}
	hist := v.domainHistory(t, d.ID)
	if len(hist) != 2 || hist[0].Change != settingsver.ChangeBaseline || len(snapshotOf(t, hist[0]).IPRanges) != MaxDomainIPRanges {
		t.Errorf("history after the trim: %+v", hist)
	}
}

// A concurrent create of the same name hits UNIQUE inside the transaction: the
// answer is the refusal of the name check, not an internal error.
func TestDomainCreateRaceIsARefusal(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	if _, err := v.pki.ExecContext(t.Context(), `CREATE TRIGGER test_race BEFORE INSERT ON domains WHEN NEW.name = 'race.lan' AND NEW.id <> 'dom-racer' BEGIN
		INSERT INTO domains (id, name, ca_id, include_subdomains, wildcards, challenge_types, approval, preset, validity_days, address_policy, ip_ranges, created_at, updated_at)
		VALUES ('dom-racer', NEW.name, NEW.ca_id, 1, 0, '["http-01"]', 'account', 'server', NULL, 'internal', '[]', NEW.created_at, NEW.updated_at);
	END`); err != nil {
		t.Fatal(err)
	}
	_, err := v.e.CreateDomain(t.Context(), DomainRequest{Name: "race.lan", DomainSettings: DomainSettings{CA: ptr("open")}, Who: tester})
	if !deniedWith(err, `domain "race.lan" exists already`) {
		t.Fatalf("create that lost the race: %v", err)
	}
}

func TestDomainRestoreNeedsTheAuditRight(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); err != nil {
		t.Fatal(err)
	}
	fresh := v.clk.Now()
	caAdmin := signedIn("caadmin", fresh, authz.Binding{CA: "issuing", Role: authz.Admin})
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, ""), caAdmin); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("a CA-limited admin restores: %v, want a denial", err)
	}
	if check, err := v.e.DomainRestoreCheck(ctx, caAdmin, d.ID, 1); err != nil || check.Restorable {
		t.Errorf("the dry run for a CA-limited admin: %+v %v", check, err)
	}
	admin := signedIn("admin", fresh, authz.Binding{Role: authz.Admin})
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, ""), admin); err != nil {
		t.Errorf("a tenant admin restores: %v", err)
	}
}
