package analysis

import (
	"strings"
	"testing"
)

// TestUnusedACMEAccountSaysUnknownForTheAccountsNotRead: with more accounts
// than the engine reads, the rule never reports ok.
func TestUnusedACMEAccountSaysUnknownForTheAccountsNotRead(t *testing.T) {
	t.Parallel()
	idle := Account{ID: "acc-1", Status: "valid", CreatedAt: now.Add(-200 * day), LastOrderAt: now.Add(-100 * day)}
	busy := Account{ID: "acc-2", Status: "valid", CreatedAt: now.Add(-200 * day), LastOrderAt: now.Add(-day)}

	r := UnusedACMEAccount(Snapshot{Now: now, Accounts: []Account{busy}, AccountsLimit: 5000})
	want(t, "nothing found in the newest 5000", r, StateUnknown, 0, 1)
	if !strings.Contains(r.UnknownReason, "only the newest 5000 accounts were checked") {
		t.Errorf("reason %q", r.UnknownReason)
	}
	r = UnusedACMEAccount(Snapshot{Now: now, Accounts: []Account{idle, busy}, AccountsLimit: 5000})
	want(t, "a finding and a part not checked", r, StateFindings, 1, 1)
	if !strings.Contains(r.UnknownReason, "newest 5000") {
		t.Errorf("reason %q", r.UnknownReason)
	}
	// Every account read: ok as before.
	want(t, "all read", UnusedACMEAccount(Snapshot{Now: now, Accounts: []Account{busy}}), StateOK, 0, 0)
}
