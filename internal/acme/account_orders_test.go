package acme

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// TestAccountOrdersBounds: at most 100 URLs; and an account's list does not
// depend on how many orders other accounts made after it.
func TestAccountOrdersBounds(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	busy := v.client(t)
	busy.register()
	q := pkidb.New(v.Engine.PKI)
	insert := func(id, account string, at time.Time) {
		t.Helper()
		err := q.InsertACMEOrder(t.Context(), pkidb.InsertACMEOrderParams{
			ID: id, AccountID: account, Status: "pending", Identifiers: `[{"type":"dns","value":"x.homelab.lan"}]`,
			ExpiresAt: dbTime(at.Add(24 * time.Hour)), CreatedAt: dbTime(at), UpdatedAt: dbTime(at),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	start := v.Clock.Now()
	accountID := c.kid[strings.LastIndex(c.kid, "/")+1:]
	busyID := busy.kid[strings.LastIndex(busy.kid, "/")+1:]

	// 120 orders of one account: the list is capped at 100.
	for i := range 120 {
		insert(fmt.Sprintf("ord_mine%03d", i), accountID, start.Add(time.Duration(i)*time.Second))
	}
	a := c.post(c.kid+"/orders", nil)
	if got := strs(a.json["orders"]); len(got) != 100 {
		t.Fatalf("%d orders listed, want the cap of 100", len(got))
	} else if !strings.HasSuffix(got[0], "ord_mine119") {
		t.Errorf("the newest order is not first: %s", got[0])
	}

	// The same account with an old order, and another account that made
	// more than a thousand orders since: the old order is still the account's.
	lone := v.client(t)
	lone.register()
	loneID := lone.kid[strings.LastIndex(lone.kid, "/")+1:]
	insert("ord_lone", loneID, start.Add(-time.Hour))
	for i := range 1001 {
		insert(fmt.Sprintf("ord_busy%04d", i), busyID, start.Add(time.Hour+time.Duration(i)*time.Second))
	}
	got := strs(lone.post(lone.kid+"/orders", nil).json["orders"])
	if len(got) != 1 || !strings.HasSuffix(got[0], "ord_lone") {
		t.Errorf("the list of an account with one old order, 1001 newer orders of others in the database: %v", got)
	}
}
