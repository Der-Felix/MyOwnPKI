package acme

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestFinalizeAppliesOtherPredecessorPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		choice string
		days   int
	}{
		{choice: predecessor.Now},
		{choice: predecessor.After, days: 3},
		{choice: predecessor.Never},
	} {
		t.Run(tc.choice, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t, ca.ApprovalOpen)
			settings := &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}
			current, settingsErr := settings.Defaults(t.Context(), store.DefaultTenant)
			if settingsErr != nil {
				t.Fatal(settingsErr)
			}
			policy := predecessor.Policy{Choice: tc.choice, Days: tc.days}
			current.OtherPredecessor = &policy
			if err := settings.Set(t.Context(), store.DefaultTenant, *current, testinstance.Console); err != nil {
				t.Fatal(err)
			}
			client := v.client(t)
			client.register()
			client.issue("renew.homelab.lan")
			q := pkidb.New(v.PKIDB.Write)
			orders, err := q.ListACMEOrders(t.Context(), 1)
			if err != nil || len(orders) != 1 || !orders[0].CertificateID.Valid {
				t.Fatalf("first order: %+v, %v", orders, err)
			}
			oldID := orders[0].CertificateID.String
			v.Clock.Advance(time.Second)
			client.issue("renew.homelab.lan")
			revocation, revokeErr := q.GetRevocation(t.Context(), oldID)
			plan, planErr := q.GetRevocationPlan(t.Context(), oldID)
			switch tc.choice {
			case predecessor.Now:
				if revokeErr != nil || revocation.Reason != ca.ReasonSuperseded || planErr == nil {
					t.Errorf("immediate: revocation %+v (%v), plan error %v", revocation, revokeErr, planErr)
				}
			case predecessor.After:
				if !errors.Is(revokeErr, sql.ErrNoRows) || planErr != nil {
					t.Fatalf("delayed: revocation error %v, plan error %v", revokeErr, planErr)
				}
				if got, want := plan.PlannedAt, v.Clock.Now().Add(time.Duration(tc.days)*24*time.Hour).Format(time.RFC3339); got != want {
					t.Errorf("planned at %s, want %s", got, want)
				}
			case predecessor.Never:
				if !errors.Is(revokeErr, sql.ErrNoRows) || !errors.Is(planErr, sql.ErrNoRows) {
					t.Errorf("never: revocation error %v, plan error %v", revokeErr, planErr)
				}
			}
		})
	}
}
