package predecessor

import "testing"

func TestPolicyValidation(t *testing.T) {
	t.Parallel()
	for _, policy := range []Policy{{Choice: Now}, {Choice: Never}, {Choice: After, Days: 1}, {Choice: After, Days: 30}} {
		if err := policy.Validate(); err != nil {
			t.Errorf("%+v: %v", policy, err)
		}
	}
	for _, policy := range []Policy{{}, {Choice: "later"}, {Choice: After}, {Choice: After, Days: -1}, {Choice: After, Days: 31}, {Choice: Now, Days: 2}, {Choice: Never, Days: 2}} {
		if err := policy.Validate(); err == nil {
			t.Errorf("%+v accepted", policy)
		}
	}
	if got := (Policy{Choice: Now, Days: 7}).Normalize(); got.Days != 0 {
		t.Errorf("normalized days %d", got.Days)
	}
}
