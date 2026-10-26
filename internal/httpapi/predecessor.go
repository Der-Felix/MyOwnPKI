package httpapi

import "github.com/Der-Felix/MyOwnPKI/internal/predecessor"

type predecessorPolicyJSON struct {
	Choice string `json:"choice"`
	Days   *int   `json:"days,omitempty"`
}

func toPredecessorPolicyJSON(p predecessor.Policy) predecessorPolicyJSON {
	p = p.Normalize()
	out := predecessorPolicyJSON{Choice: p.Choice}
	if p.Choice == predecessor.After {
		out.Days = &p.Days
	}
	return out
}

func predecessorPolicyPtr(p predecessor.Policy) *predecessorPolicyJSON {
	out := toPredecessorPolicyJSON(p)
	return &out
}

func (p predecessorPolicyJSON) value() predecessor.Policy {
	out := predecessor.Policy{Choice: p.Choice}
	if p.Days != nil {
		out.Days = *p.Days
	}
	return out
}
