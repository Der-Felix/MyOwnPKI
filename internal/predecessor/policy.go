// Package predecessor defines how a replacement handles its predecessor.
package predecessor

import "fmt"

const (
	Now   = "now"
	After = "after"
	Never = "never"
)

// Policy is a validated choice and, for After, a delay in days.
type Policy struct {
	Choice string
	Days   int
}

var (
	DefaultAgent = Policy{Choice: Now, Days: 7}
	DefaultOther = Policy{Choice: After, Days: 7}
)

// Validate checks a complete policy. Days is meaningful only for After.
func (p Policy) Validate() error {
	switch p.Choice {
	case Now, Never:
		if p.Days != 0 && p.Days != 7 {
			return fmt.Errorf("predecessor days apply only to choice after")
		}
		return nil
	case After:
		if p.Days < 1 || p.Days > 30 {
			return fmt.Errorf("predecessor days must be between 1 and 30")
		}
		return nil
	default:
		return fmt.Errorf("predecessor choice must be now, after or never")
	}
}

// Normalize allows the stored default day count on non-delayed choices.
func (p Policy) Normalize() Policy {
	if p.Choice != After {
		p.Days = 0
	}
	return p
}
