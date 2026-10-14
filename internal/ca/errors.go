package ca

import (
	"errors"
	"fmt"
	"strings"
)

// ErrDenied is wrapped by every refusal the requester or an admin can fix:
// a policy, a name, a CSR, a limit. Everything else is a failure.
var ErrDenied = errors.New("request denied")

// DeniedError lists every reason at once, so a requester can fix them all in
// one go. Reasons may contain requested names – escape them on output.
type DeniedError struct {
	Reasons []string
	// DroppedCSRNames: CSR names the preset doesn't take ("type:value"),
	// reported even when the request is denied for another reason.
	DroppedCSRNames []string
}

func (e *DeniedError) Error() string {
	if len(e.Reasons) == 1 {
		return "request denied: " + e.Reasons[0]
	}
	return "request denied:\n  - " + strings.Join(e.Reasons, "\n  - ")
}

func (e *DeniedError) Unwrap() error { return ErrDenied }

func deny(format string, args ...any) error {
	return &DeniedError{Reasons: []string{fmt.Sprintf(format, args...)}}
}
