package ca

import (
	"fmt"
	"time"
)

// Backdate moves notBefore into the past, so a client whose clock is a few
// minutes behind accepts a fresh certificate (pki-rules.md §5).
const Backdate = 5 * time.Minute

const day = 24 * time.Hour

type validity struct {
	notBefore, notAfter time.Time
	days                int // the lifetime that was applied
	notes               []string
	problem             string
}

// computeValidity applies the owner's rule (step 7 decision b): an explicit
// request is never changed silently – it is accepted or denied. A default
// (the preset's validity) adapts to the CA's limits and says so in a note.
//
// The lifetime counts both ends: RFC 5280 notAfter is inclusive, so a
// certificate for d days ends one second before notBefore + d days.
func computeValidity(now time.Time, requested, presetDays, maxDays int, caNotBefore, caNotAfter time.Time) validity {
	var v validity
	explicit := requested != 0
	switch {
	case requested < 0:
		v.problem = fmt.Sprintf("validity of %d days is not possible", requested)
		return v
	case explicit && requested > maxDays:
		v.problem = fmt.Sprintf("validity of %d days exceeds the maximum of this CA (%d days)", requested, maxDays)
		return v
	case explicit:
		v.days = requested
	case presetDays > maxDays:
		v.days = maxDays
		v.notes = append(v.notes, fmt.Sprintf("validity capped at the CA maximum of %d days (preset default %d days)", maxDays, presetDays))
	default:
		v.days = presetDays
	}

	v.notBefore = now.Add(-Backdate)
	if v.notBefore.Before(caNotBefore) {
		v.notBefore = caNotBefore
	}
	v.notAfter = v.notBefore.Add(time.Duration(v.days)*day - time.Second)
	if v.notAfter.After(caNotAfter) {
		if explicit {
			v.problem = fmt.Sprintf("validity of %d days would end after the CA certificate (%s) – a CA never issues beyond its own end",
				requested, caNotAfter.Format(time.DateOnly))
			return v
		}
		v.notAfter = caNotAfter
		v.notes = append(v.notes, fmt.Sprintf("validity shortened to the end of the CA certificate (%s)", caNotAfter.Format(time.DateOnly)))
	}
	return v
}
