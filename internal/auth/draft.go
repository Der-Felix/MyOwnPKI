package auth

import (
	"time"
)

// Draft is the second factor of a user who doesn't exist yet: TOTP secret
// and recovery codes made before anything is written. init shows it and
// takes the first code before it writes (owner decision f), and a setup
// without a terminal writes its files first – nothing in the database refers
// to a secret that was never handed out.
type Draft struct {
	secret []byte
	// Enrollment to show or write; UserID is filled in by CreateUser.
	Enrollment *Enrollment
	// confirmedStep > 0: the first code was entered (init on the console).
	confirmedStep int64
}

// NewDraft makes a TOTP secret and recovery codes for username.
func (s *Service) NewDraft(username string) (*Draft, error) {
	secret, err := newTOTPSecret(s.Rand)
	if err != nil {
		return nil, err
	}
	codes, err := newRecoveryCodes(s.Rand, RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	enr := newEnrollment(s.issuer(), "", username, secret)
	enr.RecoveryCodes = codes
	return &Draft{secret: secret, Enrollment: enr}, nil
}

// Confirm checks the first code from the authenticator app. On success the
// user is created with a confirmed authenticator, and this code's time step
// counts as used.
func (d *Draft) Confirm(code string, now time.Time) bool {
	step, ok := matchTOTP(d.secret, normalizeTOTPCode(code), now, 0)
	if ok {
		d.confirmedStep = step
	}
	return ok
}

// Confirmed reports whether Confirm succeeded.
func (d *Draft) Confirmed() bool { return d.confirmedStep > 0 }

// Clear removes the secret from memory once it is stored and shown.
func (d *Draft) Clear() { clear(d.secret) }
