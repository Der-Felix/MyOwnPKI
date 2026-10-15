package auth

import (
	"io"
	"strings"
)

const (
	// RecoveryCodeCount codes per user, each usable once.
	RecoveryCodeCount = 10
	// recoveryCodeLen Crockford Base32 characters = 100 random bits: far
	// beyond the 80 bits that make offline guessing of a stolen hash
	// hopeless (the hash is keyed with the auth key on top).
	recoveryCodeLen = 20
	recoveryGroup   = 5
	crockford       = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// newRecoveryCodes returns n codes like "7K2QF-9XW4M-…", 5 bits per
// character from one random byte each (256 is a multiple of 32: no bias).
func newRecoveryCodes(rnd io.Reader, n int) ([]string, error) {
	codes := make([]string, 0, n)
	for range n {
		b, err := randomBytes(rnd, recoveryCodeLen)
		if err != nil {
			return nil, err
		}
		var s strings.Builder
		for i, x := range b {
			if i > 0 && i%recoveryGroup == 0 {
				s.WriteByte('-')
			}
			s.WriteByte(crockford[x&31])
		}
		codes = append(codes, s.String())
	}
	return codes, nil
}

// normalizeRecoveryCode accepts what a person types: any case, with or
// without dashes and spaces, I/L for 1 and O for 0 (Crockford). It returns
// the canonical form that is hashed, or false.
func normalizeRecoveryCode(in string) (string, bool) {
	var s strings.Builder
	for _, c := range strings.ToUpper(in) {
		switch c {
		case '-', ' ':
			continue
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		if !strings.ContainsRune(crockford, c) {
			return "", false
		}
		s.WriteRune(c)
	}
	if s.Len() != recoveryCodeLen {
		return "", false
	}
	return s.String(), true
}
