// Package ids creates the opaque IDs of database rows (PHASE1 §1: "ULID-like").
//
// An ID is a short type prefix and 26 characters of lower-case Crockford
// Base32: 48 bits of milliseconds since 1970 followed by 80 random bits, so
// IDs sort by creation time and can't be guessed. Example:
// crt_01jaxk3s7m0000000000000000.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"time"
)

const alphabet = "0123456789abcdefghjkmnpqrstvwxyz" // Crockford, lower case

var prefixPattern = regexp.MustCompile(`^[a-z]{2,8}$`)

// New returns a new ID with prefix. rnd nil means crypto/rand.
func New(prefix string, now time.Time, rnd io.Reader) (string, error) {
	if !prefixPattern.MatchString(prefix) {
		return "", fmt.Errorf("id prefix %q: want 2-8 lower-case letters", prefix)
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	var b [16]byte
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(now.UnixMilli()))
	copy(b[:6], ms[2:])
	if _, err := io.ReadFull(rnd, b[6:]); err != nil {
		return "", fmt.Errorf("id: %w", err)
	}
	return prefix + "_" + encode(b), nil
}

// encode writes 128 bits as 26 Base32 characters (the first carries 3 bits).
func encode(b [16]byte) string {
	out := make([]byte, 26)
	var acc uint64
	var bits uint
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 {
			out[pos] = alphabet[acc&31]
			pos--
			acc >>= 5
			bits -= 5
		}
	}
	out[0] = alphabet[acc&31]
	return string(out)
}
