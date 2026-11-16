// Package b64url reads base64url text from outside the trust boundary in its one canonical form.
//
// The decoder of encoding/base64 silently skips '\r' and '\n', also in strict mode (strict only
// demands zero bits at the end). A text with a line break inside therefore decodes to the same bytes as the
// clean text, and a program that keeps the text itself (a key thumbprint, an identifier in a
// URL, a signing input) keeps a second spelling of the same value. Decode refuses every such text.
package b64url

import (
	"encoding/base64"
	"errors"
)

// ErrNotCanonical: the text is not base64url without padding in its one canonical form.
var ErrNotCanonical = errors.New("not base64url without padding")

var enc = base64.RawURLEncoding.Strict()

// Decode reads base64url without padding (RFC 4648 section 5). The text may hold nothing but
// the 64 characters A-Z a-z 0-9 - _ (no line break, no space, no padding, no '+' or '/'), and the
// unused bits of the last character must be zero, so every value has exactly one spelling and
// encoding the result gives the text back. The empty text decodes to no bytes.
func Decode(s string) ([]byte, error) {
	for i := range len(s) {
		if !inAlphabet(s[i]) {
			return nil, ErrNotCanonical
		}
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return nil, ErrNotCanonical
	}
	return b, nil
}

func inAlphabet(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
