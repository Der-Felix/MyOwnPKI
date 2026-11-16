package b64url

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []byte // nil: refused
	}{
		{"empty", "", []byte{}},
		{"one byte", "AQ", []byte{1}},
		{"two bytes", "AQI", []byte{1, 2}},
		{"three bytes", "AQID", []byte{1, 2, 3}},
		{"the url alphabet", "-_8", []byte{0xfb, 0xff}},
		{"CR inside", "A\rQ", nil},
		{"LF inside", "A\nQ", nil},
		{"CRLF inside", "A\r\nQ", nil},
		{"LF in front", "\nAQ", nil},
		{"LF behind", "AQ\n", nil},
		{"CR behind", "AQID\r", nil},
		{"space", "AQ ID", nil},
		{"tab", "AQ\tID", nil},
		{"NUL", "AQ\x00ID", nil},
		{"padding", "AQ==", nil},
		{"standard alphabet plus", "+_8", nil},
		{"standard alphabet slash", "-/8", nil},
		{"stray bits", "AR", nil},
		{"length 1 mod 4", "AQIDA", nil},
		{"non-ASCII", "AQé", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Decode(tc.in)
			if tc.want == nil {
				if !errors.Is(err, ErrNotCanonical) {
					t.Fatalf("Decode(%q) = %x, %v; expected ErrNotCanonical", tc.in, got, err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("Decode(%q) = %x, %v; expected %x", tc.in, got, err, tc.want)
			}
		})
	}
}

// Whatever Decode accepts encodes back to the same text.
func TestDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	for n := range 70 {
		raw := bytes.Repeat([]byte{0xa5, 0x01, 0xff}, n)[:n]
		text := base64.RawURLEncoding.EncodeToString(raw)
		got, err := Decode(text)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%d bytes: Decode(%q) = %x, %v", n, text, got, err)
		}
		if n > 0 {
			if _, err = Decode(strings.Replace(text, text[:1], text[:1]+"\n", 1)); err == nil {
				t.Fatalf("%d bytes: a line break after the first character was accepted", n)
			}
		}
	}
}
