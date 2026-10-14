package ids

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

var idPattern = regexp.MustCompile(`^crt_[0-7][0-9a-hjkmnp-tv-z]{25}$`)

func TestNewSortsByTimeAndIsRandom(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	a, err := New("crt", t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := New("crt", t0.Add(time.Millisecond), nil)
	c, _ := New("crt", t0.Add(time.Millisecond), nil)
	for _, id := range []string{a, b, c} {
		if !idPattern.MatchString(id) {
			t.Errorf("%q has the wrong form", id)
		}
	}
	if a >= b {
		t.Errorf("%s should sort before %s", a, b)
	}
	if b == c || b[:14] != c[:14] {
		t.Errorf("same millisecond: %s %s – same time part, different random part expected", b, c)
	}
}

func TestEncodeIsBase32OfTheBits(t *testing.T) {
	t.Parallel()
	var all [16]byte
	for i := range all {
		all[i] = 0xff
	}
	if got := encode(all); got != "7"+strings.Repeat("z", 25) {
		t.Errorf("all ones: %s", got)
	}
	var one [16]byte
	one[15] = 1
	if got := encode(one); got != strings.Repeat("0", 25)+"1" {
		t.Errorf("one: %s", got)
	}
	id, _ := New("key", time.UnixMilli(0), bytes.NewReader(make([]byte, 10)))
	if id != "key_"+strings.Repeat("0", 26) {
		t.Errorf("zero: %s", id)
	}
}

func TestBadPrefix(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"", "x", "CRT", "crt_", "toolongprefix"} {
		if _, err := New(p, time.UnixMilli(0), nil); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
}
