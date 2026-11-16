package agent

import (
	"strings"
	"testing"
)

// The note check of the real-service tests must not pass or fail by accident:
// it runs here without any service, against made-up notes.
func TestNoteClaimVerdict(t *testing.T) {
	t.Parallel()
	claim := func(seen bool) noteClaim {
		return noteClaim{recipe: "r", topic: "t", result: "x", seen: seen, ifSeen: "it rejects a bad key", ifNot: "it misses a bad key", pending: "not known"}
	}
	for _, tc := range []struct {
		name  string
		seen  bool
		notes []string
		want  noteVerdict
	}{
		{"seen and said so", true, []string{"a. it rejects a bad key."}, noteAgrees},
		{"not seen and said so", false, []string{"it misses a bad key"}, noteAgrees},
		{"seen but the opposite is written", true, []string{"it misses a bad key"}, noteContradicts},
		{"not seen but the opposite is written", false, []string{"x", "it rejects a bad key"}, noteContradicts},
		{"still pending", true, []string{"not known"}, noteBehind},
		{"silent", false, []string{"nothing"}, noteBehind},
	} {
		if got, message := claim(tc.seen).verdict(tc.notes); got != tc.want || (got != noteAgrees && message == "") {
			t.Errorf("%s: verdict %d (message %q), want %d", tc.name, got, message, tc.want)
		}
	}
}

// The real notes of the recipes must not already contain the sentence of the
// opposite outcome: the first real run could not tell the two apart.
func TestServiceNoteSentencesAreDistinct(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{
		{apacheNoteRejects, apacheNoteMissesKey}, {apacheNoteSurvives, apacheNoteStops},
		{haproxyNoteRefuses, haproxyNoteAccepts}, {haproxyNoteSkipsTemp, haproxyNoteLoadsTemp},
		{haproxyNoteOrderMatter, haproxyNoteOrderFree},
	} {
		if strings.Contains(pair[0], pair[1]) || strings.Contains(pair[1], pair[0]) {
			t.Errorf("%q and %q contain each other", pair[0], pair[1])
		}
	}
}
