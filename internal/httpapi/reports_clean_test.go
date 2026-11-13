package httpapi

import (
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Der-Felix/MyOwnPKI/internal/analysis"
)

// TestAnalysisJSONCleansText: the translation to JSON does not rely on the
// rules having cleaned their findings. Control and bidi characters leave the
// text, and a link that browsers would turn into another host is dropped.
func TestAnalysisJSONCleansText(t *testing.T) {
	t.Parallel()
	const (
		rlo  = "\xe2\x80\xae" // right-to-left override
		zwsp = "\xe2\x80\x8b" // zero-width space
	)
	an := &analysis.Analysis{
		GeneratedAt: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
		Findings: []analysis.Finding{
			{Key: "k1", Rule: "weak_key", Severity: "info", Subject: "ev" + rlo + "il\n.lan", Seen: "a" + zwsp + "b\tc", Why: "w" + rlo, Recommendation: "r\r\n", Href: "/\t/evil.example"},
			{Key: "k2", Rule: "weak_key", Severity: "info", Subject: "fine.lan", Seen: "s", Why: "w", Recommendation: "r", Href: "/certificates/crt_1"},
		},
	}
	out := toAnalysisJSON(an)
	if len(out.Findings) != 2 {
		t.Fatalf("%d findings", len(out.Findings))
	}
	f := out.Findings[0]
	if f.Subject != "evil.lan" || f.Seen != "abc" || f.Why != "w" || f.Recommendation != "r" || f.Href != "" {
		t.Errorf("not cleaned: %+v", f)
	}
	for _, s := range []string{f.Subject, f.Seen, f.Why, f.Recommendation} {
		if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
			t.Errorf("control or format character left in %q", s)
		}
	}
	if g := out.Findings[1]; g.Href != "/certificates/crt_1" || g.Subject != "fine.lan" {
		t.Errorf("a clean finding changed: %+v", g)
	}
}
