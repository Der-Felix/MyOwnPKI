package view

import (
	"testing"
	"time"
)

func TestParsePrefs(t *testing.T) {
	t.Parallel()
	def := DefaultPrefs()
	tests := []struct {
		in   string
		want Prefs
	}{
		{"a.dark.compact", Prefs{LayoutA, ThemeDark, DensityCompact}},
		{"c.system.comfortable", Prefs{LayoutC, ThemeSystem, DensityComfortable}},
		{"", def},
		{"b.dark", def},
		{"x.dark.compact", Prefs{def.Layout, ThemeDark, DensityCompact}},
		{`a."><script>.compact`, Prefs{LayoutA, def.Theme, DensityCompact}},
		{"a.dark.compact.extra", def},
	}
	for _, tt := range tests {
		if got := ParsePrefs(tt.in); got != tt.want {
			t.Errorf("ParsePrefs(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
	if p := (Prefs{LayoutA, ThemeDark, DensityCompact}); ParsePrefs(p.String()) != p {
		t.Error("String/ParsePrefs round trip failed")
	}
}

func TestRelative(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		t    time.Time
		want string
	}{
		{now.Add(5 * time.Hour), "today"},
		{now.Add(30 * time.Hour), "tomorrow"},
		{now.Add(-30 * time.Hour), "yesterday"},
		{now.Add(83 * 24 * time.Hour), "in 83 days"},
		{now.Add(-44 * 24 * time.Hour), "44 days ago"},
	}
	for _, tt := range tests {
		if got := Relative(now, tt.t); got != tt.want {
			t.Errorf("Relative(%v) = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestFormatsAreUTC(t *testing.T) {
	t.Parallel()
	berlin := time.FixedZone("CEST", 2*60*60)
	ts := time.Date(2026, 10, 13, 1, 30, 0, 0, berlin) // 2026-10-12 23:30 UTC
	if got := Date(ts); got != "2026-10-12" {
		t.Errorf("Date = %q", got)
	}
	if got := DateTime(ts); got != "2026-10-12 23:30 UTC" {
		t.Errorf("DateTime = %q", got)
	}
}

func TestMessageLabels(t *testing.T) {
	t.Parallel()
	for k, want := range map[MessageKind]string{MessageWarning: "Warning:", MessageError: "Error:", MessageInfo: "Note:", MessageSuccess: "Done:"} {
		if got := k.Label(); got != want {
			t.Errorf("%s.Label() = %q, want %q", k, got, want)
		}
	}
}

func TestFingerprintFormat(t *testing.T) {
	t.Parallel()
	if got := ColonHex("783d62e5"); got != "78:3D:62:E5" {
		t.Errorf("ColonHex = %q", got)
	}
	if got := ColonHex("78:3D:62:E5"); got != "78:3D:62:E5" {
		t.Errorf("ColonHex is not idempotent: %q", got)
	}
	hex := "783D62E575ED9E17D108E4F94346D0B47D99B4B9B023741A2D5DDC212A4FC0FF"
	want := "78:3D:62:E5:75:ED:9E:17:D1:08:E4:F9:43:46:D0:B4:\n7D:99:B4:B9:B0:23:74:1A:2D:5D:DC:21:2A:4F:C0:FF"
	if got := Fingerprint(hex); got != want {
		t.Errorf("Fingerprint =\n%s\nwant\n%s", got, want)
	}
}
