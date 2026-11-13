package web

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// tokenBlock returns the custom properties declared in the block of tokens.css
// that starts at the line containing marker and ends at the next line that
// is only a closing brace.
func tokenBlock(t *testing.T, css, marker string) map[string]string {
	t.Helper()
	lines := strings.Split(css, "\n")
	vals := map[string]string{}
	start := -1
	for i, l := range lines {
		if strings.Contains(l, marker) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("tokens.css has no block %q", marker)
	}
	re := regexp.MustCompile(`^\s*(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;`)
	for _, l := range lines[start:] {
		if strings.TrimSpace(l) == "}" {
			break
		}
		if m := re.FindStringSubmatch(l); m != nil {
			vals[m[1]] = m[2]
		}
	}
	return vals
}

// luminance is the WCAG relative luminance of #rrggbb.
func luminance(t *testing.T, hex string) float64 {
	t.Helper()
	var c [3]float64
	for i := range c {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatalf("bad color %q", hex)
		}
		f := float64(v) / 255
		if f <= 0.03928 {
			c[i] = f / 12.92
		} else {
			c[i] = math.Pow((f+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
}

func contrast(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := luminance(t, a), luminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestChartColorsHaveContrast: what a chart draws needs 3:1 against the
// background (WCAG 1.4.11), in the light theme, the dark theme and the
// OS-follow block. The status tokens are checked too, because the status
// series of a chart use them as fills.
func TestChartColorsHaveContrast(t *testing.T) {
	t.Parallel()
	css := readStyles(t)["styles/tokens.css"]
	blocks := map[string]string{
		"light":  `[data-theme="light"] {`,
		"dark":   `[data-theme="dark"] {`,
		"system": `[data-theme="system"] {`,
	}
	for name, marker := range blocks {
		tokens := tokenBlock(t, css, marker)
		bg := tokens["--bg"]
		if bg == "" {
			t.Fatalf("%s: no --bg", name)
		}
		for _, tok := range []string{"--chart-s1", "--chart-s2", "--chart-s3", "--status-ok", "--status-warn", "--status-crit", "--status-info", "--status-neutral"} {
			v := tokens[tok]
			if v == "" {
				t.Errorf("%s: %s is not defined", name, tok)
				continue
			}
			if r := contrast(t, v, bg); r < 3 {
				t.Errorf("%s: %s %s on %s has contrast %.2f, want at least 3", name, tok, v, bg, r)
			}
		}
	}
	// The three series colors are told apart in every theme, hatch aside.
	for name, marker := range blocks {
		tokens := tokenBlock(t, css, marker)
		for _, pair := range [][2]string{{"--chart-s1", "--chart-s2"}, {"--chart-s1", "--chart-s3"}, {"--chart-s2", "--chart-s3"}} {
			if tokens[pair[0]] == tokens[pair[1]] {
				t.Errorf("%s: %s and %s are the same color", name, pair[0], pair[1])
			}
		}
	}
}

// TestChartStylesHaveNoMotionOrDecoration: the chart styles are calm (no
// gradient, shadow, animation or transition) and use no url() other than
// what the SVG itself references.
func TestChartStylesHaveNoMotionOrDecoration(t *testing.T) {
	t.Parallel()
	css := readStyles(t)["styles/components.css"]
	i := strings.Index(css, ".chart {")
	j := strings.Index(css, ".empty {")
	if i < 0 || j < i {
		t.Fatal("chart block not found in components.css")
	}
	for _, bad := range []string{"gradient", "shadow", "animation", "transition", "@keyframes", "url(", "filter", "@import"} {
		if strings.Contains(css[i:j], bad) {
			t.Errorf("the chart styles use %q", bad)
		}
	}
}

// TestGalleryShowsEveryChart: the /design gallery shows each chart class
// family with sample data (a new class gets a gallery entry), the SVGs have
// the allowed shape, and every chart comes with a closed numbers table.
func TestGalleryShowsEveryChart(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)
	out := get(t, h, "/design").Body.String()

	svgs := reSVGOpen.FindAllString(out, -1)
	if len(svgs) != 8 {
		t.Fatalf("the gallery has %d chart SVGs, want 8 (expiry, issuances, CAs, alerts, three fleet bars, one in the dark preview)", len(svgs))
	}
	for _, v := range svgViolations(out, reRenderedChartSVG) {
		t.Error(v)
	}
	for _, id := range []string{"chart-expiry", "chart-issuances", "chart-authorities", "chart-alerts", "chart-fleet-agents", "chart-fleet-versions", "chart-fleet-deployments", "chart-preview"} {
		if !strings.Contains(out, `<title id="`+id+`-title">`) || !strings.Contains(out, `aria-labelledby="`+id+`-title `+id+`-desc"`) {
			t.Errorf("gallery lacks the chart %s", id)
		}
	}
	if got := strings.Count(out, `<details class="chart-numbers">`); got != 8 {
		t.Errorf("%d closed number tables, want 8", got)
	}
	if strings.Contains(out, `<details class="chart-numbers" open`) {
		t.Error("a numbers table is open by default")
	}
	// One empty-state chart, in words.
	if !strings.Contains(out, `<p class="empty">No certificate ends in the next 13 weeks.</p>`) {
		t.Error("the empty-state chart is missing")
	}
	// The classes of the families that need a gallery entry.
	for _, class := range []string{"ch-ok", "ch-warn", "ch-crit", "ch-info", "ch-neutral", "ch-s1", "ch-s2", "ch-s3", "ch-axis", "ch-grid", "ch-label", "ch-hatch", "ch-num", "chart-numbers"} {
		if !strings.Contains(out, class) {
			t.Errorf("the gallery does not show %s", class)
		}
	}
}
