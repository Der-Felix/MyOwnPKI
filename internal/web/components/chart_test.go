package components

import (
	"bytes"
	"context"
	"html"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

func renderChart(t *testing.T, c view.Chart) string {
	t.Helper()
	var b bytes.Buffer
	if err := Chart(c).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

var (
	reRect = regexp.MustCompile(`<rect class="(ch-bar[^"]*)" x="([^"]*)" y="([^"]*)" width="([^"]*)" height="([^"]*)"`)
	reText = regexp.MustCompile(`<text class="([^"]*)" x="([^"]*)" y="([^"]*)">([^<]*)</text>`)
)

type rect struct {
	class      string
	x, y, w, h float64
}

func rects(t *testing.T, out string) []rect {
	t.Helper()
	var list []rect
	for _, m := range reRect.FindAllStringSubmatch(out, -1) {
		f := func(s string) float64 {
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				t.Fatalf("not a number: %q", s)
			}
			return v
		}
		list = append(list, rect{class: m[1], x: f(m[2]), y: f(m[3]), w: f(m[4]), h: f(m[5])})
	}
	return list
}

func approx(a, b float64) bool { return math.Abs(a-b) < 0.011 }

func weekCats(n int, values func(i int) []int64) []view.ChartCategory {
	var cats []view.ChartCategory
	for i := 0; i < n; i++ {
		cats = append(cats, view.ChartCategory{Label: "W" + strconv.Itoa(i+1), Name: "Week " + strconv.Itoa(i+1), Values: values(i)})
	}
	return cats
}

func TestChartStructure(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{
		ID: "chart-x", Kind: view.ChartColumns, Title: "Expiry timeline", Summary: "Seven certificates end.",
		CategoryHeader: "Week", ValueHeader: "Certificates", SeriesHeader: "Window", Legend: true,
		Series: []view.ChartSeries{{Label: "Critical window", Class: view.ChartCrit}, {Label: "Later", Class: view.ChartNeutral}},
		Categories: []view.ChartCategory{
			{Label: "W47", Name: "2026-W47", Series: 0, Values: []int64{3}},
			{Label: "W48", Name: "2026-W48", Series: 1, Values: []int64{4}},
		},
	})
	if !regexp.MustCompile(`<svg class="chart-svg" role="img" aria-labelledby="chart-x-title chart-x-desc" viewBox="0 0 360 \d+">`).MatchString(out) {
		t.Errorf("svg tag shape: %s", out)
	}
	for _, want := range []string{
		`<figure class="chart">`, `<title id="chart-x-title">Expiry timeline</title>`, `<desc id="chart-x-desc">Seven certificates end.</desc>`,
		`<details class="chart-numbers">`, `<summary>Numbers</summary>`, `<caption class="visually-hidden">Expiry timeline</caption>`,
		`<th scope="col">Week</th>`, `<th scope="col" class="ch-num">Certificates</th>`, `<th scope="col">Window</th>`,
		`<th scope="row">2026-W47</th><td class="ch-num">3</td><td>Critical window</td>`,
		`<th scope="row">2026-W48</th><td class="ch-num">4</td><td>Later</td>`,
		`<text class="ch-label ch-mid" x=`, `>W47</text>`, `>Critical window</text>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "<details class=\"chart-numbers\" open") {
		t.Error("the numbers must be closed by default")
	}
	// Color classes come from the series; the plot has 2 bars, the legend 2 swatches.
	rs := rects(t, out)
	if len(rs) != 4 || rs[0].class != "ch-bar ch-crit" || rs[1].class != "ch-bar ch-neutral" {
		t.Errorf("rects: %+v", rs)
	}
}

func TestChartColumnsAreProportional(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{
		ID: "c", Kind: view.ChartColumns, Series: []view.ChartSeries{{Label: "n", Class: view.ChartS1}},
		Categories: weekCats(3, func(i int) []int64 { return []int64{[]int64{10, 20, 40}[i]} }),
	})
	rs := rects(t, out)
	if len(rs) != 3 {
		t.Fatalf("rects: %+v", rs)
	}
	// Axis maximum 40 over a 140 unit plot: 3.5 units per certificate.
	for i, want := range []float64{35, 70, 140} {
		if !approx(rs[i].h, want) {
			t.Errorf("bar %d height %v, want %v", i, rs[i].h, want)
		}
		if !approx(rs[i].y+rs[i].h, 158) { // all bars stand on the baseline
			t.Errorf("bar %d bottom %v, want 158", i, rs[i].y+rs[i].h)
		}
	}
	if !approx(rs[0].w, rs[2].w) {
		t.Error("bars differ in width")
	}
	// Axis labels: 0, 10, 20, 30, 40 and the totals above the bars.
	var labels []string
	for _, m := range reText.FindAllStringSubmatch(out, -1) {
		labels = append(labels, m[4])
	}
	for _, want := range []string{"0", "10", "20", "30", "40"} {
		found := false
		for _, l := range labels {
			found = found || l == want
		}
		if !found {
			t.Errorf("axis label %q missing in %v", want, labels)
		}
	}
}

func TestChartStackedSegmentsStack(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{
		ID: "c", Kind: view.ChartStacked,
		Series:     []view.ChartSeries{{Label: "a", Class: view.ChartS1}, {Label: "b", Class: view.ChartS2}, {Label: "c", Class: view.ChartS3}},
		Categories: []view.ChartCategory{{Label: "W1", Values: []int64{10, 0, 30}}, {Label: "W2", Values: []int64{5, 5, 0}}},
	})
	rs := rects(t, out)
	// W1: segment a (10) and c (30), none for b; W2: a (5) and b (5).
	if len(rs) != 4 {
		t.Fatalf("rects: %+v", rs)
	}
	// Axis maximum 40: 3.5 units per certificate.
	if !approx(rs[0].h, 35) || !approx(rs[1].h, 105) {
		t.Errorf("W1 heights %v %v", rs[0].h, rs[1].h)
	}
	if !approx(rs[0].y+rs[0].h, 158) || !approx(rs[1].y+rs[1].h, rs[0].y) {
		t.Errorf("W1 segments do not stack: %+v", rs[:2])
	}
	if !approx(rs[2].h, 17.5) || !approx(rs[3].h, 17.5) || !approx(rs[3].y+rs[3].h, rs[2].y) {
		t.Errorf("W2 segments: %+v", rs[2:])
	}
	// Hatch patterns for s2 and s3 exist and the fill references them.
	for _, want := range []string{`<pattern id="c-s2"`, `<pattern id="c-s3"`, `fill="url(#c-s2)"`, `fill="url(#c-s3)"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, `fill="url(#c-s1)"`) || strings.Count(out, "<pattern ") != 2 {
		t.Error("s1 must be solid and each pattern defined once")
	}
	// The table has one column per series and the total.
	if !strings.Contains(out, `<td class="ch-num">10</td><td class="ch-num">0</td><td class="ch-num">30</td><td class="ch-num">40</td>`) {
		t.Errorf("stacked table row missing in\n%s", out)
	}
}

func TestChartHorizontal(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{
		ID: "h", Kind: view.ChartStackedBars, Legend: true,
		Series: []view.ChartSeries{{Label: "Valid", Class: view.ChartOK}, {Label: "Revoked", Class: view.ChartNeutral}},
		Categories: []view.ChartCategory{
			{Label: "homelab-issuing", Values: []int64{90, 10}},
			{Label: "homelab-users", Values: []int64{50, 0}},
			{Label: "a-very-long-name-of-an-authority-that-gets-clipped", Name: "x", Values: []int64{25, 0}},
		},
	})
	rs := rects(t, out)
	// Bars: 2 + 1 + 1 segments, then 2 legend swatches.
	if len(rs) != 6 {
		t.Fatalf("rects: %+v", rs)
	}
	full := rs[0].w + rs[1].w
	if !approx(rs[2].w, full/2) || !approx(rs[3].w, full/4) {
		t.Errorf("widths %v %v %v (full %v)", rs[0].w, rs[2].w, rs[3].w, full)
	}
	if !approx(rs[1].x, rs[0].x+rs[0].w) {
		t.Error("segments of a row do not abut")
	}
	if !strings.Contains(out, ">a-very-long-name-…</text>") {
		t.Errorf("long name not clipped to 18 runes:\n%s", out)
	}
	if !strings.Contains(out, ">100</text>") {
		t.Error("row total missing")
	}
}

func TestChartCategoryCounts(t *testing.T) {
	t.Parallel()
	for _, n := range []int{5, 12, 13, 26} {
		cats := weekCats(n, func(i int) []int64 { return []int64{int64(i + 1)} })
		out := renderChart(t, view.Chart{ID: "c", Kind: view.ChartColumns, Series: []view.ChartSeries{{Label: "n", Class: view.ChartOK}}, Categories: cats})
		if got := len(rects(t, out)); got != n {
			t.Errorf("%d categories: %d bars", n, got)
		}
		if got := strings.Count(out, "<tr><th scope=\"row\">"); got != n {
			t.Errorf("%d categories: %d table rows", n, got)
		}
		// Every column stays inside the plot area.
		for _, r := range rects(t, out) {
			if r.x < 0 || r.x+r.w > 360 || r.y < 0 {
				t.Errorf("%d categories: bar outside the viewBox: %+v", n, r)
			}
		}
	}
	// With 26 columns the labels thin out instead of overlapping.
	cats := weekCats(26, func(i int) []int64 { return []int64{1} })
	out := renderChart(t, view.Chart{ID: "c", Kind: view.ChartColumns, Series: []view.ChartSeries{{Label: "n", Class: view.ChartOK}}, Categories: cats})
	axis := 0
	for _, m := range reText.FindAllStringSubmatch(out, -1) {
		if strings.HasPrefix(m[4], "W") {
			axis++
		}
	}
	if axis >= 26 || axis < 6 {
		t.Errorf("26 columns show %d axis labels", axis)
	}
}

func TestChartEmpty(t *testing.T) {
	t.Parallel()
	for name, cats := range map[string][]view.ChartCategory{
		"no categories": nil,
		"zeros":         weekCats(13, func(int) []int64 { return []int64{0} }),
		"negative":      weekCats(3, func(int) []int64 { return []int64{-5} }),
		"short values":  {{Label: "a"}, {Label: "b", Values: nil}},
	} {
		out := renderChart(t, view.Chart{ID: "c", Kind: view.ChartColumns, Title: "T", Summary: "S", Empty: "Nothing ends soon.", Categories: cats})
		if !strings.Contains(out, `<p class="empty">Nothing ends soon.</p>`) {
			t.Errorf("%s: no empty state: %s", name, out)
		}
		for _, bad := range []string{"<svg", "<table", "<details", "NaN", "Inf"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: contains %q", name, bad)
			}
		}
		if !strings.Contains(out, "<figcaption") {
			t.Errorf("%s: the caption must stay", name)
		}
	}
	if out := renderChart(t, view.Chart{ID: "c", Kind: view.ChartStacked}); !strings.Contains(out, `<p class="empty">Nothing to show.</p>`) {
		t.Error("default empty text missing")
	}
}

func TestChartHugeAndTinyValues(t *testing.T) {
	t.Parallel()
	for _, kind := range []view.ChartKind{view.ChartColumns, view.ChartBars} {
		out := renderChart(t, view.Chart{
			ID: "c", Kind: kind, Series: []view.ChartSeries{{Label: "n", Class: view.ChartInfo}},
			Categories: []view.ChartCategory{{Label: "a", Values: []int64{math.MaxInt64}}, {Label: "b", Values: []int64{1}}, {Label: "c", Values: []int64{2_000_000_000}}},
		})
		for _, bad := range []string{"NaN", "Inf", "e+", "E+", "-0\""} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: contains %q", kind, bad)
			}
		}
		rs := rects(t, out)
		if len(rs) != 3 {
			t.Fatalf("%s: rects %+v", kind, rs)
		}
		size := func(r rect) float64 {
			if kind == view.ChartColumns {
				return r.h
			}
			return r.w
		}
		// The huge value fills the plot, the tiny ones stay visible at the minimum size.
		if size(rs[0]) <= size(rs[2]) || size(rs[1]) < 2 || size(rs[2]) < 2 {
			t.Errorf("%s: sizes %v %v %v", kind, size(rs[0]), size(rs[1]), size(rs[2]))
		}
		for _, r := range rs {
			if r.x+r.w > 360.01 || r.y+r.h > 400 {
				t.Errorf("%s: outside the viewBox: %+v", kind, r)
			}
		}
		// The table keeps the exact number, grouped.
		if !strings.Contains(out, "1,125,899,906,842,624") { // the value is clamped to 2^50
			t.Errorf("%s: clamped value missing in the table", kind)
		}
	}
}

func TestChartIsDeterministic(t *testing.T) {
	t.Parallel()
	c := view.Chart{
		ID: "c", Kind: view.ChartStacked, Legend: true, Title: "T", Summary: "S",
		Series:     []view.ChartSeries{{Label: "a", Class: view.ChartS1}, {Label: "b", Class: view.ChartS2}},
		Categories: weekCats(12, func(i int) []int64 { return []int64{int64(i * 3), int64(12 - i)} }),
	}
	first := renderChart(t, c)
	for i := 0; i < 3; i++ {
		if renderChart(t, c) != first {
			t.Fatal("the same input renders different bytes")
		}
	}
}

func TestChartEscapesHostileText(t *testing.T) {
	t.Parallel()
	const hostile = `"><script>alert(1)</script>`
	long := strings.Repeat("x", 5000)
	out := renderChart(t, view.Chart{
		ID: `c"><script>`, Kind: view.ChartStackedBars, Legend: true,
		Title: hostile, Summary: hostile, Empty: hostile, CategoryHeader: hostile, ValueHeader: hostile,
		Series:     []view.ChartSeries{{Label: hostile, Class: view.ChartClass(`ok" onload="x`)}, {Label: long, Class: view.ChartS2}},
		Categories: []view.ChartCategory{{Label: hostile, Name: hostile, Values: []int64{3, 4}}, {Label: long, Name: long, Values: []int64{1, 1}}},
	})
	for _, bad := range []string{"<script", "</script", "onload=", `ok"`} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%s", bad, out)
		}
	}
	// The text is there, as text, in the title, the labels, the legend and the table.
	escaped := "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
	for _, tag := range []string{`<title id="cscript-title">`, `<desc id="cscript-desc">`, `<title>`, `<th scope="row">`, `<span class="chart-title">`} {
		i := strings.Index(out, tag)
		if i < 0 || !strings.HasPrefix(out[i+len(tag):], escaped) {
			t.Errorf("%s does not hold the escaped text:\n%s", tag, out)
		}
	}
	if !strings.Contains(out, `<text class="ch-label ch-end"`) || !strings.Contains(out, ">&#34;&gt;&lt;script&gt;alert(1…</text>") {
		t.Errorf("the axis label is not escaped and clipped to 18 runes:\n%s", out)
	}
	if !strings.Contains(out, `<th scope="col">&#34;&gt;&lt;script&gt;alert(1)`) {
		t.Error("the table header is not escaped")
	}
	// 5,000 characters are clipped everywhere they appear.
	if strings.Contains(out, strings.Repeat("x", 100)) {
		t.Error("a long text is not clipped")
	}
	if len(out) > 20000 {
		t.Errorf("the output is %d bytes for two categories", len(out))
	}
	// The id of the element cannot break out of the attribute.
	if !strings.Contains(out, `aria-labelledby="cscript-title cscript-desc"`) {
		t.Errorf("id not cleaned:\n%s", out)
	}
	// Empty state escapes too.
	empty := renderChart(t, view.Chart{ID: "c", Kind: view.ChartColumns, Empty: hostile})
	if strings.Contains(empty, "<script") || !strings.Contains(empty, `<p class="empty">`+escaped) {
		t.Errorf("empty state: %s", empty)
	}
}

func TestChartHasNoCSPRelevantMarkup(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{
		ID: "c", Kind: view.ChartStacked, Legend: true, Title: "T", Summary: "S",
		Series:     []view.ChartSeries{{Label: "a", Class: view.ChartS1}, {Label: "b", Class: view.ChartS2}, {Label: "c", Class: view.ChartS3}},
		Categories: weekCats(12, func(i int) []int64 { return []int64{1, int64(i), 3} }),
	})
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)\sstyle\s*=`), regexp.MustCompile(`(?i)<style[\s>]`), regexp.MustCompile(`(?i)<script`),
		regexp.MustCompile(`(?i)\son[a-z]+\s*=`), regexp.MustCompile(`(?i)javascript:`), regexp.MustCompile(`(?i)\s(xlink:)?href\s*=`),
		regexp.MustCompile(`(?i)<(image|use|foreignObject|animate\w*|set|a)[\s>/]`), regexp.MustCompile(`(?i)<img`), regexp.MustCompile(`(?i)\ssrc\s*=`),
	} {
		if m := re.FindString(out); m != "" {
			t.Errorf("chart output contains %q", m)
		}
	}
	// Only classes of components.css are used (the web tests check they are defined).
	for _, m := range regexp.MustCompile(`class="([^"]*)"`).FindAllStringSubmatch(out, -1) {
		for _, class := range strings.Fields(m[1]) {
			if !strings.HasPrefix(class, "ch-") && !strings.HasPrefix(class, "chart") && !strings.HasPrefix(class, "table") &&
				class != "visually-hidden" {
				t.Errorf("unexpected class %q", class)
			}
		}
	}
	// Numbers in attributes only: the geometry attributes hold plain decimals.
	for _, m := range regexp.MustCompile(`\s(x|y|x1|y1|x2|y2|width|height)="([^"]*)"`).FindAllStringSubmatch(out, -1) {
		if _, err := strconv.ParseFloat(m[2], 64); err != nil || strings.ContainsAny(m[2], "eE+") {
			t.Errorf("attribute %s=%q is not a plain number", m[1], m[2])
		}
	}
}

func TestChartUnknownClassFallsBackToNeutral(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{
		ID: "c", Kind: view.ChartColumns, Series: []view.ChartSeries{{Label: "n", Class: "fancy"}},
		Categories: []view.ChartCategory{{Label: "a", Series: 7, Values: []int64{1}}},
	})
	if !strings.Contains(out, `class="ch-bar ch-neutral"`) {
		t.Errorf("unknown class: %s", out)
	}
}

func TestNiceAxis(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ peak, wantTop int64 }{{0, 1}, {1, 1}, {3, 3}, {4, 4}, {5, 6}, {7, 8}, {13, 15}, {40, 40}, {41, 60}, {99, 100}, {1284, 1500}, {math.MaxInt64 >> 13, 0}} {
		top, step := niceAxis(c.peak)
		if step <= 0 || top < c.peak || top%step != 0 {
			t.Errorf("niceAxis(%d) = %d, %d", c.peak, top, step)
		}
		if c.wantTop != 0 && top != c.wantTop {
			t.Errorf("niceAxis(%d) top = %d, want %d", c.peak, top, c.wantTop)
		}
		if top/step > 4 && c.peak > 0 {
			t.Errorf("niceAxis(%d) has %d intervals", c.peak, top/step)
		}
	}
}

func TestChartHelpers(t *testing.T) {
	t.Parallel()
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", 100000: "100,000"} {
		if got := groupInt(in); got != want {
			t.Errorf("groupInt(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[float64]string{0: "0", 1.5: "1.5", 1.005: "1", 10: "10", -0.001: "0", 0.1 + 0.2: "0.3", 123.456: "123.46"} {
		if got := num(in); got != want {
			t.Errorf("num(%v) = %q, want %q", in, got, want)
		}
	}
	if num(math.NaN()) != "0" || num(math.Inf(1)) != "0" {
		t.Error("num must not write NaN or Inf")
	}
	for in, want := range map[string]string{
		"plain":                   "plain",
		"line\nbreak\tand\x00nul": "linebreakandnul",
		"rtl\u202eoverride\u200b": "rtloverride",
		strings.Repeat("ä", 5):    "äääää",
	} {
		if got := cleanText(in, 18); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanText(strings.Repeat("ä", 19), 18); got != strings.Repeat("ä", 17)+"…" {
		t.Errorf("clip: %q", got)
	}
	if got := cleanText(strings.Repeat("ä", 18), 18); got != strings.Repeat("ä", 18) {
		t.Errorf("exactly the limit is not clipped: %q", got)
	}
	if got := cleanText("bad\xffbyte", 18); got != "badbyte" {
		t.Errorf("invalid UTF-8: %q", got)
	}
	if html.EscapeString(cleanID("a b/c\"d-1")) != "abcd-1" || cleanID("") != "chart" {
		t.Error("cleanID")
	}
}

func TestChartZeroValuesDrawNoBar(t *testing.T) {
	t.Parallel()
	for _, kind := range []view.ChartKind{view.ChartColumns, view.ChartBars} {
		out := renderChart(t, view.Chart{
			ID: "c", Kind: kind, Series: []view.ChartSeries{{Label: "n", Class: view.ChartOK}},
			Categories: []view.ChartCategory{{Label: "a", Values: []int64{0}}, {Label: "b", Values: []int64{4}}, {Label: "c", Values: []int64{0}}},
		})
		if got := len(rects(t, out)); got != 1 {
			t.Errorf("%s: %d bars for one non-zero value", kind, got)
		}
		// The table still lists all three, with their zeros.
		if got := strings.Count(out, `<td class="ch-num">0</td>`); got != 2 {
			t.Errorf("%s: %d zero cells in the table", kind, got)
		}
	}
}

func TestChartEmptyStateHasNoSummary(t *testing.T) {
	t.Parallel()
	out := renderChart(t, view.Chart{ID: "c", Kind: view.ChartColumns, Title: "T", Summary: "0 certificates end soon.", Empty: "Nothing ends soon."})
	if strings.Contains(out, "chart-summary") || strings.Contains(out, "0 certificates") {
		t.Errorf("an empty chart repeats its summary: %s", out)
	}
}
