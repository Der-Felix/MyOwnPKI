package components

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Server-rendered charts (docs/PHASE3.md D1). This file turns a view.Chart
// into plain geometry: every number below is a float or an int that is
// formatted by num, and every string that came from data (names, labels) is
// cleaned and clipped. chart.templ writes the result; nothing here builds
// markup, so no text can reach the page unescaped.
//
// Units are SVG user units. The viewBox is 360 units wide, so on a phone
// (about 343 CSS pixels of content) one unit is about one pixel and the
// 12 px labels stay readable; on a wide screen .chart-svg caps the width.

const (
	chartWidth   = 360.0
	glyphWidth   = 7.2 // generous width of a 12 px label glyph, for fitting text
	digitWidth   = 7.2 // widest digit, for the axis labels
	chartPad     = 8.0
	plotHeight   = 140.0 // vertical kinds: height of the plot area
	plotTop      = 18.0  // vertical kinds: room for the value labels
	maxBarWidth  = 40.0
	minSegment   = 2.0 // smallest drawn height or width of a non-zero value
	rowHeight    = 24.0
	barThickness = 14.0
	nameWidth    = 128.0 // horizontal kinds: room for the category names
	legendRow    = 18.0
	swatchSize   = 10.0

	maxLabelRunes  = 18 // category label on the axis
	maxNameRunes   = 48 // category name in the table and the tooltip
	maxSeriesRunes = 24
	maxTextRunes   = 200 // title, summary, headers
	// maxValue keeps sums of many series inside int64 and floats exact.
	maxValue int64 = 1 << 50
)

type chartLine struct {
	X1, Y1, X2, Y2, Class string
}

type chartText struct {
	X, Y, Text, Class string
}

type chartRect struct {
	X, Y, W, H string
	Class      string
	// Fill is a url(#pattern) reference for the hatched series, else empty.
	Fill  string
	Title string
}

// chartPattern is a hatch definition for the series classes s2 and s3.
type chartPattern struct {
	ID, Class string
	Diagonal  bool // s2: diagonal lines (the pattern is rotated); s3: horizontal lines
}

type chartCell struct {
	Text string
	Num  bool
}

type chartRow struct {
	Name  string
	Cells []chartCell
}

type chartModel struct {
	TitleID, DescID string
	Title, Summary  string
	Empty           string // non-empty: the chart has no data, draw only this
	ViewBox         string
	Patterns        []chartPattern
	Lines           []chartLine
	Rects           []chartRect
	Texts           []chartText
	Headers         []chartCell
	Rows            []chartRow
	NumbersLabel    string
}

var chartClasses = map[view.ChartClass]bool{
	view.ChartOK: true, view.ChartWarn: true, view.ChartCrit: true, view.ChartInfo: true,
	view.ChartNeutral: true, view.ChartS1: true, view.ChartS2: true, view.ChartS3: true,
}

// cleanClass keeps only the known color classes.
func cleanClass(c view.ChartClass) view.ChartClass {
	if chartClasses[c] {
		return c
	}
	return view.ChartNeutral
}

// cleanText drops control and format characters (line breaks, bidi
// overrides, zero-width marks) and clips to max runes with an ellipsis. The
// result is still data: the template escapes it.
func cleanText(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			continue
		}
		if n == limit {
			// One more character exists: replace the last kept one.
			out := []rune(b.String())
			return string(out[:len(out)-1]) + "…"
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// cleanID keeps a-z, 0-9 and "-" so a page constant cannot break an
// attribute; an empty result becomes "chart".
func cleanID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "chart"
	}
	return b.String()
}

// num formats a coordinate: at most two decimals, no exponent, no "-0".
func num(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "0"
	}
	s := strconv.FormatFloat(v, 'f', 2, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if s == "-0" || s == "" {
		return "0"
	}
	return s
}

// groupInt writes 1234567 as 1,234,567 (counts in the numbers table).
func groupInt(v int64) string {
	s := strconv.FormatInt(v, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func clampValue(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

// niceAxis returns the top of the value axis and the tick step for a
// maximum: whole numbers, at most four intervals (1, 2 or 5 times a power of
// ten).
func niceAxis(peak int64) (top, step int64) {
	if peak <= 0 {
		return 1, 1
	}
	raw := (peak + 3) / 4
	mag := int64(1)
	for mag*10 <= raw {
		mag *= 10
	}
	step = mag * 10
	for _, m := range []int64{1, 2, 5} {
		if m*mag >= raw {
			step = m * mag
			break
		}
	}
	return (peak + step - 1) / step * step, step
}

func textWidth(s string) float64 { return float64(utf8.RuneCountInString(s)) * glyphWidth }

func digitsWidth(v int64) float64 { return float64(len(groupInt(v))) * digitWidth }

// chartData is a Chart with cleaned text and normalized numbers.
type chartData struct {
	id      string
	series  []view.ChartSeries
	cats    []chartCat
	stacked bool
	// tipSeries: the tooltip names the series (it is not the category's own).
	tipSeries bool
	maxTot    int64
}

type chartCat struct {
	label, name string
	series      int
	vals        []int64 // stacked: one per series; else one value
	total       int64
}

func normalize(c view.Chart) chartData {
	d := chartData{id: cleanID(c.ID)}
	d.stacked = c.Kind == view.ChartStacked || c.Kind == view.ChartStackedBars
	d.tipSeries = d.stacked || c.SeriesHeader != ""
	for _, s := range c.Series {
		d.series = append(d.series, view.ChartSeries{Label: cleanText(s.Label, maxSeriesRunes), Class: cleanClass(s.Class)})
	}
	if len(d.series) == 0 {
		d.series = []view.ChartSeries{{Label: "Value", Class: view.ChartNeutral}}
	}
	for _, cat := range c.Categories {
		x := chartCat{label: cleanText(cat.Label, maxLabelRunes), name: cleanText(cat.Name, maxNameRunes)}
		if x.name == "" {
			x.name = cleanText(cat.Label, maxNameRunes)
		}
		if d.stacked {
			x.vals = make([]int64, len(d.series))
			for i := range x.vals {
				if i < len(cat.Values) {
					x.vals[i] = clampValue(cat.Values[i])
				}
				x.total += x.vals[i]
			}
		} else {
			x.series = cat.Series
			if x.series < 0 || x.series >= len(d.series) {
				x.series = 0
			}
			var v int64
			if len(cat.Values) > 0 {
				v = clampValue(cat.Values[0])
			}
			x.vals = []int64{v}
			x.total = v
		}
		if x.total > d.maxTot {
			d.maxTot = x.total
		}
		d.cats = append(d.cats, x)
	}
	return d
}

// segment is one drawn rectangle of a category: its value, series and the
// value where it starts.
func (d chartData) segments(c chartCat) []segment {
	if !d.stacked {
		if c.vals[0] == 0 {
			return nil
		}
		return []segment{{series: c.series, value: c.vals[0]}}
	}
	var out []segment
	var cum int64
	for i, v := range c.vals {
		if v > 0 {
			out = append(out, segment{series: i, value: v, from: cum})
		}
		cum += v
	}
	return out
}

type segment struct {
	series      int
	value, from int64
}

// buildChart computes the geometry, the legend and the numbers table.
func buildChart(c view.Chart) chartModel {
	d := normalize(c)
	m := chartModel{
		TitleID:      d.id + "-title",
		DescID:       d.id + "-desc",
		Title:        cleanText(c.Title, maxTextRunes),
		Summary:      cleanText(c.Summary, maxTextRunes),
		NumbersLabel: "Numbers",
	}
	if d.maxTot == 0 {
		m.Empty = cleanText(c.Empty, maxTextRunes)
		if m.Empty == "" {
			m.Empty = "Nothing to show."
		}
		return m
	}

	// Hatch patterns for the series classes without a status meaning.
	var hasS2, hasS3 bool
	for _, s := range d.series {
		switch {
		case s.Class == view.ChartS2 && !hasS2:
			hasS2 = true
			m.Patterns = append(m.Patterns, chartPattern{ID: d.id + "-s2", Class: "ch-s2-base", Diagonal: true})
		case s.Class == view.ChartS3 && !hasS3:
			hasS3 = true
			m.Patterns = append(m.Patterns, chartPattern{ID: d.id + "-s3", Class: "ch-s3-base"})
		}
	}

	var height float64
	switch c.Kind {
	case view.ChartBars, view.ChartStackedBars:
		height = layoutHorizontal(&m, d)
	default:
		height = layoutVertical(&m, d)
	}
	if c.Legend {
		height = layoutLegend(&m, d, height)
	}
	m.ViewBox = "0 0 " + num(chartWidth) + " " + num(math.Ceil(height))
	buildTable(&m, d, c)
	return m
}

func patternFill(d chartData, class view.ChartClass) string {
	switch class { //nolint:exhaustive // only the hatched classes have a pattern
	case view.ChartS2:
		return "url(#" + d.id + "-s2)"
	case view.ChartS3:
		return "url(#" + d.id + "-s3)"
	}
	return ""
}

func (d chartData) tooltip(c chartCat, s segment) string {
	t := c.name + ": " + groupInt(s.value)
	if d.tipSeries {
		t += " " + d.series[s.series].Label
	}
	return t
}

func layoutVertical(m *chartModel, d chartData) float64 {
	top, step := niceAxis(d.maxTot)
	left := math.Max(24, digitsWidth(top)+chartPad+2)
	plotW := chartWidth - left - chartPad
	bottom := plotTop + plotHeight
	y := func(v float64) float64 { return bottom - v/float64(top)*plotHeight }

	for v := int64(0); v <= top; v += step {
		class := "ch-grid"
		if v == 0 {
			class = "ch-axis"
		}
		yy := num(y(float64(v)))
		m.Lines = append(m.Lines, chartLine{X1: num(left), Y1: yy, X2: num(chartWidth - chartPad), Y2: yy, Class: class})
		m.Texts = append(m.Texts, chartText{X: num(left - 6), Y: num(y(float64(v)) + 4), Text: groupInt(v), Class: "ch-label ch-end"})
	}

	n := float64(len(d.cats))
	slot := plotW / n
	barW := math.Min(slot*0.7, maxBarWidth)
	maxLabel := 0
	for _, c := range d.cats {
		maxLabel = max(maxLabel, utf8.RuneCountInString(c.label))
	}
	every := int(math.Ceil((float64(maxLabel)*glyphWidth + 6) / slot))
	if every < 1 {
		every = 1
	}
	for i, c := range d.cats {
		cx := left + slot*(float64(i)+0.5)
		x := cx - barW/2
		for _, s := range d.segments(c) {
			h := math.Max(float64(s.value)/float64(top)*plotHeight, minSegment)
			base := y(float64(s.from))
			class := d.series[s.series].Class
			m.Rects = append(m.Rects, chartRect{
				X: num(x), Y: num(base - h), W: num(barW), H: num(h),
				Class: "ch-bar ch-" + string(class), Fill: patternFill(d, class), Title: d.tooltip(c, s),
			})
		}
		if c.total > 0 {
			vt := groupInt(c.total)
			if textWidth(vt) <= slot-2 {
				ty := y(float64(c.total)) - 4
				m.Texts = append(m.Texts, chartText{X: num(cx), Y: num(ty), Text: vt, Class: "ch-label ch-mid"})
			}
		}
		if i%every == 0 && c.label != "" {
			m.Texts = append(m.Texts, chartText{X: num(cx), Y: num(bottom + 16), Text: c.label, Class: "ch-label ch-mid"})
		}
	}
	return bottom + 24
}

func layoutHorizontal(m *chartModel, d chartData) float64 {
	valueW := digitsWidth(d.maxTot) + chartPad
	left := chartPad + nameWidth + chartPad
	plotW := chartWidth - left - valueW - chartPad
	top := chartPad / 2
	rows := float64(len(d.cats))
	m.Lines = append(m.Lines, chartLine{X1: num(left), Y1: num(top), X2: num(left), Y2: num(top + rows*rowHeight), Class: "ch-axis"})
	for i, c := range d.cats {
		rowTop := top + float64(i)*rowHeight
		by := rowTop + (rowHeight-barThickness)/2
		cy := rowTop + rowHeight/2
		if c.label != "" {
			m.Texts = append(m.Texts, chartText{X: num(left - chartPad), Y: num(cy + 4), Text: c.label, Class: "ch-label ch-end"})
		}
		var end float64
		for _, s := range d.segments(c) {
			w := math.Max(float64(s.value)/float64(d.maxTot)*plotW, minSegment)
			start := float64(s.from) / float64(d.maxTot) * plotW
			class := d.series[s.series].Class
			m.Rects = append(m.Rects, chartRect{
				X: num(left + start), Y: num(by), W: num(w), H: num(barThickness),
				Class: "ch-bar ch-" + string(class), Fill: patternFill(d, class), Title: d.tooltip(c, s),
			})
			end = math.Max(end, start+w)
		}
		m.Texts = append(m.Texts, chartText{X: num(left + end + 6), Y: num(cy + 4), Text: groupInt(c.total), Class: "ch-label"})
	}
	return top + rows*rowHeight + chartPad
}

// layoutLegend appends the legend (swatch plus text, wrapped) below the plot
// and returns the new height.
func layoutLegend(m *chartModel, d chartData, height float64) float64 {
	x, y := chartPad, height+chartPad
	for _, s := range d.series {
		w := swatchSize + 4 + textWidth(s.Label) + 16
		if x > chartPad && x+w > chartWidth-chartPad {
			x = chartPad
			y += legendRow
		}
		m.Rects = append(m.Rects, chartRect{
			X: num(x), Y: num(y), W: num(swatchSize), H: num(swatchSize),
			Class: "ch-bar ch-" + string(s.Class), Fill: patternFill(d, s.Class),
		})
		m.Texts = append(m.Texts, chartText{X: num(x + swatchSize + 4), Y: num(y + swatchSize), Text: s.Label, Class: "ch-label"})
		x += w
	}
	return y + legendRow
}

func buildTable(m *chartModel, d chartData, c view.Chart) {
	first := cleanText(c.CategoryHeader, maxSeriesRunes)
	if first == "" {
		first = "Category"
	}
	m.Headers = []chartCell{{Text: first}}
	if d.stacked {
		for _, s := range d.series {
			m.Headers = append(m.Headers, chartCell{Text: s.Label, Num: true})
		}
		m.Headers = append(m.Headers, chartCell{Text: "Total", Num: true})
	} else {
		v := cleanText(c.ValueHeader, maxSeriesRunes)
		if v == "" {
			v = "Count"
		}
		m.Headers = append(m.Headers, chartCell{Text: v, Num: true})
		if c.SeriesHeader != "" {
			m.Headers = append(m.Headers, chartCell{Text: cleanText(c.SeriesHeader, maxSeriesRunes)})
		}
	}
	for _, cat := range d.cats {
		row := chartRow{Name: cat.name}
		if d.stacked {
			for _, v := range cat.vals {
				row.Cells = append(row.Cells, chartCell{Text: groupInt(v), Num: true})
			}
			row.Cells = append(row.Cells, chartCell{Text: groupInt(cat.total), Num: true})
		} else {
			row.Cells = append(row.Cells, chartCell{Text: groupInt(cat.total), Num: true})
			if c.SeriesHeader != "" {
				row.Cells = append(row.Cells, chartCell{Text: d.series[cat.series].Label})
			}
		}
		m.Rows = append(m.Rows, row)
	}
}
