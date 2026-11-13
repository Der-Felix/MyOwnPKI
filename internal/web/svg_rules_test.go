package web

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The web tests forbid inline <svg> (the UI has no icons, frontend.md) with
// one narrow exception: the chart component (internal/web/components/chart.templ,
// docs/PHASE3.md D1) writes exactly one tag shape, and nothing dangerous may
// sit inside it. svgViolations is that rule; both the render tests and the
// .templ scan use it.

var (
	reSVGOpen = regexp.MustCompile(`(?i)<svg[\s>]`)
	// reRenderedChartSVG is the one tag shape a rendered page may contain.
	reRenderedChartSVG = regexp.MustCompile(`^<svg class="chart-svg" role="img" aria-labelledby="[a-z0-9 -]+" viewBox="0 0 [0-9]+ [0-9]+">`)
	// reSourceChartSVG is the same shape in chart.templ.
	reSourceChartSVG = regexp.MustCompile(`^<svg class="chart-svg" role="img" aria-labelledby=\{[^}]+\} viewBox=\{[^}]+\}>`)
	// reSVGBad is what must not appear anywhere between <svg and </svg>:
	// script, foreign content, images, references, animation, styles, links,
	// event handlers and javascript: URLs.
	reSVGBad = regexp.MustCompile(`(?i)<(script|foreignObject|image|use|style|a|set|animate\w*|iframe|object|embed|link|mpath|switch)[\s>/]` +
		`|\s(href|xlink:href|src|style)\s*=|\son[a-z]+\s*=|javascript:`)
)

// svgViolations returns every way src breaks the SVG rule: an <svg> tag that
// is not the chart shape (shape matches the text starting at the tag), one
// that is nested or never closed, and dangerous content inside one.
func svgViolations(src string, shape *regexp.Regexp) []string {
	var out []string
	for _, loc := range reSVGOpen.FindAllStringIndex(src, -1) {
		from := loc[0]
		if !shape.MatchString(src[from:]) {
			out = append(out, "svg tag that is not the chart shape: "+clip(src[from:], 80))
			continue
		}
		end := strings.Index(src[from:], "</svg>")
		if end < 0 {
			out = append(out, "svg tag without </svg>: "+clip(src[from:], 80))
			continue
		}
		inner := src[from+len("<svg") : from+end]
		if reSVGOpen.MatchString(inner) {
			out = append(out, "nested svg: "+clip(src[from:], 80))
		}
		if m := reSVGBad.FindString(inner); m != "" {
			out = append(out, fmt.Sprintf("forbidden content %q inside svg", m))
		}
	}
	return out
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func TestSVGRule(t *testing.T) {
	t.Parallel()
	const open = `<svg class="chart-svg" role="img" aria-labelledby="chart-x-title chart-x-desc" viewBox="0 0 360 200">`
	good := open + `<title id="chart-x-title">T</title><desc id="chart-x-desc">D</desc><line class="ch-axis" x1="0" y1="0" x2="1" y2="1"></line>` +
		`<rect class="ch-bar ch-ok" x="1" y="2" width="3" height="4" fill="url(#chart-x-s2)"><title>W47: 3</title></rect><text class="ch-label" x="1" y="1">W47</text></svg>`
	if v := svgViolations("<p>"+good+"</p>"+good, reRenderedChartSVG); len(v) != 0 {
		t.Fatalf("the chart shape is refused: %v", v)
	}
	if v := svgViolations("<p>no svg here</p>", reRenderedChartSVG); len(v) != 0 {
		t.Fatalf("page without svg refused: %v", v)
	}

	bad := map[string]string{
		"icon":              `<svg width="16" height="16"><path d="M0 0"/></svg>`,
		"bare svg":          `<svg>` + `</svg>`,
		"extra attribute":   `<svg class="chart-svg" role="img" aria-labelledby="a" viewBox="0 0 1 1" onload="x()"></svg>`,
		"style attribute":   `<svg class="chart-svg" role="img" aria-labelledby="a" viewBox="0 0 1 1" style="width:1px"></svg>`,
		"xmlns":             `<svg xmlns="http://www.w3.org/2000/svg" class="chart-svg" role="img" aria-labelledby="a" viewBox="0 0 1 1"></svg>`,
		"uppercase":         `<SVG class="chart-svg" role="img" aria-labelledby="a" viewBox="0 0 1 1"></SVG>`,
		"script":            open + `<script>alert(1)</script></svg>`,
		"foreignObject":     open + `<foreignObject><p>x</p></foreignObject></svg>`,
		"image":             open + `<image href="/x.png"/></svg>`,
		"use":               open + `<use href="#a"/></svg>`,
		"href":              open + `<rect href="x"></rect></svg>`,
		"xlink":             open + `<rect xlink:href="x"></rect></svg>`,
		"event":             open + `<rect onclick="x()"></rect></svg>`,
		"inner style attr":  open + `<rect style="fill:red"></rect></svg>`,
		"style tag":         open + `<style>rect{fill:red}</style></svg>`,
		"link":              open + `<a href="/x"><text>x</text></a></svg>`,
		"animate":           open + `<animate attributeName="x"/></svg>`,
		"set":               open + `<set attributeName="x"/></svg>`,
		"javascript url":    open + `<rect fill="javascript:x"></rect></svg>`,
		"nested svg":        open + open + `</svg></svg>`,
		"never closed":      open + `<rect></rect>`,
		"unclosed in page":  `<p>` + open + `<title>x</title>`,
		"icon after a good": open + `</svg><svg viewBox="0 0 1 1"></svg>`,
	}
	for name, src := range bad {
		if v := svgViolations(src, reRenderedChartSVG); len(v) == 0 {
			t.Errorf("%s: not refused: %s", name, src)
		}
	}

	// A hostile name is escaped text, not markup, so it is no violation.
	escaped := open + `<title>&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</title></svg>`
	if v := svgViolations(escaped, reRenderedChartSVG); len(v) != 0 {
		t.Errorf("escaped text refused: %v", v)
	}

	// The shape in the template source.
	const srcOpen = `<svg class="chart-svg" role="img" aria-labelledby={ m.TitleID + " " + m.DescID } viewBox={ m.ViewBox }>`
	if v := svgViolations(srcOpen+`<rect class={ r.Class }></rect></svg>`, reSourceChartSVG); len(v) != 0 {
		t.Errorf("template shape refused: %v", v)
	}
	if v := svgViolations(`<svg class="chart-svg" role="img" viewBox={ m.ViewBox }></svg>`, reSourceChartSVG); len(v) == 0 {
		t.Error("another template shape not refused")
	}
}
