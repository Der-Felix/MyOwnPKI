package agent

import (
	"fmt"
	"strings"
)

// unifiedDiff renders a unified diff with three lines of context for the
// --dry-run output. It trims the common head and tail and compares the rest
// with a longest-common-subsequence table; files here are small, and a
// changed middle too large for the table is shown as one removed and one
// added block. A missing old file diffs against /dev/null.
func unifiedDiff(name string, old []byte, oldExists bool, updated []byte) string {
	if oldExists && string(old) == string(updated) {
		return ""
	}
	a, b := splitLines(string(old)), splitLines(string(updated))
	head := 0
	for head < len(a) && head < len(b) && a[head] == b[head] {
		head++
	}
	tail := 0
	for tail < len(a)-head && tail < len(b)-head && a[len(a)-1-tail] == b[len(b)-1-tail] {
		tail++
	}
	midA, midB := a[head:len(a)-tail], b[head:len(b)-tail]

	type edit struct {
		op   byte // ' ', '-', '+'
		text string
	}
	var edits []edit
	for _, l := range a[:head] {
		edits = append(edits, edit{' ', l})
	}
	if len(midA)*len(midB) > 4_000_000 {
		for _, l := range midA {
			edits = append(edits, edit{'-', l})
		}
		for _, l := range midB {
			edits = append(edits, edit{'+', l})
		}
	} else {
		// lcs[i][j]: length of the common subsequence of midA[i:] and midB[j:].
		lcs := make([][]int, len(midA)+1)
		for i := range lcs {
			lcs[i] = make([]int, len(midB)+1)
		}
		for i := len(midA) - 1; i >= 0; i-- {
			for j := len(midB) - 1; j >= 0; j-- {
				if midA[i] == midB[j] {
					lcs[i][j] = lcs[i+1][j+1] + 1
				} else {
					lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
				}
			}
		}
		i, j := 0, 0
		for i < len(midA) || j < len(midB) {
			switch {
			case i < len(midA) && j < len(midB) && midA[i] == midB[j]:
				edits = append(edits, edit{' ', midA[i]})
				i++
				j++
			case i < len(midA) && (j == len(midB) || lcs[i+1][j] >= lcs[i][j+1]):
				edits = append(edits, edit{'-', midA[i]})
				i++
			default:
				edits = append(edits, edit{'+', midB[j]})
				j++
			}
		}
	}
	for _, l := range a[len(a)-tail:] {
		edits = append(edits, edit{' ', l})
	}

	const context = 3
	var b2 strings.Builder
	from := "a/" + name
	if !oldExists {
		from = "/dev/null"
	}
	fmt.Fprintf(&b2, "--- %s\n+++ b/%s\n", from, name)
	oldLine, newLine := 1, 1
	for i := 0; i < len(edits); {
		if edits[i].op == ' ' {
			oldLine++
			newLine++
			i++
			continue
		}
		// A hunk starts up to three lines before this change and runs until
		// more than six unchanged lines separate two changes.
		start := max(i-context, 0)
		for start < i && edits[start].op != ' ' {
			start++
		}
		end := i
		for last := i; last < len(edits); last++ {
			if edits[last].op != ' ' {
				end = last
			} else if last-end > 2*context {
				break
			}
		}
		end = min(end+context, len(edits)-1)
		ctxBefore := i - start
		oldStart, newStart := oldLine-ctxBefore, newLine-ctxBefore
		var oldCount, newCount int
		var body strings.Builder
		for _, e := range edits[start : end+1] {
			body.WriteByte(e.op)
			body.WriteString(e.text)
			body.WriteByte('\n')
			if e.op != '+' {
				oldCount++
			}
			if e.op != '-' {
				newCount++
			}
		}
		if oldCount == 0 {
			oldStart--
		}
		if newCount == 0 {
			newStart--
		}
		fmt.Fprintf(&b2, "@@ -%d,%d +%d,%d @@\n%s", oldStart, oldCount, newStart, newCount, body.String())
		for _, e := range edits[i : end+1] {
			if e.op != '+' {
				oldLine++
			}
			if e.op != '-' {
				newLine++
			}
		}
		i = end + 1
	}
	return b2.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
