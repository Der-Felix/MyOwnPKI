package trust

import (
	"strconv"
	"strings"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// join puts one command on each line of a preformatted block (templ would join
// lines of plain text).
func join(lines []string) string { return strings.Join(lines, "\n") }
