package legacy

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// The key/value files of pki.sh (pki.conf, ca.meta, cert.meta) are read like
// its load_kv: line by line, never executed. Only upper-case keys; a value
// is "double quoted", 'single quoted' or bare up to a # comment.
var kvLine = regexp.MustCompile(`^[ \t]*([A-Z_][A-Z0-9_]*)[ \t]*=(.*)$`)

// parseKV reads a key/value file. Lines it can't read are returned as
// notes; unknown keys are kept (the caller picks what it needs).
func parseKV(data []byte) (map[string]string, []string) {
	out := map[string]string{}
	var notes []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := kvLine.FindStringSubmatch(line)
		if m == nil {
			notes = append(notes, "ignored line: "+clip(trimmed, 80))
			continue
		}
		out[m[1]] = kvValue(strings.TrimSpace(m[2]))
	}
	if err := sc.Err(); err != nil {
		notes = append(notes, "file not read to the end: "+err.Error())
	}
	return out, notes
}

func kvValue(v string) string {
	for _, q := range []string{`"`, `'`} {
		if strings.HasPrefix(v, q) {
			if end := strings.Index(v[1:], q); end >= 0 {
				return v[1 : 1+end]
			}
		}
	}
	if i := strings.Index(v, "#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// clip shortens text from the files for messages.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
