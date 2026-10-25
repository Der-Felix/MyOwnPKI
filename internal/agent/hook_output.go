package agent

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	hookOutputCapture = 4096
	hookOutputLimit   = 1024
)

type tailWriter struct{ data []byte }

func (w *tailWriter) Write(p []byte) (int, error) {
	if len(p) >= hookOutputCapture {
		w.data = append(w.data[:0], p[len(p)-hookOutputCapture:]...)
		return len(p), nil
	}
	w.data = append(w.data, p...)
	if len(w.data) > hookOutputCapture {
		copy(w.data, w.data[len(w.data)-hookOutputCapture:])
		w.data = w.data[:hookOutputCapture]
	}
	return len(p), nil
}

func sanitizeHookOutput(data []byte) string {
	text := strings.ToValidUTF8(string(data), "�")
	var out strings.Builder
	for _, r := range text {
		if r == '\n' || !unicode.IsControl(r) {
			out.WriteRune(r)
		}
	}
	clean := out.String()
	if len(clean) > hookOutputLimit {
		start := len(clean) - hookOutputLimit
		for start < len(clean) && !utf8.RuneStart(clean[start]) {
			start++
		}
		clean = clean[start:]
		if newline := strings.IndexByte(clean, '\n'); newline >= 0 {
			clean = clean[newline+1:]
		}
	}
	return strings.TrimSpace(clean)
}
