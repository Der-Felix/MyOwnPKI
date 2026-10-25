package agent

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	hookOutputCapture = 4096
	hookOutputLimit   = 1024
)

type tailWriter struct{ data []byte }

// clipUTF8 limits valid UTF-8 text to a byte budget without splitting a rune.
// With keepTail it keeps the end, otherwise the beginning.
func clipUTF8(text string, limit int, keepTail bool) string {
	if limit <= 0 {
		return ""
	}
	if len(text) <= limit {
		return text
	}
	if keepTail {
		start := len(text) - limit
		for start < len(text) && !utf8.RuneStart(text[start]) {
			start++
		}
		return text[start:]
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

const deployErrorLimit = 1000

// clipDeployErrorText keeps the error prefix and, when stderr follows, its
// tail. This preserves the hook name and the final diagnostic line.
func clipDeployErrorText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	const marker = "; output: "
	index := strings.Index(text, marker)
	if index < 0 {
		return clipUTF8(text, limit, false)
	}
	prefix := text[:index+len(marker)]
	if len(prefix) >= limit {
		return clipUTF8(prefix, limit, false)
	}
	return prefix + clipUTF8(text[len(prefix):], limit-len(prefix), true)
}

func hookErrorText(name string, cause error, output string) string {
	prefix := fmt.Sprintf("hook %q failed: %v", name, cause)
	if output == "" {
		return clipDeployErrorText(prefix, deployErrorLimit)
	}
	return clipDeployErrorText(prefix+"; output: "+output, deployErrorLimit)
}

func joinedDeployError(cause, rollbackErr error) string {
	suffix := clipDeployErrorText("; rollback failed: "+rollbackErr.Error(), deployErrorLimit/2)
	return clipDeployErrorText(cause.Error(), deployErrorLimit-len(suffix)) + suffix
}

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
	clean := clipUTF8(out.String(), hookOutputLimit, true)
	if len(out.String()) > hookOutputLimit {
		if newline := strings.IndexByte(clean, '\n'); newline >= 0 {
			clean = clean[newline+1:]
		}
	}
	return strings.TrimSpace(clean)
}
