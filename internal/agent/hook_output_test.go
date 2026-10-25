package agent

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestSanitizeHookOutputIsBoundedUTF8AndPlainText(t *testing.T) {
	t.Parallel()
	data := []byte("first line\n" + strings.Repeat("x", 2000) + "\x00\xff\nlast line\x1b[31m")
	output := sanitizeHookOutput(data)
	if len(output) > hookOutputLimit || !utf8.ValidString(output) {
		t.Fatalf("invalid sanitized output: len=%d valid=%v", len(output), utf8.ValidString(output))
	}
	for _, r := range output {
		if r != '\n' && unicode.IsControl(r) {
			t.Fatalf("control character remains: %q", r)
		}
	}
	if strings.Contains(output, "first line") || !strings.Contains(output, "last line") {
		t.Fatalf("output is not the sanitized tail: %q", output)
	}
}

func TestAgentHookHelper(t *testing.T) {
	if os.Getenv("MYOWNPKI_AGENT_HOOK_HELPER") != "1" {
		return
	}
	_, _ = fmt.Fprint(os.Stderr, os.Getenv("MYOWNPKI_AGENT_HOOK_OUTPUT"))
	os.Exit(1)
}

func TestRunHookFailureLogsAndReturnsSanitizedStderr(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYOWNPKI_AGENT_HOOK_HELPER", "1")
	t.Setenv("MYOWNPKI_AGENT_HOOK_OUTPUT", "bind() to 0.0.0.0:443 failed\nlast detail\x1b")
	var logs bytes.Buffer
	a := &Agent{cfg: &Config{Hooks: map[string][]string{"test": {executable, "-test.run=^TestAgentHookHelper$"}}},
		log: slog.New(slog.NewJSONHandler(&logs, nil))}
	hookErr := a.runHook(t.Context(), "test")
	if hookErr == nil || !strings.Contains(hookErr.Error(), "output: bind() to 0.0.0.0:443 failed") || !strings.Contains(hookErr.Error(), "last detail") {
		t.Fatalf("hook error lacks stderr: %v", hookErr)
	}
	if strings.ContainsRune(hookErr.Error(), '\x1b') {
		t.Fatal("hook error contains a control character")
	}
	for _, want := range []string{`"level":"ERROR"`, `"hook":"test"`, `"output"`, "bind() to 0.0.0.0:443 failed", "last detail"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("hook log lacks %q: %s", want, logs.String())
		}
	}
}
