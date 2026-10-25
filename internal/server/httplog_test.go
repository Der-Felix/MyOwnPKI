package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestHTTPErrorLogLevels(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.NewLogLogger(httpErrorLogHandler{Handler: logger.Handler()}, slog.LevelDebug).Print("http2: panic serving example")
	slog.NewLogLogger(httpErrorLogHandler{Handler: logger.Handler()}, slog.LevelDebug).Print("http: TLS handshake error from scanner")
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"level":"ERROR"`) || !strings.Contains(lines[0], "panic serving") {
		t.Fatalf("panic is not an error log: %s", logs.String())
	}
	if !strings.Contains(lines[1], `"level":"DEBUG"`) || !strings.Contains(lines[1], "TLS handshake") {
		t.Fatalf("ordinary server noise is not debug: %s", logs.String())
	}
}

func TestHTTPErrorLogKeepsPanicAtInfoLevel(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	bridge := slog.NewLogLogger(httpErrorLogHandler{Handler: logger.Handler()}, slog.LevelDebug)
	bridge.Print("http2: panic serving example")
	bridge.Print("http: TLS handshake error from scanner")
	if strings.Contains(logs.String(), "TLS handshake") {
		t.Fatalf("info logger received debug noise: %s", logs.String())
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"level":"ERROR"`) || !strings.Contains(lines[0], "panic serving") {
		t.Fatalf("info logger lost the panic: %s", logs.String())
	}
}
