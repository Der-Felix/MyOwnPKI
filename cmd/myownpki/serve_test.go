package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServeUntilDoneShutsDownCleanly: Ctrl+C (context cancel) stops the server
// gracefully with exit code 0.
func TestServeUntilDoneShutsDownCleanly(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- serveUntilDone(ctx, srv, ln, slog.New(slog.DiscardHandler)) }()

	// The server answers before the shutdown …
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("server not reachable: %v", err)
	}
	_ = resp.Body.Close()

	// … and exits with 0 after it.
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestLogTimesAreUTC(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: utcTime}))
	log.Info("test")
	if !strings.Contains(buf.String(), "Z level=") {
		t.Errorf("log time is not UTC: %s", buf.String())
	}
}
