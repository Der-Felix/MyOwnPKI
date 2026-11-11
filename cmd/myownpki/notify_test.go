package main

import (
	"bytes"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/notify"
)

func TestNotifyTest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		d, err := notify.ParseDigest(body)
		if err != nil || len(d.Events) != 1 || d.Events[0].State != notify.Test || r.Header.Get(notify.SignatureHeader) != notify.Sign([]byte("key"), body) {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	q := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	ca := write("ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})))
	secret := write("secret", "key\n")
	withHook := write("hook.yaml", "data_dir: \""+q(dir)+"\"\nnotify:\n  webhook:\n    url: \""+ts.URL+"/hook?token=t0ken\"\n    secret_file: \""+q(secret)+"\"\n    ca_file: \""+q(ca)+"\"\n")
	withoutCA := write("noca.yaml", "data_dir: \""+q(dir)+"\"\nnotify:\n  webhook:\n    url: \""+ts.URL+"/hook?token=t0ken\"\n    secret_file: \""+q(secret)+"\"\n")
	none := write("none.yaml", "data_dir: \""+q(dir)+"\"\n")

	for _, tc := range []struct {
		name     string
		args     []string
		code     int
		stdout   string
		stderr   string
		notInAny string
	}{
		{"sent", []string{"notify", "test", "--config", withHook}, 0, "webhook  sent to 127.0.0.1", "", "t0ken"},
		{"untrusted certificate", []string{"notify", "test", "--config", withoutCA}, 1, "", "webhook  FAILED: webhook 127.0.0.1", "t0ken"},
		{"no channel", []string{"notify", "test", "--config", none}, 1, "", "No notification channel is configured", ""},
		{"other channel only", []string{"notify", "test", "--config", withHook, "--channel", "email"}, 1, "", "No notification channel is configured", ""},
		{"unknown channel", []string{"notify", "test", "--config", withHook, "--channel", "sms"}, 2, "", "Usage:", ""},
		{"no subcommand", []string{"notify"}, 2, "", "Usage:", ""},
	} {
		var stdout, stderr bytes.Buffer
		code := run(t.Context(), tc.args, &stdout, &stderr)
		if code != tc.code || !strings.Contains(stdout.String(), tc.stdout) || !strings.Contains(stderr.String(), tc.stderr) ||
			(tc.notInAny != "" && strings.Contains(stdout.String()+stderr.String(), tc.notInAny)) {
			t.Errorf("%s: code %d\nstdout: %s\nstderr: %s", tc.name, code, stdout.String(), stderr.String())
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the receiver got %d test messages, want 1", n)
	}
}
