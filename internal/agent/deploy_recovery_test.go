package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentStartupCleansChallengeFiles(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx)
	www := filepath.Join(r.a.cfg.Paths[0], "www")
	if err := os.Mkdir(www, 0o750); err != nil {
		t.Fatal(err)
	}
	responder := newResponder(ChallengeWebroot, www, r.a.cfg.Paths, r.a.st, "", r.a.log)
	token := strings.Repeat("D", 43)
	if err := responder.place(token, "public key authorization"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(www, challengeDir, token)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a crashed pass's challenge file remained")
	}
}

func TestChallengeCleanupKeepsFailedRecords(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx)
	entry := writtenEntry{Root: filepath.Join(r.a.cfg.Paths[0], "not-mounted"), Token: strings.Repeat("E", 43)}
	if err := r.a.st.addWritten(entry); err != nil {
		t.Fatal(err)
	}
	r.a.st.cleanupWritten()
	if len(r.a.st.written()) != 1 {
		t.Fatal("a failed cleanup was forgotten")
	}
	if err := os.MkdirAll(filepath.Join(entry.Root, challengeDir), 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(entry.Root, challengeDir, entry.Token)
	if err := os.WriteFile(path, []byte("public key authorization"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.a.st.cleanupWritten()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) || len(r.a.st.written()) != 0 {
		t.Fatal("cleanup did not retry the saved entry")
	}
}
