package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// challengePath is where http-01 looks – for enrollment as for ACME, so the
// nginx location the admin made for ACME serves both.
const challengePath = "/.well-known/acme-challenge/"

// writtenFile records the token files the agent wrote into webroots, so a
// crash between place and remove leaves nothing behind for long.
const writtenFile = "webroot-files.json"

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// responder answers the server's http-01 check.
type responder interface {
	place(token, content string) error
	remove(token string)
}

// newResponder returns the responder for a challenge mode.
func newResponder(mode, webrootDir string, paths []string, st state, standaloneAddr string, log *slog.Logger) responder {
	if mode == ChallengeWebroot {
		return &webroot{dir: webrootDir, paths: paths, st: st}
	}
	return &standalone{addr: standaloneAddr, log: log}
}

// challengeDir is challengePath relative to a webroot.
var challengeDir = filepath.Join(".well-known", "acme-challenge")

// webroot writes the token file into the webroot of the web server that
// already answers on port 80 (nginx), and deletes it afterwards.
//
// The agent runs as root, the webroot often belongs to the web server's
// user, who could swap .well-known/acme-challenge for a symlink between a
// check and the write. So the webroot is checked once against paths
// (resolveUnder), and then everything below it – creating the directory,
// writing a temporary file, renaming, deleting – goes through an os.Root
// opened on it: a path that leads out of the webroot, also through a
// symlink placed later, fails.
type webroot struct {
	dir   string
	paths []string
	st    state
	mu    sync.Mutex
}

// open checks the webroot against paths and opens it as an os.Root.
func (w *webroot) open() (*os.Root, string, error) {
	resolved, err := resolveUnder(w.paths, w.dir)
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(resolved)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("webroot %s does not exist – it is the directory your web server serves /.well-known/acme-challenge/ from", resolved)
	} else if err != nil {
		return nil, "", fmt.Errorf("webroot: %w", err)
	}
	return root, resolved, nil
}

func checkToken(token string) error {
	if !tokenRE.MatchString(token) {
		return fmt.Errorf("check token %q: not a token", clip(token))
	}
	return nil
}

func (w *webroot) place(token, content string) error {
	if err := checkToken(token); err != nil {
		return err
	}
	root, resolved, err := w.open()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := root.MkdirAll(challengeDir, 0o755); err != nil { // 0755: the web server must read it
		return fmt.Errorf("webroot %s: %w", resolved, err)
	}
	if err := w.st.addWritten(writtenEntry{Root: resolved, Token: token}); err != nil {
		return err
	}
	// 0644: the web server's user reads it; the content is no secret – it
	// is what the server fetches over plain HTTP anyway.
	if err := rootWrite(root, filepath.Join(challengeDir, token), []byte(content), 0o644); err != nil {
		return fmt.Errorf("webroot %s: %w", resolved, err)
	}
	return nil
}

func (w *webroot) remove(token string) {
	if checkToken(token) != nil {
		return
	}
	root, resolved, err := w.open()
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := root.Remove(filepath.Join(challengeDir, token)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return // keep the record: the next startup retries the cleanup
	}
	_ = w.st.dropWritten(writtenEntry{Root: resolved, Token: token})
}

// rootWrite writes name inside root atomically: a new temporary file next
// to it (O_EXCL, never an existing file or link), fsync, rename – every
// step through root.
func rootWrite(root *os.Root, name string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(filepath.Dir(name), "."+filepath.Base(name)+".tmp")
	_ = root.Remove(tmp) // a leftover of a crash
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	if err := f.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Rename(tmp, name)
}

// standalone listens on port 80 itself – only while a check runs.
type standalone struct {
	addr   string
	log    *slog.Logger
	mu     sync.Mutex
	tokens map[string]string
	srv    *http.Server
}

func (s *standalone) place(token, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens == nil {
		s.tokens = map[string]string{}
	}
	s.tokens[token] = content
	if s.srv != nil {
		return nil
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.addr)
	if err != nil {
		delete(s.tokens, token)
		return fmt.Errorf("challenge standalone: port %s is in use or not allowed (%w) – with a web server on port 80 use challenge: webroot", s.addr, err)
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func(srv *http.Server) {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Warn("challenge listener stopped", slog.Any("error", err))
		}
	}(s.srv)
	return nil
}

func (s *standalone) serve(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, challengePath)
	s.mu.Lock()
	content, found := s.tokens[token]
	s.mu.Unlock()
	if r.Method != http.MethodGet || !ok || !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, content) // #nosec G705 -- our own key authorization, as text/plain
}

func (s *standalone) remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	if len(s.tokens) == 0 && s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
		s.srv = nil
	}
}

// resolveUnder resolves the symlinks of the existing part of p and checks
// that the result still lies under one of dirs (themselves resolved): a
// symlink in a webroot must not lead the agent to write elsewhere.
func resolveUnder(dirs []string, p string) (string, error) {
	resolved, err := resolveExisting(p)
	if err != nil {
		return "", err
	}
	var roots []string
	for _, d := range dirs {
		r, rerr := resolveExisting(d)
		if rerr == nil {
			roots = append(roots, r)
		}
	}
	if !Under(roots, resolved) {
		return "", fmt.Errorf("%s leads to %s, which is not under paths – the agent writes only there", p, resolved)
	}
	return resolved, nil
}

// resolveExisting runs EvalSymlinks on the longest existing prefix of p.
func resolveExisting(p string) (string, error) {
	p = filepath.Clean(p)
	var rest []string
	for {
		r, err := filepath.EvalSymlinks(p)
		if err == nil {
			slices.Reverse(rest)
			return filepath.Join(append([]string{r}, rest...)...), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", err
		}
		rest = append(rest, filepath.Base(p))
		p = parent
	}
}

// writtenEntry is a token file the agent wrote: the webroot (as resolved
// and checked against paths) and the token – the file is
// .well-known/acme-challenge/<token> below it.
type writtenEntry struct {
	Root  string `json:"root"`
	Token string `json:"token"`
}

// addWritten and dropWritten keep the list of token files in webroots.
func (s state) addWritten(e writtenEntry) error {
	list := s.written()
	if !slices.Contains(list, e) {
		list = append(list, e)
	}
	return s.saveWritten(list)
}

func (s state) dropWritten(e writtenEntry) error {
	return s.saveWritten(slices.DeleteFunc(s.written(), func(x writtenEntry) bool { return x == e }))
}

func (s state) written() []writtenEntry {
	data, err := os.ReadFile(s.path(writtenFile))
	if err != nil {
		return nil
	}
	var list []writtenEntry
	_ = json.Unmarshal(data, &list)
	return list
}

func (s state) saveWritten(list []writtenEntry) error {
	if len(list) == 0 {
		err := os.Remove(s.path(writtenFile))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return writeFile(s.path(writtenFile), data, 0o600)
}

// cleanupWritten deletes token files a crashed run left in webroots – only
// .well-known/acme-challenge/<token> below a recorded webroot, through an
// os.Root opened on it, so nothing outside can be hit.
func (s state) cleanupWritten() {
	var remaining []writtenEntry
	for _, e := range s.written() {
		if checkToken(e.Token) != nil {
			continue
		}
		root, err := os.OpenRoot(e.Root)
		if err != nil {
			remaining = append(remaining, e)
			continue
		}
		if err := root.Remove(filepath.Join(challengeDir, e.Token)); err != nil && !errors.Is(err, os.ErrNotExist) {
			remaining = append(remaining, e)
		}
		_ = root.Close()
	}
	_ = s.saveWritten(remaining)
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
