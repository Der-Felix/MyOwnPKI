package agentdist

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func populated(t *testing.T) *Store {
	t.Helper()
	s := New(t.TempDir(), "v0.3.1")
	for _, arch := range Arches {
		for _, format := range Formats {
			name, _ := s.Name(format, arch)
			if err := os.WriteFile(filepath.Join(s.dir, name), []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(s.dir, Checksums), []byte("sums\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManifestHashesFiles(t *testing.T) {
	t.Parallel()
	s := populated(t)
	manifest, err := s.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 7 {
		t.Fatalf("manifest has %d entries", len(manifest))
	}
	for _, artifact := range manifest {
		data, err := os.ReadFile(filepath.Join(s.dir, artifact.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if artifact.SHA256 != hex.EncodeToString(sum[:]) || artifact.Size != int64(len(data)) {
			t.Errorf("bad metadata for %s: %+v", artifact.Name, artifact)
		}
	}
	if _, err := s.Artifact("zip", "amd64"); !IsNotFound(err) {
		t.Errorf("unknown format: %v", err)
	}
}

func TestHandlerAnonymousGetHeadAndRefusals(t *testing.T) {
	t.Parallel()
	s := populated(t)
	h := s.Handler()
	name, _ := s.Name("deb", "amd64")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequestWithContext(t.Context(), method, BasePath+name, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/vnd.debian.binary-package" ||
			w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d %v", method, w.Code, w.Header())
		}
		if method == http.MethodHead && w.Body.Len() != 0 {
			t.Error("HEAD returned a body")
		}
		if method == http.MethodGet && w.Body.String() != name {
			t.Errorf("GET body %q", w.Body.String())
		}
	}
	for _, path := range []string{
		BasePath, BasePath + "missing.deb", BasePath + "../" + name, BasePath + "%2e%2e/" + name,
		BasePath + name + "/", "/other/" + name, BasePath + name + "?redirect=https://evil.example",
	} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, w.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, BasePath+name, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", method, w.Code)
		}
	}
}

func TestHandlerRefusesSymlinkAndMissingDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	s := populated(t)
	name, _ := s.Name("rpm", "arm64")
	path := filepath.Join(s.dir, name)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, BasePath+name, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("symlink: %d", w.Code)
	}
	missing := New(filepath.Join(s.dir, "missing"), "0.3.1").Handler()
	w = httptest.NewRecorder()
	missing.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, BasePath+Checksums, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing directory: %d", w.Code)
	}
}

func TestHandlerBoundsResponse(t *testing.T) {
	t.Parallel()
	s := populated(t)
	name, _ := s.Name("deb", "amd64")
	if err := os.WriteFile(filepath.Join(s.dir, name), []byte(strings.Repeat("x", MaxSumsSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := s.Artifact("deb", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, BasePath+name, nil))
	body, _ := io.ReadAll(w.Result().Body)
	if int64(len(body)) != artifact.Size {
		t.Fatalf("served %d bytes, want %d", len(body), artifact.Size)
	}
}
