// Package agentdist maps the exact server release to its immutable agent
// artifacts. It never derives a filesystem path from a request.
package agentdist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	BasePath       = "/agent-packages/"
	Checksums      = "checksums.txt"
	MaxPackageSize = 64 << 20
	MaxSumsSize    = 1 << 20
)

var (
	ErrNotFound = errors.New("agent artifact not found")
	Formats     = []string{"deb", "rpm", "tarball"}
	Arches      = []string{"amd64", "arm64"}
)

type Artifact struct {
	Name   string
	Format string
	Arch   string
	Size   int64
	SHA256 string
}

type Store struct {
	dir     string
	version string
}

func New(dir, version string) *Store {
	return &Store{dir: dir, version: strings.TrimPrefix(version, "v")}
}

func (s *Store) Version() string { return s.version }

func (s *Store) Name(format, arch string) (string, bool) {
	if format != Checksums && !validChoice(format, Formats) {
		return "", false
	}
	if format != Checksums && !validChoice(arch, Arches) {
		return "", false
	}
	if s.version == "" || s.version == "dev" || !validVersion(s.version) {
		return "", false
	}
	if format == Checksums {
		return Checksums, true
	}
	ext := format
	if format == "tarball" {
		ext = "tar.gz"
	}
	return "myownpki-agent_" + s.version + "_linux_" + arch + "." + ext, true
}

func validChoice(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validVersion(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '.' && r != '-' {
			return false
		}
	}
	return value != "" && !strings.HasPrefix(value, ".") && !strings.HasPrefix(value, "-")
}

func (s *Store) Manifest() ([]Artifact, error) {
	var out []Artifact
	for _, arch := range Arches {
		for _, format := range Formats {
			name, _ := s.Name(format, arch)
			artifact, err := s.inspect(name, format, arch)
			if err != nil {
				return nil, err
			}
			out = append(out, artifact)
		}
	}
	checksums, err := s.inspect(Checksums, Checksums, "")
	if err != nil {
		return nil, err
	}
	return append(out, checksums), nil
}

func (s *Store) Artifact(format, arch string) (Artifact, error) {
	name, ok := s.Name(format, arch)
	if !ok {
		return Artifact{}, ErrNotFound
	}
	return s.inspect(name, format, arch)
}

func (s *Store) inspect(name, format, arch string) (Artifact, error) {
	f, size, err := s.open(name)
	if err != nil {
		return Artifact{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil {
		return Artifact{}, fmt.Errorf("read agent artifact: %w", err)
	}
	if n != size {
		return Artifact{}, errors.New("agent artifact changed while being read")
	}
	return Artifact{Name: name, Format: format, Arch: arch, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func (s *Store) open(name string) (*os.File, int64, error) {
	expected, ok := s.requestName(name)
	if !ok || expected != name || s.dir == "" {
		return nil, 0, ErrNotFound
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, 0, ErrNotFound
	}
	defer func() { _ = root.Close() }()
	st, err := root.Lstat(name)
	if err != nil || !st.Mode().IsRegular() {
		return nil, 0, ErrNotFound
	}
	limit := int64(MaxPackageSize)
	if name == Checksums {
		limit = MaxSumsSize
	}
	if st.Size() <= 0 || st.Size() > limit {
		return nil, 0, ErrNotFound
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, 0, ErrNotFound
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != st.Size() || !os.SameFile(st, opened) {
		_ = f.Close()
		return nil, 0, ErrNotFound
	}
	return f, st.Size(), nil
}

func (s *Store) requestName(name string) (string, bool) {
	if name == Checksums {
		return s.Name(Checksums, "")
	}
	for _, arch := range Arches {
		for _, format := range Formats {
			expected, _ := s.Name(format, arch)
			if name == expected {
				return expected, true
			}
		}
	}
	return "", false
}

func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, BasePath) || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, BasePath)
		f, size, err := s.open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }()
		w.Header().Set("Content-Type", contentType(name))
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.CopyN(w, f, size)
	})
}

func contentType(name string) string {
	switch {
	case name == Checksums:
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(name, ".deb"):
		return "application/vnd.debian.binary-package"
	case strings.HasSuffix(name, ".rpm"):
		return "application/x-rpm"
	default:
		return "application/gzip"
	}
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}
