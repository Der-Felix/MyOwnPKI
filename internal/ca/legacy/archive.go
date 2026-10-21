package legacy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"
)

// Limits of an uploaded archive (the API import, step 18).
const (
	MaxArchive         = 64 << 20  // the .tar.gz itself
	maxUnpacked        = 256 << 20 // everything inside: a decompression bomb stops here
	maxArchiveEntries  = 100_000
	maxArchiveFileSize = 64 << 20
)

// FromArchive unpacks a .tar.gz of a pki.sh directory into memory – keys
// never touch the disk – and returns it as a file system for Read. The
// archive may hold the directory itself (root/, intermediate/, …) or one
// directory around it (pki/root/…). Only regular files and directories
// with clean relative names are accepted.
func FromArchive(data []byte) (fs.FS, error) {
	if len(data) > MaxArchive {
		return nil, fmt.Errorf("the archive is larger than %d MiB", MaxArchive>>20)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive (.tar.gz): %w", err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(io.LimitReader(zr, maxUnpacked+1))
	m := memFS{"": {dir: true}}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the archive can't be read: %w", err)
		}
		if n >= maxArchiveEntries {
			return nil, fmt.Errorf("more than %d entries in the archive", maxArchiveEntries)
		}
		name := strings.TrimPrefix(h.Name, "./")
		name = strings.TrimSuffix(name, "/")
		if name == "" || name == "." {
			continue
		}
		if strings.Contains(name, `\`) || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("archive entry %q: not a clean relative name", clip(h.Name, 80))
		}
		switch h.Typeflag {
		case tar.TypeDir:
			m.addDir(name)
		case tar.TypeReg:
			if h.Size > maxArchiveFileSize {
				return nil, fmt.Errorf("archive entry %q is larger than %d MiB", clip(name, 80), maxArchiveFileSize>>20)
			}
			total += h.Size
			if total > maxUnpacked {
				return nil, fmt.Errorf("the archive unpacks to more than %d MiB", maxUnpacked>>20)
			}
			body, rerr := io.ReadAll(io.LimitReader(tr, h.Size+1))
			if rerr != nil {
				return nil, fmt.Errorf("archive entry %q: %w", clip(name, 80), rerr)
			}
			m.addDir(path.Dir(name))
			m[name] = &memFile{data: body, mod: h.ModTime}
		default:
			return nil, fmt.Errorf("archive entry %q is a link or special file – only files and directories are accepted", clip(name, 80))
		}
	}
	var root fs.FS = m
	if _, err := fs.Stat(m, "root/certs/ca.crt"); err != nil {
		tops, _ := fs.ReadDir(m, ".")
		if len(tops) == 1 && tops[0].IsDir() {
			if sub, serr := fs.Sub(m, tops[0].Name()); serr == nil {
				root = sub
			}
		}
	}
	return root, nil
}

// memFS is a read-only file system in memory: path → file or directory.
type memFS map[string]*memFile

type memFile struct {
	data []byte
	dir  bool
	mod  time.Time
}

func (m memFS) addDir(p string) {
	for p != "." && p != "" {
		if _, ok := m[p]; !ok {
			m[p] = &memFile{dir: true}
		}
		p = path.Dir(p)
	}
}

func (m memFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	key := name
	if key == "." {
		key = ""
	}
	f, ok := m[key]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	info := memInfo{name: path.Base(name), f: f}
	if !f.dir {
		return &openFile{info: info, r: bytes.NewReader(f.data)}, nil
	}
	var entries []fs.DirEntry
	prefix := key + "/"
	if key == "" {
		prefix = ""
	}
	for p, c := range m {
		if p == "" || !strings.HasPrefix(p, prefix) || strings.Contains(p[len(prefix):], "/") {
			continue
		}
		entries = append(entries, fs.FileInfoToDirEntry(memInfo{name: p[len(prefix):], f: c}))
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return &openDir{info: info, entries: entries}, nil
}

type memInfo struct {
	name string
	f    *memFile
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64  { return int64(len(i.f.data)) }
func (i memInfo) Mode() fs.FileMode {
	if i.f.dir {
		return fs.ModeDir | 0o500
	}
	return 0o400
}
func (i memInfo) ModTime() time.Time { return i.f.mod }
func (i memInfo) IsDir() bool        { return i.f.dir }
func (i memInfo) Sys() any           { return nil }

type openFile struct {
	info memInfo
	r    *bytes.Reader
}

func (f *openFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *openFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *openFile) Close() error               { return nil }

type openDir struct {
	info    memInfo
	entries []fs.DirEntry
	pos     int
}

func (d *openDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *openDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.name, Err: fs.ErrInvalid}
}
func (d *openDir) Close() error { return nil }

func (d *openDir) ReadDir(n int) ([]fs.DirEntry, error) {
	rest := d.entries[d.pos:]
	if n <= 0 {
		d.pos = len(d.entries)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	n = min(n, len(rest))
	d.pos += n
	return rest[:n], nil
}
