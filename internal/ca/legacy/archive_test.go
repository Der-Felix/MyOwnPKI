package legacy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
)

func tarGz(t *testing.T, entries func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	entries(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestArchiveReadsLikeTheDirectory: a tar.gz of a pki.sh directory (with
// the pki/ folder around it) reads exactly like the directory.
func TestArchiveReadsLikeTheDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "pki")
	legacytest.Write(t, dir, time.Now())
	data := tarGz(t, func(tw *tar.Writer) {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			rel, _ := filepath.Rel(filepath.Dir(dir), p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				return tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o700})
			}
			body, rerr := os.ReadFile(p) // #nosec G304 G122 -- the test's own fixture in a temp dir
			if rerr != nil {
				return rerr
			}
			if herr := tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))}); herr != nil {
				return herr
			}
			_, werr = tw.Write(body)
			return werr
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	fsys, err := FromArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Read(fsys, Passphrases{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Read(os.DirFS(dir), Passphrases{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Problems) != 0 || len(a.Intermediates) != len(b.Intermediates) || len(a.Issued) != len(b.Issued) ||
		len(a.Intermediates[0].Index) != len(b.Intermediates[0].Index) || a.Intermediates[0].NextCRLNumber != b.Intermediates[0].NextCRLNumber {
		t.Errorf("archive %+v\ndirectory %+v", a.Problems, b.Problems)
	}
}

func TestArchiveRefuses(t *testing.T) {
	t.Parallel()
	for want, entry := range map[string]*tar.Header{
		"clean relative name":   {Name: "../evil", Typeflag: tar.TypeReg, Size: 1},
		"link":                  {Name: "pki/root/certs/ca.crt", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"clean (absolute path)": {Name: "/etc/shadow", Typeflag: tar.TypeReg, Size: 1},
	} {
		data := tarGz(t, func(tw *tar.Writer) {
			_ = tw.WriteHeader(entry)
			if entry.Size > 0 {
				_, _ = tw.Write([]byte("x"))
			}
		})
		if _, err := FromArchive(data); err == nil || !strings.Contains(err.Error(), strings.Fields(want)[0]) {
			t.Errorf("%s: %v", want, err)
		}
	}
	if _, err := FromArchive([]byte("not gzip")); err == nil {
		t.Error("not gzip accepted")
	}
}

// Found by fuzzing: a name could be a file and the parent of another entry, which no directory on disk can.
func TestArchiveRefusesAFileThatIsADirectory(t *testing.T) {
	t.Parallel()
	file := func(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: 1} }
	dir := func(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeDir} }
	for name, entries := range map[string][]*tar.Header{
		"file, then below it": {file("a"), file("a/b")},
		"below it, then file": {file("a/b"), file("a")},
		"file, then dir":      {file("a"), dir("a/")},
		"dir, then file":      {dir("a/"), file("a")},
		"deeper":              {file("x/a"), file("x/a/b/c")},
	} {
		data := tarGz(t, func(tw *tar.Writer) {
			for _, h := range entries {
				_ = tw.WriteHeader(h)
				if h.Typeflag == tar.TypeReg {
					_, _ = tw.Write([]byte("x"))
				}
			}
		})
		if _, err := FromArchive(data); err == nil || !strings.Contains(err.Error(), "a file and a directory") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A later file of the same name still replaces the earlier one, and a directory entry may repeat.
	data := tarGz(t, func(tw *tar.Writer) {
		for _, h := range []*tar.Header{{Name: "root/certs/ca.crt", Typeflag: tar.TypeReg}, {Name: "d/", Typeflag: tar.TypeDir}, {Name: "d/f", Typeflag: tar.TypeReg, Size: 1}, {Name: "d/f", Typeflag: tar.TypeReg, Size: 2}, {Name: "d", Typeflag: tar.TypeDir}} {
			_ = tw.WriteHeader(h)
			if h.Size > 0 {
				_, _ = tw.Write([]byte("xx"[:h.Size]))
			}
		}
	})
	fsys, err := FromArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fs.ReadFile(fsys, "d/f"); err != nil || string(got) != "xx" {
		t.Errorf("d/f: %q, %v", got, err)
	}
}

// Found by fuzzing: listing a directory of the archive walked the whole table, so a walk over an archive of
// 100,000 entries with many directories took minutes, and one name of 500,000 levels made 500,000 directories.
func TestArchiveTreeStaysCheap(t *testing.T) {
	t.Parallel()
	const dirs = 20_000
	data := tarGz(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "root/certs/ca.crt", Typeflag: tar.TypeReg})
		for i := range dirs {
			name := "issued/c" + strconv.Itoa(i)
			_ = tw.WriteHeader(&tar.Header{Name: name + "/archive/k/", Typeflag: tar.TypeDir})
			_ = tw.WriteHeader(&tar.Header{Name: name + "/cert.pem", Typeflag: tar.TypeReg})
		}
	})
	start := time.Now()
	fsys, err := FromArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	listed := 0
	for i := range dirs {
		kids, lerr := fs.ReadDir(fsys, "issued/c"+strconv.Itoa(i)+"/archive")
		if lerr != nil || len(kids) != 1 || kids[0].Name() != "k" || !kids[0].IsDir() {
			t.Fatalf("c%d/archive: %v, %v", i, kids, lerr)
		}
		listed++
	}
	top, err := fs.ReadDir(fsys, "issued")
	if err != nil || len(top) != dirs || top[0].Name() != "c0" {
		t.Fatalf("issued: %d entries, %v", len(top), err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("%d directory listings took %v", listed, d)
	}

	deep := tarGz(t, func(tw *tar.Writer) {
		for _, top := range []string{"x", "y"} {
			_ = tw.WriteHeader(&tar.Header{Name: top + "/" + strings.Repeat("d/", 120_000) + "f", Typeflag: tar.TypeReg})
		}
	})
	start = time.Now()
	if _, err := FromArchive(deep); err == nil || !strings.Contains(err.Error(), "files and directories") {
		t.Errorf("two names of 120,000 levels: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("refusing them took %v", d)
	}
}
