package legacy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
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
