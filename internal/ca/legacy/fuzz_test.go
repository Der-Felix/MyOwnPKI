package legacy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- builds a PBKDF2-HMAC-SHA1 test key, the PKCS#5 default
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Fuzz targets of the legacy import (docs/PHASE3.md §18.2): the archive an admin uploads and the text files
// of a pki.sh directory. Every target calls the production function unchanged and re-checks what it promises
// with code of its own. Seeds are built here; files under testdata/fuzz are only what the fuzzer wrote after a
// failure.

// fuzzDeadline is the longest one input may take.
const fuzzDeadline = 2 * time.Second

// fuzzTimer fails the target when one input needed longer than fuzzDeadline.
func fuzzTimer(t *testing.T) func() {
	t.Helper()
	start := time.Now()
	return func() {
		if d := time.Since(start); d > fuzzDeadline {
			t.Errorf("one input took %v (limit %v)", d, fuzzDeadline)
		}
	}
}

// --- archive -------------------------------------------------------------------------------------------

// rawTarHeader writes one 512-byte header by hand, for what archive/tar refuses to write (a NUL in a name).
func rawTarHeader(name string, flag byte, size int64) []byte {
	h := make([]byte, 512)
	copy(h, name)
	copy(h[100:], "0000600\x00")
	copy(h[108:], "0000000\x00")
	copy(h[116:], "0000000\x00")
	copy(h[124:], fmt.Sprintf("%011o\x00", size))
	copy(h[136:], "00000000000\x00")
	h[156] = flag
	copy(h[257:], "ustar\x0000")
	fixTarChecksums(h)
	return h
}

// fixTarChecksums repairs the checksum of every header of a tar stream, so that a byte the fuzzer changed in a
// header is read as what it says and not refused as a broken header. It follows the size fields like a reader
// and stops where the stream stops making sense.
func fixTarChecksums(b []byte) {
	for off := 0; off+512 <= len(b); {
		h := b[off : off+512]
		off += 512
		if bytes.Count(h, []byte{0}) == 512 {
			continue
		}
		for i := 148; i < 156; i++ {
			h[i] = ' '
		}
		sum := 0
		for _, c := range h {
			sum += int(c)
		}
		copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
		switch h[156] { // types without a body, whatever the size field says
		case '1', '2', '3', '4', '5', '6':
			continue
		}
		field := strings.TrimRight(string(h[124:136]), "\x00 ")
		size, err := strconv.ParseInt(field, 8, 64)
		if err != nil || size < 0 || size > int64(len(b)) {
			continue
		}
		off += int((size + 511) / 512 * 512)
	}
}

func gzipBytes(raw []byte, level int) []byte {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		panic(err)
	}
	if _, err := zw.Write(raw); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// asArchive gives the production function its input: bytes that start like gzip go in as they are; anything
// else is read as a tar stream, which gets its checksums repaired and is compressed. The second form lets the
// fuzzer change headers and names, which a changed byte in a compressed stream never allows.
func asArchive(data []byte) []byte {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return data
	}
	raw := bytes.Clone(data)
	fixTarChecksums(raw)
	return gzipBytes(raw, gzip.BestSpeed)
}

type tarEntry struct {
	name string
	flag byte
	body string
	link string
}

func tarBytes(entries []tarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.flag, Mode: 0o600, Linkname: e.link}
		if e.flag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
		if e.flag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				panic(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// pkiTree is a small pki.sh directory.
func pkiTree(prefix string) []tarEntry {
	file := func(p, body string) tarEntry { return tarEntry{name: prefix + p, flag: tar.TypeReg, body: body} }
	dir := func(p string) tarEntry { return tarEntry{name: prefix + p + "/", flag: tar.TypeDir} }
	return []tarEntry{
		dir("root"), dir("root/certs"), file("root/certs/ca.crt", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
		file("root/ca.meta", "NAME=root\n"), dir("intermediate"), dir("intermediate/issuing"), dir("intermediate/issuing/certs"),
		file("intermediate/issuing/certs/ca.crt", "x"), file("intermediate/issuing/index.txt", "V\t270101000000Z\t\t01\tunknown\t/CN=a\n"),
		dir("issued"), dir("issued/nas"), file("issued/nas/cert.pem", "x"), file("pki.conf", "AIA_BASE_URL=\"http://pki.example\"\n"),
	}
}

// zeroTar writes a tar stream of n files of size bytes of zeros each into a gzip stream.
func zeroTar(n int, size int64) []byte {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		panic(err)
	}
	tw := tar.NewWriter(zw)
	for i := range n {
		if err := tw.WriteHeader(&tar.Header{Name: "root/f" + strconv.Itoa(i), Typeflag: tar.TypeReg, Mode: 0o600, Size: size}); err != nil {
			panic(err)
		}
		if _, err := io.CopyN(tw, zeroReader{}, size); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// manyEntries is a tar.gz of n empty files (names from name), as the entry limit sees it.
func manyEntries(n int, name func(i int) string) []byte {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		panic(err)
	}
	tw := tar.NewWriter(zw)
	for i := range n {
		if err := tw.WriteHeader(&tar.Header{Name: name(i), Typeflag: tar.TypeReg, Mode: 0o600}); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// refEntry is what the test's own reader finds in an archive.
type refEntry struct {
	dir  bool
	size int64
	crc  uint32
}

// refArchive reads the archive again with archive/tar and the promise of FromArchive: only regular files and
// directories, clean relative names, at most 100,000 entries, 64 MiB a file and 256 MiB in all. It reports why
// it would refuse, or "" and every entry under its normalized name (the last of a name wins).
func refArchive(data []byte) (map[string]refEntry, string) {
	const maxEntries, maxFile, maxTotal = 100_000, 64 << 20, 256 << 20
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, "not gzip"
	}
	tr := tar.NewReader(io.LimitReader(zr, maxTotal+1))
	out := map[string]refEntry{}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			return out, ""
		}
		if err != nil {
			return nil, "tar: " + err.Error()
		}
		if n >= maxEntries {
			return nil, "too many entries"
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if name == "" || name == "." {
			continue
		}
		if strings.ContainsAny(name, "\\") || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return nil, "unclean name"
		}
		switch h.Typeflag {
		case tar.TypeDir:
			out[name] = refEntry{dir: true}
		case tar.TypeReg:
			if h.Size > maxFile {
				return nil, "file too large"
			}
			if total += h.Size; total > maxTotal {
				return nil, "too much data"
			}
			sum := crc32.NewIEEE()
			got, err := io.Copy(sum, io.LimitReader(tr, h.Size+1))
			if err != nil || got != h.Size {
				return nil, "short body"
			}
			out[name] = refEntry{size: got, crc: sum.Sum32()}
		default:
			return nil, "link or special file"
		}
	}
}

func FuzzFromArchive(f *testing.F) {
	tree := pkiTree("")
	add := func(entries []tarEntry) {
		raw := tarBytes(entries)
		f.Add(raw) // as a tar stream, which the fuzzer can change header by header
		f.Add(gzipBytes(raw, gzip.DefaultCompression))
	}
	add(tree)
	add(pkiTree("pki/"))
	add(pkiTree("./"))
	add([]tarEntry{{name: "../evil", flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: "root/../../evil", flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: "/etc/shadow", flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: `root\certs\ca.crt`, flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: "root//certs/ca.crt", flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: "root/./certs/ca.crt", flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: "root/certs/ca.crt", flag: tar.TypeReg, body: "first"}, {name: "root/certs/ca.crt", flag: tar.TypeReg, body: "second"}})
	add([]tarEntry{{name: "a", flag: tar.TypeReg, body: "x"}, {name: "a/b", flag: tar.TypeReg, body: "y"}}) // a file, then below it
	add([]tarEntry{{name: "a/b", flag: tar.TypeReg, body: "y"}, {name: "a", flag: tar.TypeReg, body: "x"}}) // below it, then the file
	add([]tarEntry{{name: "a/b", flag: tar.TypeReg, body: "y"}, {name: "a/", flag: tar.TypeDir}})           // a directory again
	add([]tarEntry{{name: "root/certs/ca.crt", flag: tar.TypeSymlink, link: "/etc/passwd"}})
	add([]tarEntry{{name: "root/certs/ca.crt", flag: tar.TypeLink, link: "root/ca.meta"}})
	add([]tarEntry{{name: "dev", flag: tar.TypeChar}, {name: "pipe", flag: tar.TypeFifo}})
	add([]tarEntry{{name: ".", flag: tar.TypeDir}, {name: "./", flag: tar.TypeDir}, {name: "root/", flag: tar.TypeDir}})
	add([]tarEntry{{name: strings.Repeat("a/", 200) + "f", flag: tar.TypeReg, body: "x"}})
	add([]tarEntry{{name: strings.Repeat("d", 300), flag: tar.TypeReg, body: "x"}}) // a name over the USTAR limit: PAX header

	// A name with a NUL byte, which archive/tar will not write.
	f.Add(append(append(rawTarHeader("root/certs/ca\x00.crt", '0', 1), 'x', 0), make([]byte, 511+1024)...))
	// A header that claims 1 TiB and brings nothing, one that claims 60 MiB and brings 3 bytes.
	{
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: "root/certs/ca.crt", Typeflag: tar.TypeReg, Size: 1 << 40})
		f.Add(gzipBytes(buf.Bytes(), gzip.DefaultCompression))
		buf.Reset()
		tw = tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: "root/certs/ca.crt", Typeflag: tar.TypeReg, Size: 60 << 20})
		_, _ = tw.Write([]byte("abc"))
		f.Add(gzipBytes(buf.Bytes(), gzip.DefaultCompression))
	}
	// Entry limit: 100,001 empty files are refused, 100,000 pass; and 50,000 certificate directories under
	// issued/ (a directory listing of this memory file system walks the whole table).
	f.Add(manyEntries(100_001, func(i int) string { return "root/f" + strconv.Itoa(i) }))
	f.Add(manyEntries(100_000, func(i int) string { return "root/f" + strconv.Itoa(i) }))
	f.Add(manyEntries(100_000, func(i int) string { return "issued/c" + strconv.Itoa(i/2) + "/f" + strconv.Itoa(i%2) }))
	// One name of 1 MiB made of directories.
	f.Add(manyEntries(1, func(int) string { return "root/" + strings.Repeat("d/", 524_000) + "f" }))
	// Not an archive at all, and bombs: zeros that compress 1000 to 1, two files of 64 MiB.
	f.Add(gzipBytes(make([]byte, 1<<20), gzip.BestCompression))
	f.Add(gzipBytes(nil, gzip.DefaultCompression))
	f.Add([]byte("not gzip"))
	f.Add(zeroTar(2, 64<<20))
	f.Add(tarBytes(tree)[:700])

	f.Fuzz(func(t *testing.T, data []byte) {
		archive := asArchive(data)
		stop := fuzzTimer(t)
		fsys, err := FromArchive(archive)
		var walked int
		var files int
		var bytesTotal int64
		if err == nil {
			walkErr := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
				if werr != nil {
					return werr
				}
				if !fs.ValidPath(p) {
					t.Fatalf("walk visits the invalid path %q", p)
				}
				walked++
				if !d.IsDir() {
					info, ierr := d.Info()
					if ierr != nil {
						return ierr
					}
					files++
					bytesTotal += info.Size()
					if info.Size() > 64<<20 {
						t.Fatalf("file %q has %d bytes", p, info.Size())
					}
				}
				return nil
			})
			if walkErr != nil {
				t.Fatalf("walk: %v", walkErr)
			}
		}
		stop()

		if len(archive) > 64<<20 && err == nil {
			t.Fatalf("accepted an archive of %d bytes", len(archive))
		}
		if err != nil {
			if n := len(err.Error()); n > 400 {
				t.Errorf("refusal text of %d bytes: %.200q", n, err.Error())
			}
			return
		}
		if files > 100_000 || bytesTotal > 256<<20 {
			t.Fatalf("accepted %d files with %d bytes", files, bytesTotal)
		}
		want, why := refArchive(archive)
		if why != "" {
			t.Fatalf("accepted an archive that a second reader refuses: %s", why)
		}
		checkTree(t, fsys, want, walked)
	})
}

// checkTree compares the file system with what the test's own reader found: every file with its content, every
// directory, and no name that is a file and a directory's parent at once.
func checkTree(t *testing.T, fsys fs.FS, want map[string]refEntry, walked int) {
	t.Helper()
	for name := range want {
		for a := path.Dir(name); a != "." && a != "/"; a = path.Dir(a) {
			if p, ok := want[a]; ok && !p.dir {
				t.Fatalf("accepted %q below the file %q", name, a)
			}
		}
	}
	// The files may sit one directory down (a pki/ folder around the tree).
	prefix := ""
	if _, ok := want["root/certs/ca.crt"]; !ok {
		tops := map[string]bool{}
		for name := range want {
			tops[strings.SplitN(name, "/", 2)[0]] = true
		}
		if len(tops) == 1 {
			for top := range tops {
				if e, ok := want[top]; !ok || e.dir {
					prefix = top + "/"
				}
			}
		}
	}
	// Nothing is invented: the file system holds the names of the archive and their parent directories.
	nodes := map[string]bool{}
	for name := range want {
		for p := name; p != "."; p = path.Dir(p) {
			nodes[p] = true
		}
	}
	if prefix != "" {
		delete(nodes, strings.TrimSuffix(prefix, "/"))
	}
	if walked-1 != len(nodes) { // the walk starts at "."
		t.Fatalf("the walk visits %d entries, the archive names %d", walked-1, len(nodes))
	}
	for name, e := range want {
		if !strings.HasPrefix(name, prefix) || name == strings.TrimSuffix(prefix, "/") {
			continue
		}
		rel := strings.TrimPrefix(name, prefix)
		info, err := fs.Stat(fsys, rel)
		if err != nil {
			t.Fatalf("%q is in the archive and not in the file system: %v", rel, err)
		}
		if info.IsDir() != e.dir {
			t.Fatalf("%q: directory %v in the file system, %v in the archive", rel, info.IsDir(), e.dir)
		}
		if e.dir {
			continue
		}
		file, err := fsys.Open(rel)
		if err != nil {
			t.Fatal(err)
		}
		sum := crc32.NewIEEE()
		n, err := io.Copy(sum, file)
		_ = file.Close()
		if err != nil || n != e.size || sum.Sum32() != e.crc {
			t.Fatalf("%q: %d bytes with crc %08x (%v), the archive has %d bytes with crc %08x", rel, n, sum.Sum32(), err, e.size, e.crc)
		}
	}
}

// --- key/value files and index.txt -----------------------------------------------------------------------

var kvKey = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func FuzzParseKV(f *testing.F) {
	for _, s := range []string{
		"NAME=root\nAIA_BASE_URL=\"http://pki.example\"\nKEY='x y'\n",
		"# comment\n\nA = 1 # note\nB=\"a#b\"\nC='unterminated\nD=\n",
		"lower=1\n1A=2\n=3\nA B=4\nA=1\r\nB=2\r\n",
		"A=\"x\"y\"\nA=second\n",
		"$(touch /tmp/x)\nA=$(id)\nB=`id`\n",
		"A=" + strings.Repeat("x", 70_000) + "\nB=1\n",
		strings.Repeat("A=1\n", 20_000),
		strings.Repeat("junk line\n", 20_000),
		"A=\x00\xff\xfe\n",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		defer fuzzTimer(t)()
		kv, notes := parseKV(data)
		lines := strings.Split(string(data), "\n")
		if len(kv) > len(lines) {
			t.Fatalf("%d keys from %d lines", len(kv), len(lines))
		}
		if len(notes) > len(lines)+1 {
			t.Fatalf("%d notes from %d lines", len(notes), len(lines))
		}
		for _, n := range notes {
			if len(n) > 200 {
				t.Fatalf("a note of %d bytes: %.100q", len(n), n)
			}
		}
		for k, v := range kv {
			if !kvKey.MatchString(k) {
				t.Fatalf("key %q is not an upper-case name", k)
			}
			if strings.ContainsAny(v, "\n") {
				t.Fatalf("value of %s holds a newline", k)
			}
			// The value is text of a line that names the key: nothing is made up.
			found := false
			for _, l := range lines {
				l = strings.TrimSuffix(l, "\r")
				if rest, ok := strings.CutPrefix(strings.TrimLeft(l, " \t"), k); ok && strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=") && strings.Contains(l, v) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s=%q is on no line of the file", k, v)
			}
		}
	})
}

var (
	hexSerial   = regexp.MustCompile(`^([0-9A-F]{2})+$`)
	indexStatus = map[string]bool{"V": true, "E": true, "R": true}
)

func FuzzParseIndex(f *testing.F) {
	for _, s := range []string{
		"V\t270101000000Z\t\t1A2B\tunknown\t/CN=valid\n",
		"R\t270101000000Z\t261018120000Z,superseded\t00FF\tunknown\t/CN=superseded\n",
		"R\t270101000000Z\t261018120000Z,keyTime,261017080000Z\t0B\tunknown\t/CN=key\n",
		"R\t270101000000Z\t261018120000Z,CAkeyTime,261017080000Z\t0C\tunknown\t/CN=ca key\n",
		"R\t270101000000Z\t261018120000Z,holdInstruction,1.2.840.10040.2.2\t0D\tunknown\t/CN=hold\n",
		"E\t20510101000000Z\t\t0E\tunknown\t/CN=generalized\r\nV\t500101000000Z\t\t0F\tunknown\t/CN=1950",
		"X\t270101000000Z\t\t10\tunknown\t/CN=bad status\nV\t270101000000Z\t\tnothex\tunknown\t/CN=bad serial\n",
		"V\t270101000000Z\t\t0x1F\tunknown\t/CN=x\nV\t270101000000Z\t\t-1\tunknown\t/CN=minus\nV\t270101000000Z\t\t+1\tunknown\t/CN=plus\n",
		"V\t270101000000Z\t\t0\tunknown\t/CN=zero\nV\t270101000000Z\t\t" + strings.Repeat("F", 200) + "\tunknown\t/CN=long\n",
		"V\t270101000000Z\t\t1_0\tunknown\t/CN=underscore\nV\t270101000000Z\t\t 1\tunknown\t/CN=space\n",
		"V\t271301000000Z\t\t01\tunknown\t/CN=month 13\nV\t270101000000\t\t02\tunknown\t/CN=no Z\n",
		"V\t270101000000Z\t\t01\tunknown\t/CN=" + strings.Repeat("x", 70_000) + "\nV\t270101000000Z\t\t02\tunknown\t/CN=after\n",
		strings.Repeat("V\t270101000000Z\t\t01\tunknown\t/CN=a\n", 10_000),
		"V\t270101000000Z\t\t01\tunknown\n\n\n\t\t\t\t\t\n",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		defer fuzzTimer(t)()
		entries, problems := parseIndex(data)
		lines := strings.Split(string(data), "\n")
		if len(entries)+len(problems) > len(lines)+1 {
			t.Fatalf("%d entries and %d problems from %d lines", len(entries), len(problems), len(lines))
		}
		for _, p := range problems {
			if len(p) > 300 {
				t.Fatalf("a problem of %d bytes: %.100q", len(p), p)
			}
		}
		last := 0
		for _, e := range entries {
			if e.Line <= last || e.Line > len(lines) {
				t.Fatalf("entry on line %d after line %d (%d lines)", e.Line, last, len(lines))
			}
			last = e.Line
			fields := strings.Split(strings.TrimSuffix(lines[e.Line-1], "\r"), "\t")
			if len(fields) != 6 || fields[0] != e.Status || fields[3] != e.File || fields[5] != e.Subject {
				t.Fatalf("entry %+v does not match line %d: %.200q", e, e.Line, lines[e.Line-1])
			}
			if !indexStatus[e.Status] {
				t.Fatalf("status %q", e.Status)
			}
			if !hexSerial.MatchString(e.Serial) || strings.HasPrefix(e.Serial, "00") {
				t.Fatalf("serial %q is not canonical hex", e.Serial)
			}
			if strings.TrimLeft(strings.ToUpper(e.File), "0") != strings.TrimLeft(e.Serial, "0") {
				t.Fatalf("serial %q for the file %q", e.Serial, e.File)
			}
			if (e.Status == "R") != (e.Revoked != nil) {
				t.Fatalf("status %s and revocation %v", e.Status, e.Revoked)
			}
			if e.Status != "R" && fields[2] != "" {
				t.Fatalf("status %s with a revocation field %q", e.Status, fields[2])
			}
			if e.Expiry.Location() != time.UTC {
				t.Fatalf("expiry in %v", e.Expiry.Location())
			}
			if n := len(fields[1]); (n != 13 && n != 15) || !strings.HasSuffix(fields[1], "Z") {
				t.Fatalf("expiry %q", fields[1])
			}
			if e.Revoked != nil {
				switch e.Revoked.Reason {
				case "", "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL":
				default:
					t.Fatalf("reason %q", e.Revoked.Reason)
				}
				if e.Revoked.Time.IsZero() {
					t.Fatal("revoked without a time")
				}
			}
		}
	})
}

// --- private keys ------------------------------------------------------------------------------------------

type fuzzKeyMaterial struct {
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
	rsa *rsa.PrivateKey
}

var fuzzKeys = sync.OnceValue(func() fuzzKeyMaterial {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return fuzzKeyMaterial{ec, ed, rk}
})

// fuzzEncryptKey writes an ENCRYPTED PRIVATE KEY (PBES2: PBKDF2 and AES-CBC) like `openssl pkcs8 -topk8`, with
// types of its own so that the test does not depend on the reader's.
func fuzzEncryptKey(plain, pass []byte, iterations int, prfOID, cipherOID asn1.ObjectIdentifier, keyLen int) []byte {
	type algorithm = pkix.AlgorithmIdentifier
	mustMarshal := func(v any) asn1.RawValue {
		der, err := asn1.Marshal(v)
		if err != nil {
			panic(err)
		}
		return asn1.RawValue{FullBytes: der}
	}
	salt, iv := make([]byte, 8), make([]byte, aes.BlockSize)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(iv)
	prf := sha1.New
	if prfOID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}) {
		prf = sha256.New
	}
	key, err := pbkdf2.Key(prf, string(pass), salt, iterations, keyLen)
	if err != nil {
		panic(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(enc, padded)
	kdf := struct {
		Salt []byte
		Iter int
		PRF  algorithm
	}{salt, iterations, algorithm{Algorithm: prfOID, Parameters: asn1.NullRawValue}}
	pbes2 := struct {
		KDF    algorithm
		Scheme algorithm
	}{
		algorithm{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, Parameters: mustMarshal(kdf)},
		algorithm{Algorithm: cipherOID, Parameters: mustMarshal(iv)},
	}
	der, err := asn1.Marshal(struct {
		Alg  algorithm
		Data []byte
	}{algorithm{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: mustMarshal(pbes2)}, enc})
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
}

// pbkdf2Iterations reads the iteration count of an ENCRYPTED PRIVATE KEY without the reader's code.
func pbkdf2Iterations(data []byte) (int, bool) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		return 0, false
	}
	var outer struct {
		Alg  pkix.AlgorithmIdentifier
		Data []byte
	}
	if _, err := asn1.Unmarshal(block.Bytes, &outer); err != nil || !outer.Alg.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}) {
		return 0, false
	}
	var pbes2 struct{ KDF, Scheme pkix.AlgorithmIdentifier }
	if _, err := asn1.Unmarshal(outer.Alg.Parameters.FullBytes, &pbes2); err != nil || !pbes2.KDF.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}) {
		return 0, false
	}
	var kdf struct {
		Salt   []byte
		Iter   int
		KeyLen int                      `asn1:"optional"`
		PRF    pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(pbes2.KDF.Parameters.FullBytes, &kdf); err != nil {
		return 0, false
	}
	return kdf.Iter, true
}

// skippedKeys counts the inputs FuzzParsePrivateKey leaves out because of their iteration count (decision 9 in
// docs/PHASE3.md §18.5).
var skippedKeys atomic.Int64

func FuzzParsePrivateKey(f *testing.F) {
	k := fuzzKeys()
	pkcs8 := func(key any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			panic(err)
		}
		return der
	}
	ecDER, edDER, rsaDER := pkcs8(k.ec), pkcs8(k.ed), pkcs8(k.rsa)
	sha1OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	sha256OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	aes256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	aes128 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	pass := []byte("correct horse")

	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), []byte(nil))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER}), []byte(nil))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), []byte(nil))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.rsa)}), []byte(nil))
	ecSEC1, err := x509.MarshalECPrivateKey(k.ec)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecSEC1}), []byte(nil))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"}, Bytes: ecSEC1}), pass)
	f.Add(fuzzEncryptKey(ecDER, pass, 2048, sha256OID, aes256, 32), pass)
	f.Add(fuzzEncryptKey(ecDER, pass, 2048, sha256OID, aes256, 32), []byte("wrong"))
	f.Add(fuzzEncryptKey(ecDER, pass, 2048, sha256OID, aes256, 32), []byte(nil))
	f.Add(fuzzEncryptKey(edDER, pass, 2048, sha1OID, aes128, 16), pass)
	f.Add(fuzzEncryptKey(rsaDER, pass, 100_000, sha256OID, aes256, 32), pass)
	f.Add(fuzzEncryptKey(ecDER, pass, 600_000, sha256OID, aes256, 32), pass)                             // OpenSSL 3 default: skipped by the target
	f.Add(fuzzEncryptKey(ecDER, nil, 1, sha256OID, aes256, 32), []byte("x"))                             // the empty passphrase it was made with
	f.Add(fuzzEncryptKey(ecDER, pass, 1, sha256OID, aes256, 24), pass)                                   // key length that the cipher does not have
	f.Add(rewriteIterations(fuzzEncryptKey(ecDER, pass, 2048, sha256OID, aes256, 32), 10_000_001), pass) // over the limit: refused quickly
	f.Add(rewriteIterations(fuzzEncryptKey(ecDER, pass, 2048, sha256OID, aes256, 32), 0), pass)
	f.Add(rewriteIterations(fuzzEncryptKey(ecDER, pass, 2048, sha256OID, aes256, 32), 2_000_000_000), pass)
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}), pass)
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), pass)
	f.Add(append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER})...), []byte(nil))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n"), []byte(nil))
	f.Add([]byte{}, []byte(nil))

	f.Fuzz(func(t *testing.T, data, passphrase []byte) {
		if n, ok := pbkdf2Iterations(data); ok && n > 100_000 && n <= 10_000_000 {
			skippedKeys.Add(1)
			t.Skipf("PBKDF2 with %d iterations is slow and accepted by design (decision 9)", n)
		}
		defer fuzzTimer(t)()
		signer, encrypted, err := parsePrivateKey(data, passphrase)
		block, _ := pem.Decode(data)
		if err != nil {
			if len(err.Error()) > 400 {
				t.Errorf("error text of %d bytes: %.200q", len(err.Error()), err.Error())
			}
			if signer != nil {
				t.Fatal("a key and an error")
			}
			if block != nil && block.Type == "ENCRYPTED PRIVATE KEY" && !encrypted {
				t.Errorf("an encrypted key is not reported as encrypted: %v", err)
			}
			return
		}
		if block == nil {
			t.Fatal("accepted a key without a PEM block")
		}
		if signer == nil {
			t.Fatal("no error and no key")
		}
		switch pub := signer.Public().(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
			if _, merr := x509.MarshalPKIXPublicKey(pub); merr != nil {
				t.Fatalf("the public key does not marshal: %v", merr)
			}
		default:
			t.Fatalf("accepted a key of the type %T", pub)
		}
		if want := block.Type == "ENCRYPTED PRIVATE KEY"; encrypted != want {
			t.Fatalf("encrypted %v for a %q block", encrypted, block.Type)
		}
		if _, old := block.Headers["DEK-Info"]; old && block.Type != "PRIVATE KEY" {
			t.Fatal("accepted a key with the old PEM encryption")
		}
		if encrypted && len(passphrase) == 0 {
			t.Fatal("opened an encrypted key without a passphrase")
		}
		if !encrypted {
			// A plain key is what the stdlib reads from the same DER.
			var want any
			var perr error
			switch block.Type {
			case "PRIVATE KEY":
				want, perr = x509.ParsePKCS8PrivateKey(block.Bytes)
			case "RSA PRIVATE KEY":
				want, perr = x509.ParsePKCS1PrivateKey(block.Bytes)
			case "EC PRIVATE KEY":
				want, perr = x509.ParseECPrivateKey(block.Bytes)
			default:
				t.Fatalf("accepted a %q block", block.Type)
			}
			if perr != nil {
				t.Fatalf("accepted a key the standard library refuses: %v", perr)
			}
			wantKey, ok := want.(interface{ Public() crypto.PublicKey })
			gotPub, ok2 := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !ok2 || !gotPub.Equal(wantKey.Public()) {
				t.Fatal("the key is not the one in the PEM block")
			}
		}
	})
	f.Cleanup(func() {
		if n := skippedKeys.Load(); n > 0 {
			f.Logf("skipped %d inputs with more than 100,000 PBKDF2 iterations", n)
		}
	})
}

// rewriteIterations changes the iteration count inside an ENCRYPTED PRIVATE KEY.
func rewriteIterations(pemData []byte, n int) []byte {
	block, _ := pem.Decode(pemData)
	var outer struct {
		Alg  pkix.AlgorithmIdentifier
		Data []byte
	}
	if _, err := asn1.Unmarshal(block.Bytes, &outer); err != nil {
		panic(err)
	}
	var pbes2 struct{ KDF, Scheme pkix.AlgorithmIdentifier }
	if _, err := asn1.Unmarshal(outer.Alg.Parameters.FullBytes, &pbes2); err != nil {
		panic(err)
	}
	var kdf struct {
		Salt []byte
		Iter int
		PRF  pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(pbes2.KDF.Parameters.FullBytes, &kdf); err != nil {
		panic(err)
	}
	kdf.Iter = n
	kdfDER, err := asn1.Marshal(kdf)
	if err != nil {
		panic(err)
	}
	pbes2.KDF.Parameters = asn1.RawValue{FullBytes: kdfDER}
	pbes2DER, err := asn1.Marshal(pbes2)
	if err != nil {
		panic(err)
	}
	outer.Alg.Parameters = asn1.RawValue{FullBytes: pbes2DER}
	der, err := asn1.Marshal(outer)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
}
