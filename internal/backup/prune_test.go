package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// copyTree copies a backup directory (the test makes one real backup and
// clones it under the names it needs).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestPrune: only complete scheduled backups are deleted, the oldest first,
// and the newest keep stay; everything else in the directory is left alone.
func TestPrune(t *testing.T) {
	t.Parallel()
	_, o := newInstance(t)
	parent := t.TempDir()
	real := filepath.Join(t.TempDir(), "real")
	if _, err := Create(t.Context(), real, o); err != nil {
		t.Fatal(err)
	}
	if got := ScheduledName(time.Date(2026, 10, 25, 3, 12, 9, 0, time.FixedZone("CEST", 2*3600))); got != "20261025T011209Z" {
		t.Fatalf("ScheduledName in UTC: %s", got)
	}
	scheduled := []string{"20261020T031200Z", "20261021T030500Z", "20261022T034400Z", "20261023T031900Z"}
	for _, n := range scheduled {
		copyTree(t, real, filepath.Join(parent, n))
	}
	// Never deleted: install.sh's update backup, a failed one, a foreign
	// directory and file, and scheduled names that aren't complete backups.
	copyTree(t, real, filepath.Join(parent, "20261019T101010Z-v0.2.1-rc.1"))
	copyTree(t, real, filepath.Join(parent, "20261018T030000Z"+UnverifiedSuffix))
	copyTree(t, real, filepath.Join(parent, "notes"))
	if err := os.WriteFile(filepath.Join(parent, "README.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "20261017T000000Z"), []byte("a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "20261016T000000Z"), 0o700); err != nil { // no manifest
		t.Fatal(err)
	}
	copyTree(t, real, filepath.Join(parent, "20261015T000000Z")) // an extra file
	if err := os.WriteFile(filepath.Join(parent, "20261015T000000Z", "private.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyTree(t, real, filepath.Join(parent, "20261014T000000Z")) // a damaged database
	if err := os.WriteFile(filepath.Join(parent, "20261014T000000Z", "system.db"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyTree(t, real, filepath.Join(parent, "20261013T000000Z")) // a missing database
	if err := os.Remove(filepath.Join(parent, "20261013T000000Z", "audit.db")); err != nil {
		t.Fatal(err)
	}
	copyTree(t, real, filepath.Join(parent, "20261012T999999Z")) // not a time
	symlink := runtime.GOOS != "windows"
	if symlink {
		if err := os.Symlink(filepath.Join(parent, scheduled[0]), filepath.Join(parent, "20261011T000000Z")); err != nil {
			t.Fatal(err)
		}
	}
	before := names(t, parent)

	if _, err := Prune(parent, 0, false); err == nil {
		t.Error("keep 0 accepted")
	}
	dry, err := Prune(parent, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names(t, parent), before) || !slices.Equal(dry.Deleted, scheduled[:2]) {
		t.Fatalf("dry run: deleted %v, directory %v", dry.Deleted, names(t, parent))
	}

	res, err := Prune(parent, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Deleted, scheduled[:2]) || !slices.Equal(res.Kept, []string{scheduled[3], scheduled[2]}) {
		t.Errorf("deleted %v, kept %v", res.Deleted, res.Kept)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Name] = s.Reason
	}
	for name, want := range map[string]string{
		"20261017T000000Z": "not a directory",
		"20261016T000000Z": "has no manifest.json",
		"20261015T000000Z": "doesn't list: private.txt",
		"20261014T000000Z": "system.db has 5 bytes",
		"20261013T000000Z": "audit.db, which is missing",
	} {
		if !strings.Contains(reasons[name], want) {
			t.Errorf("%s: skipped with %q, want %q", name, reasons[name], want)
		}
	}
	if symlink && !strings.Contains(reasons["20261011T000000Z"], "symbolic link") {
		t.Errorf("symlink: %q", reasons["20261011T000000Z"])
	}
	left := names(t, parent)
	for _, n := range before {
		if slices.Contains(scheduled[:2], n) == slices.Contains(left, n) {
			t.Errorf("%s: deleted %v", n, !slices.Contains(left, n))
		}
	}
	// The target of the symlink is gone, the link and everything else stayed.
	if res.String() != "kept 2, deleted 2 ("+scheduled[0]+", "+scheduled[1]+"), skipped "+map[bool]string{true: "6", false: "5"}[symlink] {
		t.Errorf("summary %q", res.String())
	}

	// Nothing more to delete: the second run keeps the same two.
	again, err := Prune(parent, 2, false)
	if err != nil || len(again.Deleted) != 0 || len(again.Kept) != 2 {
		t.Errorf("second run: %+v %v", again, err)
	}
	// The kept ones still pass every restore check.
	if _, err := Verify(t.Context(), filepath.Join(parent, scheduled[3]), ""); err != nil {
		t.Error(err)
	}
}
