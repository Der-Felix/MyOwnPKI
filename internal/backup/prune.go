package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Scheduled backups (v0.2.2, owner 2026-10-24): the timer
// myownpki-backup.timer runs `myownpki backup scheduled DIR --keep N`, which
// writes DIR/<UTC time>, verifies it and prunes the older ones.
//
// Prune deletes only what the timer made: a directory (never a symlink)
// named exactly like ScheduledName, with a readable manifest.json, that
// holds exactly the files its manifest lists, each with the listed size.
// Anything else in DIR – the update backups of install.sh
// (<time>-<version>), a backup that failed its check (<time>-unverified),
// notes, other files – is left alone, and so is a timer backup that doesn't
// pass these checks (it is reported as skipped).

// scheduledLayout is the name of a scheduled backup: UTC, to the second.
const scheduledLayout = "20060102T150405Z"

var scheduledPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

// UnverifiedSuffix marks a scheduled backup whose check failed; Prune never
// deletes it and it doesn't count as one of the kept backups.
const UnverifiedSuffix = "-unverified"

// MaxKeep bounds --keep.
const MaxKeep = 1000

// ScheduledName is the directory name of a scheduled backup made at t.
func ScheduledName(t time.Time) string { return t.UTC().Format(scheduledLayout) }

// isScheduled reports whether name is the name of a scheduled backup.
func isScheduled(name string) bool {
	if !scheduledPattern.MatchString(name) {
		return false
	}
	_, err := time.Parse(scheduledLayout, name)
	return err == nil
}

// PruneResult says what Prune did (or, with dryRun, would do).
type PruneResult struct {
	Kept    []string // the newest valid scheduled backups, newest first
	Deleted []string // oldest first
	Skipped []Skipped
}

// Skipped is a directory that looks like a scheduled backup but is left
// alone.
type Skipped struct {
	Name, Reason string
}

// Prune keeps the newest keep scheduled backups in parent and deletes the
// older ones. keep must be at least 1, so the newest backup always stays.
func Prune(parent string, keep int, dryRun bool) (*PruneResult, error) {
	if keep < 1 || keep > MaxKeep {
		return nil, fmt.Errorf("keep %d: must be 1 to %d – the newest backup always stays", keep, MaxKeep)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	res := &PruneResult{}
	var valid []string
	for _, e := range entries {
		name := e.Name()
		if !isScheduled(name) {
			continue // not made by the timer: never touched, not reported
		}
		if reason := checkScheduled(filepath.Join(parent, name)); reason != "" {
			res.Skipped = append(res.Skipped, Skipped{Name: name, Reason: reason})
			continue
		}
		valid = append(valid, name)
	}
	slices.Sort(valid) // the names are UTC times: sorted by name = sorted by age
	slices.Reverse(valid)
	if len(valid) <= keep {
		res.Kept = valid
		return res, nil
	}
	res.Kept = valid[:keep]
	old := slices.Clone(valid[keep:])
	slices.Reverse(old)
	for _, name := range old {
		if !dryRun {
			if err := os.RemoveAll(filepath.Join(parent, name)); err != nil {
				return res, fmt.Errorf("delete %s: %w", name, err)
			}
		}
		res.Deleted = append(res.Deleted, name)
	}
	return res, nil
}

// checkScheduled says why dir may not be deleted; "" = it is a complete
// backup and nothing else.
func checkScheduled(dir string) string {
	st, err := os.Lstat(dir)
	switch {
	case err != nil:
		return err.Error()
	case st.Mode()&fs.ModeSymlink != 0:
		return "a symbolic link, not a backup directory"
	case !st.IsDir():
		return "not a directory"
	}
	m, err := readManifest(dir)
	if err != nil {
		return err.Error()
	}
	want := map[string]int64{ManifestFile: -1}
	dirs := map[string]bool{}
	for _, f := range m.Files {
		rel := filepath.FromSlash(f.Path)
		if !filepath.IsLocal(rel) {
			return fmt.Sprintf("the manifest names %q – outside the backup", f.Path)
		}
		want[rel] = f.Size
		for d := filepath.Dir(rel); d != "."; d = filepath.Dir(d) {
			dirs[d] = true
		}
	}
	var problem string
	seen := map[string]bool{}
	werr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		size, listed := want[rel]
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			problem = "it holds a symbolic link: " + filepath.ToSlash(rel)
		case d.IsDir() && dirs[rel]:
			return nil
		case d.IsDir() || !listed:
			problem = "it holds something the manifest doesn't list: " + filepath.ToSlash(rel)
		case size >= 0 && info.Size() != size:
			problem = fmt.Sprintf("%s has %d bytes, the manifest says %d", filepath.ToSlash(rel), info.Size(), size)
		default:
			seen[rel] = true
			return nil
		}
		return fs.SkipAll
	})
	if werr != nil && !errors.Is(werr, fs.SkipAll) {
		return werr.Error()
	}
	if problem != "" {
		return problem
	}
	for rel := range want {
		if !seen[rel] {
			return "the manifest lists " + filepath.ToSlash(rel) + ", which is missing"
		}
	}
	return ""
}

// String sums a result up in one line.
func (r *PruneResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "kept %d", len(r.Kept))
	if len(r.Deleted) > 0 {
		fmt.Fprintf(&b, ", deleted %d (%s)", len(r.Deleted), strings.Join(r.Deleted, ", "))
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, ", skipped %d", len(r.Skipped))
	}
	return b.String()
}

// TimerStatus is what the dashboard shows about the scheduled backups in a
// directory (v0.2.2, owner 2026-10-24).
type TimerStatus struct {
	// Newest is the time of the newest scheduled backup (from its name);
	// zero = there is none. A backup that failed its check doesn't count.
	Newest time.Time
	// Unverified are the backups that failed their check, oldest first.
	Unverified []string
}

// Seen reports whether the timer has ever written a backup here.
func (s TimerStatus) Seen() bool { return !s.Newest.IsZero() || len(s.Unverified) > 0 }

// ReadTimerStatus lists parent by name only – it opens no backup, so the
// dashboard can call it on every view. A missing parent is no error: the
// timer hasn't run yet (or isn't installed).
func ReadTimerStatus(parent string) (TimerStatus, error) {
	var st TimerStatus
	fi, err := os.Stat(parent)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return st, nil
	case err != nil:
		return st, err
	case !fi.IsDir():
		return st, fmt.Errorf("%s is not a directory", parent)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return st, err
	}
	for _, e := range entries { // sorted by name = by age
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if base, ok := strings.CutSuffix(name, UnverifiedSuffix); ok && isScheduled(base) {
			st.Unverified = append(st.Unverified, name)
			continue
		}
		if isScheduled(name) {
			st.Newest, _ = time.Parse(scheduledLayout, name) // isScheduled parsed it
		}
	}
	return st, nil
}
