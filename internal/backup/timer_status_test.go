package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReadTimerStatus: the dashboard reads names only; what is not exactly a
// scheduled backup's name does not count.
func TestReadTimerStatus(t *testing.T) {
	t.Parallel()
	at := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	tests := []struct {
		name       string
		dirs       []string
		files      []string
		newest     time.Time
		unverified []string
		seen       bool
	}{
		{"nothing there", nil, nil, time.Time{}, nil, false},
		{"one backup", []string{"20261101T030000Z"}, nil, at("2026-11-01T03:00:00Z"), nil, true},
		{"the newest by name wins", []string{"20261103T030000Z", "20261101T030000Z", "20261102T030000Z"}, nil, at("2026-11-03T03:00:00Z"), nil, true},
		{"only an unverified one", []string{"20261101T030000Z-unverified"}, nil, time.Time{}, []string{"20261101T030000Z-unverified"}, true},
		{"unverified does not count as newest", []string{"20261101T030000Z", "20261102T030000Z-unverified"}, nil, at("2026-11-01T03:00:00Z"), []string{"20261102T030000Z-unverified"}, true},
		{"update backups and notes are not the timer's", []string{"20261101T030000Z-0.3.1", "notes", "20261101"}, []string{"20261105T030000Z"}, time.Time{}, nil, false},
		{"names that look right but are no times", []string{"20261340T250000Z", "20261101T030000z", "20261101T030000Z-unverified-unverified", "x20261101T030000Z"}, nil, time.Time{}, nil, false},
		{"unverified suffix on something else", []string{"notes-unverified"}, nil, time.Time{}, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.Mkdir(filepath.Join(parent, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(parent, f), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			st, err := ReadTimerStatus(parent)
			if err != nil {
				t.Fatal(err)
			}
			if !st.Newest.Equal(tc.newest) || len(st.Unverified) != len(tc.unverified) || st.Seen() != tc.seen {
				t.Fatalf("status %+v seen %v, want newest %v unverified %v seen %v", st, st.Seen(), tc.newest, tc.unverified, tc.seen)
			}
			for i, u := range tc.unverified {
				if st.Unverified[i] != u {
					t.Errorf("unverified %v, want %v", st.Unverified, tc.unverified)
				}
			}
		})
	}
	t.Run("a missing directory is no error", func(t *testing.T) {
		t.Parallel()
		st, err := ReadTimerStatus(filepath.Join(t.TempDir(), "missing"))
		if err != nil || st.Seen() {
			t.Errorf("%+v %v", st, err)
		}
	})
	t.Run("a file is an error", func(t *testing.T) {
		t.Parallel()
		f := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadTimerStatus(f); err == nil {
			t.Error("a file as the backup directory was accepted")
		}
	})
}
