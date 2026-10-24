package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/backup"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// TestBackupAttention: the dashboard warns about a scheduled backup that
// failed its check and about a newest backup older than 48 hours – only
// when the timer is installed or has written a backup – and stays quiet
// for an admin who switched the timer off before it ever ran.
func TestBackupAttention(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	type setup struct {
		timer   bool          // the unit file is installed
		enabled time.Duration // > 0: switched on that long ago
		dirs    []time.Duration
		extra   []string // other names in the backup directory
		file    bool     // the backup "directory" is a file
	}
	for _, tt := range []struct {
		name string
		setup
		want []string // substrings, one per message; nil = no message
	}{
		{name: "nothing installed"},
		{name: "another backup tool only", setup: setup{extra: []string{"20261020T000000Z-0.2.1", "notes"}}},
		{name: "timer switched off, never ran", setup: setup{timer: true}},
		{name: "timer just switched on", setup: setup{timer: true, enabled: time.Hour}},
		{name: "timer on for three days, no backup", setup: setup{timer: true, enabled: 72 * time.Hour},
			want: []string{"No scheduled backup in BACKUPS although myownpki-backup.timer is on since 2026-10-21"}},
		{name: "fresh backup", setup: setup{timer: true, enabled: 72 * time.Hour, dirs: []time.Duration{50 * time.Hour, time.Hour}}},
		{name: "47 hours", setup: setup{timer: true, dirs: []time.Duration{47 * time.Hour}}},
		{name: "49 hours", setup: setup{timer: true, enabled: 72 * time.Hour, dirs: []time.Duration{60 * time.Hour, 49 * time.Hour}},
			want: []string{"The newest scheduled backup is from 2026-10-22 11:00 UTC, 49 hours ago – myownpki-backup.timer is off or the backup fails"}},
		{name: "timer removed, old backups stay", setup: setup{dirs: []time.Duration{100 * time.Hour}},
			want: []string{"100 hours ago"}},
		{name: "an update backup is no timer backup", setup: setup{timer: true, enabled: 72 * time.Hour, extra: []string{"20261024T110000Z-0.2.1"}},
			want: []string{"No scheduled backup"}},
		{name: "failed check", setup: setup{timer: true, dirs: []time.Duration{time.Hour}, extra: []string{"20261024T100000Z" + backup.UnverifiedSuffix}},
			want: []string{"A scheduled backup failed its check and was kept as BACKUPS/20261024T100000Z-unverified – find the cause"}},
		{name: "two failed checks, nothing good", setup: setup{timer: true, extra: []string{"20261023T100000Z-unverified", "20261024T100000Z-unverified"}},
			want: []string{"2 scheduled backups failed their check (newest: BACKUPS/20261024T100000Z-unverified)"}},
		{name: "unreadable", setup: setup{timer: true, file: true}, want: []string{"The scheduled backups can't be checked"}},
		{name: "unreadable without a timer", setup: setup{file: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			w := backupWatch{dir: filepath.Join(root, "backups"), timer: filepath.Join(root, "myownpki-backup.timer"),
				enabled: filepath.Join(root, "wants-myownpki-backup.timer"), clk: clock.NewFake(now)}
			write := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.timer {
				write(w.timer)
			}
			if tt.enabled > 0 {
				write(w.enabled)
				if err := os.Chtimes(w.enabled, now.Add(-tt.enabled), now.Add(-tt.enabled)); err != nil {
					t.Fatal(err)
				}
			}
			if tt.file {
				write(w.dir)
			}
			names := tt.extra
			for _, age := range tt.dirs {
				names = append(names, backup.ScheduledName(now.Add(-age)))
			}
			for _, n := range names {
				if err := os.MkdirAll(filepath.Join(w.dir, n), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			got := w.attention()
			if all := (&Server{backups: w}).attention(false); len(all) != len(got) { // what the dashboard gets
				t.Errorf("dashboard: %s", kinds(all))
			}
			if len(got) != len(tt.want) {
				t.Fatalf("%d messages, want %d: %s", len(got), len(tt.want), kinds(got))
			}
			for i, m := range got {
				if want := strings.ReplaceAll(tt.want[i], "BACKUPS", w.dir); m.Kind != "warn" || !strings.Contains(m.Text, want) {
					t.Errorf("message %d: %s: %q\nwant %q", i, m.Kind, m.Text, want)
				}
			}
		})
	}
}
