package server

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/backup"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The daily backup on the dashboard (v0.2.2, owner 2026-10-24): a warning
// when a scheduled backup failed its check, or when the newest one is older
// than 48 hours – the timer is off or the backup fails. The timer runs daily
// with up to an hour of random delay, so 48 hours means one run was missed.
//
// The server only reads: it lists the backup directory by name and looks
// whether the timer's unit file and its link in timers.target.wants exist.
// Its unit needs no new rights for that – ProtectSystem=strict makes /etc
// and /var read-only, not unreadable, and /var/backups/myownpki belongs to
// the service user (install.sh) – so the backup service doesn't have to
// write a status file for it.
const (
	backupMaxAge  = 48 * time.Hour
	backupDir     = "/var/backups/myownpki"
	backupTimer   = "/etc/systemd/system/myownpki-backup.timer"
	backupEnabled = "/etc/systemd/system/timers.target.wants/myownpki-backup.timer"
)

// backupWatch knows where the timer and its backups are; tests use their own
// directories.
type backupWatch struct {
	dir, timer, enabled string
	clk                 clock.Clock
}

func newBackupWatch(clk clock.Clock) backupWatch {
	return backupWatch{dir: backupDir, timer: backupTimer, enabled: backupEnabled, clk: clk}
}

// attention is what the dashboard shows. Nothing when the timer is neither
// installed nor has ever written a backup (another platform, a container,
// an admin who backs up differently), and nothing when it is installed but
// switched off (install.sh --no-backup-timer) and never ran – that was
// chosen. Once it has written a backup, a stop is a warning.
func (w backupWatch) attention() []view.Message {
	installed := exists(w.timer)
	st, err := backup.ReadTimerStatus(w.dir)
	if err != nil {
		if !installed {
			return nil
		}
		return []view.Message{{Kind: view.MessageWarning, Text: "The scheduled backups can't be checked: " + err.Error() + "."}}
	}
	if !installed && !st.Seen() {
		return nil
	}
	now := w.clk.Now()
	var out []view.Message
	if n := len(st.Unverified); n > 0 {
		newest := st.Unverified[n-1]
		text := "A scheduled backup failed its check and was kept as " + w.dir + "/" + newest
		if n > 1 {
			text = strconv.Itoa(n) + " scheduled backups failed their check (newest: " + w.dir + "/" + newest + ")"
		}
		out = append(out, view.Message{Kind: view.MessageWarning,
			Text: text + " – find the cause (journalctl -u myownpki-backup), then delete the directory."})
	}
	switch {
	case !st.Newest.IsZero() && now.Sub(st.Newest) > backupMaxAge:
		out = append(out, view.Message{Kind: view.MessageWarning, Text: "The newest scheduled backup is from " + view.DateTime(st.Newest) + ", " +
			strconv.Itoa(int(now.Sub(st.Newest).Hours())) + " hours ago – myownpki-backup.timer is off or the backup fails (systemctl status myownpki-backup.timer myownpki-backup)."})
	case st.Newest.IsZero():
		// Never a good backup: a warning once the timer has been on for 48
		// hours (the time of its link is when it was switched on).
		if fi, lerr := os.Lstat(w.enabled); lerr == nil && now.Sub(fi.ModTime()) > backupMaxAge {
			out = append(out, view.Message{Kind: view.MessageWarning, Text: "No scheduled backup in " + w.dir + " although myownpki-backup.timer is on since " +
				view.DateTime(fi.ModTime()) + " – check systemctl status myownpki-backup."})
		}
	}
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
