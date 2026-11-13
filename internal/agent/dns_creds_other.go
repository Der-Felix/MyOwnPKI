//go:build !unix

package agent

import (
	"errors"
	"os"
)

// credsEnforcePermissions: Windows has no POSIX mode and owner to check, like
// the enrollment token file (setup.go). The file is protected by the ACL of
// its directory, which the admin sets (docs: site/dns-01.md).
const credsEnforcePermissions = false

// openCredentialsFile refuses a symbolic link (there is no O_NOFOLLOW) and
// then checks that the file it opened is the one it looked at.
func openCredentialsFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, errSymlink
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, errors.Join(errSymlink, err)
	}
	return f, nil
}

var errSymlink = errors.New("symbolic link")

func isSymlinkOpenError(err error) bool { return errors.Is(err, errSymlink) }

func fileUID(os.FileInfo) (int, bool) { return 0, false }

func effectiveUID() int { return -1 }
