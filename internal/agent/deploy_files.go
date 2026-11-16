package agent

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
)

const maxDeployFile = 4 << 20

type targetFile struct {
	path     string
	data     []byte
	mode     os.FileMode
	uid, gid int
}

// deploymentPaths is the only mapping from a profile to filesystem paths.
// Both profiles enter exactly the same test/reload/check/rollback pipeline.
func deploymentPaths(d Deployment) Files {
	if d.Profile == ProfileNginx {
		return Files{Fullchain: filepath.Join(d.Dir, "fullchain.pem"), Key: filepath.Join(d.Dir, "privkey.pem")}
	}
	return d.Files
}

func targets(d Deployment, m *Material) ([]targetFile, error) {
	if _, err := tls.X509KeyPair(m.Certificate, m.Key); err != nil {
		return nil, errors.New("deployment: certificate and key do not match")
	}
	uid, gid, err := deploymentOwner(d.Owner, d.Group)
	if err != nil {
		return nil, err
	}
	mode := uint64(0o600)
	if d.KeyMode != "" {
		mode, err = strconv.ParseUint(d.KeyMode, 8, 32)
		if err != nil || mode > 0o777 || mode&0o007 != 0 {
			return nil, errors.New("deployment: invalid key_mode")
		}
	}
	f := deploymentPaths(d)
	var out []targetFile
	for _, part := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{f.Certificate, m.Certificate, 0o644}, {f.Chain, m.Chain, 0o644},
		{f.Fullchain, m.Fullchain, 0o644}, {f.Key, m.Key, os.FileMode(mode)},
	} {
		if part.path != "" {
			out = append(out, targetFile{part.path, part.data, part.mode, uid, gid})
		}
	}
	if f.Combined != "" {
		// One file with the private key in it: the key mode, never the 0644 of
		// a certificate. The buffer is a copy; stageGroup clears it.
		out = append(out, targetFile{f.Combined, combinedPEM(m), os.FileMode(mode), uid, gid})
	}
	return out, nil
}

// combinedPEM is the certificate chain followed by the private key, the form
// HAProxy reads from one file. The certificate comes first so that every
// reader of "the first PEM block" gets the leaf, and crypto/tls takes the same
// bytes as certificate and as key (it skips the blocks that are not its kind).
// The buffer holds the key: its owner clears it after the write and it is
// never logged or put into an error.
func combinedPEM(m *Material) []byte {
	chain := m.Fullchain
	if len(chain) == 0 {
		chain = append(append([]byte(nil), m.Certificate...), m.Chain...)
	}
	out := make([]byte, 0, len(chain)+len(m.Key)+2)
	for _, part := range [][]byte{chain, m.Key} {
		out = append(out, part...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	return out
}

func deploymentOwner(owner, group string) (int, int, error) {
	uid, gid := -1, -1
	if owner != "" {
		id := owner
		if _, err := strconv.Atoi(id); err != nil {
			u, err := user.Lookup(owner)
			if err != nil {
				return 0, 0, fmt.Errorf("owner %q: %w", owner, err)
			}
			id = u.Uid
		}
		value, err := strconv.ParseUint(id, 10, 31)
		if err != nil {
			return 0, 0, errors.New("owner: invalid user ID")
		}
		uid = int(value)
	}
	if group != "" {
		id := group
		if _, err := strconv.Atoi(id); err != nil {
			g, err := user.LookupGroup(group)
			if err != nil {
				return 0, 0, fmt.Errorf("group %q: %w", group, err)
			}
			id = g.Gid
		}
		value, err := strconv.ParseUint(id, 10, 31)
		if err != nil {
			return 0, 0, errors.New("group: invalid group ID")
		}
		gid = int(value)
	}
	return uid, gid, nil
}

// openTarget anchors every operation to an allowed directory. Symlinks
// are resolved for the allowlist, then os.Root contains all later access,
// including a directory swapped after that check.
func (a *Agent) openTarget(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) {
		return nil, "", errors.New("deployment: relative target path")
	}
	resolved, err := resolveUnder(a.cfg.Paths, path)
	if err != nil {
		return nil, "", err
	}
	var best string
	for _, p := range a.cfg.Paths {
		root, rerr := filepath.EvalSymlinks(p)
		if rerr == nil && Under([]string{root}, resolved) && len(root) > len(best) {
			best = root
		}
	}
	if best == "" {
		return nil, "", errors.New("deployment: an allowed parent directory must exist")
	}
	name, err := filepath.Rel(best, resolved)
	if err != nil || name == "." {
		return nil, "", errors.New("deployment: target must be a file below paths")
	}
	root, err := os.OpenRoot(best)
	if err != nil {
		return nil, "", err
	}
	return root, name, nil
}

// atomicTarget makes an exclusive temporary file next to its target,
// fsyncs its contents and metadata, renames it and fsyncs the directory.
func (a *Agent) atomicTarget(t targetFile) error {
	root, name, err := a.openTarget(t.path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	dir := filepath.Dir(name)
	// Certificate consumers must traverse these directories. Private keys
	// remain protected by the per-file owner, group and mode.
	if merr := root.MkdirAll(dir, 0o755); merr != nil {
		return merr
	}
	tmp := filepath.Join(dir, tempPrefix+rand.Text())
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	defer func() { _ = f.Close() }()
	if t.uid != -1 || t.gid != -1 {
		if err := f.Chown(t.uid, t.gid); err != nil {
			return err
		}
	}
	if err := f.Chmod(t.mode); err != nil {
		return err
	}
	if _, err := f.Write(t.data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		return err
	}
	return syncDirectory(root, dir)
}

func (a *Agent) readTarget(path string) ([]byte, os.FileInfo, error) {
	root, name, err := a.openTarget(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxDeployFile {
		return nil, nil, errors.New("deployment: target is not a regular file of at most 4 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDeployFile+1))
	if len(data) > maxDeployFile {
		return nil, nil, errors.New("deployment: target exceeds 4 MiB")
	}
	return data, info, err
}

func (a *Agent) removeTarget(path string) error {
	root, name, err := a.openTarget(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.Remove(name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDirectory(root, filepath.Dir(name))
}

// tempPrefix starts the name of the exclusive temporary file of atomicTarget.
const tempPrefix = ".myownpki-"

// tempName is exactly what atomicTarget creates: the prefix and the 26
// characters of crypto/rand.Text (base32, upper case). Nothing else is ever
// removed as a leftover.
var tempName = regexp.MustCompile(`^\.myownpki-[A-Z2-7]{26}$`)

// removeStaleTemps removes the temporary files a killed or power-cut agent
// left in the directories of its deployment targets. Such a file holds a copy
// of a target, and for a combined file the private key; HAProxy may even load
// it when its crt is a directory. It runs under the deployment lock, so no
// write of this agent is in flight. Everything goes through os.Root on an
// allowed path: only a regular file whose name is exactly a temporary name is
// removed, a symlink or any other name is left alone. A failure is logged with
// the path only and never stops the agent.
func (a *Agent) removeStaleTemps() {
	done := map[string]bool{}
	for _, d := range a.cfg.Deployments {
		for _, target := range deploymentPaths(d).Targets() {
			dir := filepath.Dir(target)
			if done[dir] {
				continue
			}
			done[dir] = true
			a.removeStaleTempsIn(target)
		}
	}
}

// removeStaleTempsIn cleans the directory of one target file.
func (a *Agent) removeStaleTempsIn(target string) {
	root, name, err := a.openTarget(target)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	dir := filepath.Dir(name)
	f, err := root.Open(dir)
	if err != nil {
		return
	}
	entries, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return
	}
	for _, e := range entries {
		if !tempName.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		// Look again right before the removal: a symlink put there since the
		// listing is removed as a link at worst, but never counted as ours.
		if info, lerr := root.Lstat(p); lerr != nil || !info.Mode().IsRegular() {
			continue
		}
		full := filepath.Join(root.Name(), p)
		if rerr := root.Remove(p); rerr != nil {
			if a.log != nil {
				a.log.Warn("deployment: a leftover temporary file could not be removed", slog.String("path", full), slog.Any("error", rerr))
			}
			continue
		}
		if a.log != nil {
			a.log.Warn("deployment: removed a leftover temporary file of an interrupted write", slog.String("path", full))
		}
	}
}

// firstPEMBlock decodes the first PEM block of data and then clears data. The
// "certificate" of a combined file is the whole file, so the buffer holds the
// private key too; the block holds a decoded copy of the first block only.
func firstPEMBlock(data []byte) *pem.Block {
	block, _ := pem.Decode(data)
	clear(data)
	return block
}
