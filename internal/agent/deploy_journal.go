package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"time"
)

const journalFile = "deployment-journal.json"

var errInterruptedDeployment = errors.New("an interrupted deployment was recovered")

type journalEntry struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

type journalDeployment struct {
	Name           string    `json:"name"`
	First          bool      `json:"first_install"`
	OldSerial      string    `json:"old_serial"`
	OldNotAfter    time.Time `json:"old_not_after"`
	OldFingerprint string    `json:"old_fingerprint"`
}

type deployJournal struct {
	Version     int                 `json:"version"`
	ID          string              `json:"id"`
	Group       string              `json:"group"`
	Phase       string              `json:"phase"`
	Files       []journalEntry      `json:"files"`
	Deployments []journalDeployment `json:"deployments"`
}

func (j *deployJournal) backup(i int) string { return "deploy-backup-" + j.ID + "-" + strconv.Itoa(i) }

func (a *Agent) saveJournal(j *deployJournal, phase string) error {
	j.Phase = phase
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return a.durableState(journalFile, data)
}

// stageGroup records every backup and a durable journal before replacing
// any target. The journal is sufficient even when the process stops
// between two file replacements or before the reload.
func (a *Agent) stageGroup(group reloadGroup, materials map[string]*Material) (*deployJournal, error) {
	if err := a.checkDeploymentTargets(); err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	j := &deployJournal{Version: 1, ID: hex.EncodeToString(random), Group: group.name, Phase: "prepared"}
	var files []targetFile
	for _, d := range group.deployments {
		items, err := targets(d, materials[d.Name])
		if err != nil {
			return nil, err
		}
		for i := range items {
			items[i].path, err = resolveUnder(a.cfg.Paths, items[i].path)
			if err != nil {
				return nil, err
			}
		}
		files = append(files, items...)
		f := deploymentPaths(d)
		certPath := f.Fullchain
		if certPath == "" {
			certPath = f.Certificate
		}
		cert, _, certErr := a.readTarget(certPath)
		key, _, keyErr := a.readTarget(f.Key)
		meta := journalDeployment{Name: d.Name}
		switch {
		case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
			meta.First = true
		case certErr != nil || keyErr != nil:
			clear(key)
			return nil, errors.Join(errors.New("deployment: previous certificate and key must both exist or both be absent"), certErr, keyErr)
		default:
			pair, err := tls.X509KeyPair(cert, key)
			clear(key)
			if err != nil {
				return nil, errors.New("deployment: previous certificate and key do not match")
			}
			meta.OldSerial, meta.OldNotAfter, meta.OldFingerprint = certificateSerial(pair.Leaf), pair.Leaf.NotAfter.UTC(), fingerprint(pair.Leaf.Raw)
		}
		j.Deployments = append(j.Deployments, meta)
	}
	for _, file := range files {
		data, info, err := a.readTarget(file.path)
		entry := journalEntry{Path: file.path, UID: -1, GID: -1}
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			a.removeBackups(j)
			return nil, err
		default:
			entry.Exists, entry.Mode = true, uint32(info.Mode().Perm())
			entry.UID, entry.GID = previousOwner(info)
			if err := a.durableState(j.backup(len(j.Files)), data); err != nil {
				clear(data)
				a.removeBackups(j)
				return nil, err
			}
			clear(data)
		}
		j.Files = append(j.Files, entry)
	}
	if err := a.saveJournal(j, "prepared"); err != nil {
		return j, err
	}
	for _, file := range files {
		if err := a.atomicTarget(file); err != nil {
			return j, err
		}
	}
	return j, a.saveJournal(j, "replaced")
}

func (a *Agent) restoreFiles(j *deployJournal) error {
	var errs []error
	for i, entry := range j.Files {
		if !entry.Exists {
			if err := a.removeTarget(entry.Path); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		data, err := os.ReadFile(a.st.path(j.backup(i)))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		err = a.atomicTarget(targetFile{entry.Path, data, os.FileMode(entry.Mode), entry.UID, entry.GID})
		clear(data)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) removeBackups(j *deployJournal) {
	for i := range j.Files {
		_ = os.Remove(a.st.path(j.backup(i)))
	}
}

func (a *Agent) completeJournal(j *deployJournal, results []DeploymentResult) error {
	if err := a.saveDeploymentResults(results); err != nil {
		return err
	}
	if err := os.Remove(a.st.path(journalFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	root, err := os.OpenRoot(a.st.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := syncDirectory(root, "."); err != nil {
		return err
	}
	a.removeBackups(j)
	return syncDirectory(root, ".")
}

// recoveryGroup validates the journal against today's local configuration.
// Journal data is never permission to write a new path or run a new hook.
func (a *Agent) recoveryGroup(j *deployJournal) (reloadGroup, error) {
	if err := a.checkDeploymentTargets(); err != nil {
		return reloadGroup{}, err
	}
	bad := errors.New("deployment journal does not match agent.yaml; restore the previous configuration before recovering")
	id, err := hex.DecodeString(j.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != j.ID || j.Version != 1 || len(j.Files) == 0 || len(j.Files) > 4000 {
		return reloadGroup{}, bad
	}
	if !slices.Contains([]string{"prepared", "replaced", "reloading", "checking", "rollback"}, j.Phase) {
		return reloadGroup{}, bad
	}
	for _, group := range groups(a.cfg.Deployments) {
		if group.name != j.Group {
			continue
		}
		// A pass can renew only part of a shared reload group (for example
		// one explicit renew request). Untouched members need no backups.
		group.deployments = slices.DeleteFunc(group.deployments, func(d Deployment) bool {
			return !slices.ContainsFunc(j.Deployments, func(meta journalDeployment) bool { return meta.Name == d.Name })
		})
		if len(group.deployments) != len(j.Deployments) {
			return reloadGroup{}, bad
		}
		var expected []string
		for _, d := range group.deployments {
			if !slices.ContainsFunc(j.Deployments, func(meta journalDeployment) bool { return meta.Name == d.Name }) {
				return reloadGroup{}, bad
			}
			f := deploymentPaths(d)
			for _, path := range []string{f.Certificate, f.Chain, f.Fullchain, f.Key} {
				if path == "" {
					continue
				}
				canonical, err := resolveUnder(a.cfg.Paths, path)
				if err != nil {
					return reloadGroup{}, err
				}
				expected = append(expected, canonical)
			}
		}
		if len(expected) != len(j.Files) {
			return reloadGroup{}, bad
		}
		seen := map[string]bool{}
		for _, f := range j.Files {
			if seen[f.Path] || !slices.Contains(expected, f.Path) || f.Mode > 0o777 || f.UID < -1 || f.GID < -1 {
				return reloadGroup{}, bad
			}
			seen[f.Path] = true
		}
		return group, nil
	}
	return reloadGroup{}, bad
}

// Recover restores one interrupted group before any new ACME/deploy pass.
// Reload/check failures are reported once; they never start a retry loop.
func (a *Agent) Recover(ctx context.Context) ([]DeploymentResult, error) {
	a.passMu.Lock()
	defer a.passMu.Unlock()
	unlock, err := a.deploymentLock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	a.st.cleanupWritten()
	data, err := os.ReadFile(a.st.path(journalFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("deployment journal exceeds 1 MiB")
	}
	var j deployJournal
	if jerr := json.Unmarshal(data, &j); jerr != nil {
		return nil, errors.New("invalid deployment journal")
	}
	group, err := a.recoveryGroup(&j)
	if err != nil {
		return nil, err
	}
	results, rollbackErr := a.rollback(ctx, group, &j, true, errInterruptedDeployment)
	return results, rollbackErr
}
