package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const writableHint = "add %s to /etc/systemd/system/myownpki-agent.service.d/10-paths.conf (ReadWritePaths), then systemctl daemon-reload and restart"

func writableError(path string, err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
		return fmt.Errorf("%s is not writable: "+writableHint+": %w", path, path, err)
	}
	return fmt.Errorf("write check for %s failed: %w", path, err)
}

// checkWritable creates and removes a file through os.Root. A missing target
// directory is checked at its nearest existing parent, which will create it.
func (a *Agent) checkWritable(path string) error {
	openRoot := os.OpenRoot
	if a.openRootForTest != nil {
		openRoot = a.openRootForTest
	}
	probe := filepath.Clean(path)
	root, err := openRoot(probe)
	for errors.Is(err, fs.ErrNotExist) {
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
		root, err = openRoot(probe)
	}
	if err != nil {
		return writableError(path, err)
	}
	defer func() { _ = root.Close() }()
	var random [8]byte
	if _, readErr := rand.Read(random[:]); readErr != nil {
		return readErr
	}
	name := ".myownpki-agent-write-check-" + hex.EncodeToString(random[:])
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return writableError(path, err)
	}
	closeErr := file.Close()
	removeErr := root.Remove(name)
	if closeErr != nil {
		return writableError(path, closeErr)
	}
	if removeErr != nil {
		return writableError(path, removeErr)
	}
	return nil
}

func (a *Agent) deploymentWriteFailures(deployments []Deployment) map[string]error {
	failures := map[string]error{}
	checked := map[string]error{}
	check := func(path string) error {
		if path == "" {
			return nil
		}
		if err, ok := checked[path]; ok {
			return err
		}
		err := a.checkWritable(path)
		checked[path] = err
		return err
	}
	if a.cfg.Enrollment.Challenge == ChallengeWebroot {
		if err := check(a.cfg.Enrollment.Webroot); err != nil {
			for _, d := range deployments {
				failures[d.Name] = err
			}
			return failures
		}
	}
	for _, d := range deployments {
		if d.Challenge == ChallengeWebroot {
			if err := check(d.Webroot); err != nil {
				failures[d.Name] = err
				continue
			}
		}
		var directories []string
		if d.Profile == ProfileNginx {
			directories = []string{d.Dir}
		} else {
			files := deploymentPaths(d)
			for _, path := range []string{files.Certificate, files.Chain, files.Fullchain, files.Key} {
				if path != "" {
					directories = append(directories, filepath.Dir(path))
				}
			}
		}
		for _, directory := range directories {
			if err := check(directory); err != nil {
				failures[d.Name] = err
				break
			}
		}
	}
	return failures
}

func (a *Agent) preflightStart() error {
	if err := a.checkWritable(a.st.dir); err != nil {
		return err
	}
	failures := a.deploymentWriteFailures(a.cfg.Deployments)
	if len(failures) == 0 {
		return nil
	}
	previous, err := a.deploymentResults()
	if err != nil {
		return err
	}
	var results []DeploymentResult
	for _, d := range a.cfg.Deployments {
		if writeErr := failures[d.Name]; writeErr != nil {
			results = append(results, DeploymentResult{Name: d.Name, State: "failed", LastError: safeDeployError(writeErr)})
		}
	}
	a.applyResultHistory(results, previous, nil)
	return a.saveDeploymentResults(results)
}
