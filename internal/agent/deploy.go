package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
)

const deploymentStateFile = "deployments.json"

// DeploymentResult contains only reportable metadata, never key material,
// hook output, paths or commands. The runtime sends it over Report.
type DeploymentResult struct {
	Name                  string    `json:"name"`
	State                 string    `json:"state"`
	Serial                string    `json:"serial,omitempty"`
	NotAfter              time.Time `json:"not_after,omitempty"`
	Fingerprint           string    `json:"fingerprint,omitempty"`
	DeployedAt            time.Time `json:"deployed_at,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
	AttemptedAt           time.Time `json:"attempted_at,omitempty"`
	Failures              int       `json:"failures,omitempty"`
	NextAttempt           time.Time `json:"next_attempt,omitempty"`
	HandledRenewalVersion int64     `json:"handled_renewal_version,omitempty"`
}

type reloadGroup struct {
	name        string
	deployments []Deployment
}

func groups(deployments []Deployment) []reloadGroup {
	var out []reloadGroup
	indices := map[string]int{}
	for _, d := range deployments {
		key := "hook:" + d.ReloadHook
		if d.ReloadHook == "" {
			key = "deployment:" + d.Name
		}
		i, ok := indices[key]
		if !ok {
			i = len(out)
			indices[key] = i
			out = append(out, reloadGroup{name: key})
		}
		out[i].deployments = append(out[i].deployments, d)
	}
	return out
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Match the server's byte-aligned hexadecimal certificate serial format.
func certificateSerial(leaf *x509.Certificate) string {
	serial := strings.ToUpper(leaf.SerialNumber.Text(16))
	if len(serial)%2 == 1 {
		serial = "0" + serial
	}
	return serial
}

// RunPass renews the named deployments through their local configuration.
// nil selects all deployments. No request can supply paths or hook names.
// The runtime calls the same operation for scheduled and requested renewals.
func (a *Agent) RunPass(ctx context.Context, names []string) ([]DeploymentResult, error) {
	return a.runPass(ctx, names, nil)
}

func (a *Agent) runPass(ctx context.Context, names []string, requested map[string]int64) ([]DeploymentResult, error) {
	a.passMu.Lock()
	defer a.passMu.Unlock()
	defer a.wakeReport()
	unlock, err := a.deploymentLock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, statErr := os.Stat(a.st.path(journalFile)); statErr == nil {
		return nil, errors.New("deployment: an unfinished journal must be recovered before another pass")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	if targetErr := a.checkDeploymentTargets(); targetErr != nil {
		return nil, targetErr
	}
	selected := make([]Deployment, 0, len(a.cfg.Deployments))
	for _, d := range a.cfg.Deployments {
		if names == nil || slices.Contains(names, d.Name) {
			selected = append(selected, d)
		}
	}
	for _, name := range names {
		if !slices.ContainsFunc(selected, func(d Deployment) bool { return d.Name == name }) {
			return nil, fmt.Errorf("deployment %q is not in agent.yaml", name)
		}
	}
	var results []DeploymentResult
	var errs []error
	previous, err := a.deploymentResults()
	if err != nil {
		return nil, err
	}
	for _, group := range groups(selected) {
		materials := map[string]*Material{}
		var obtainErr error
		for _, d := range group.deployments {
			m, err := a.obtainCertificate(ctx, d)
			if err != nil {
				obtainErr = fmt.Errorf("obtain %s: %w", d.Name, err)
				break
			}
			materials[d.Name] = m
		}
		var current []DeploymentResult
		var err error
		if obtainErr != nil {
			current = groupFailure(group, obtainErr)
			err = obtainErr
		} else {
			current, err = a.deployGroup(ctx, group, materials)
		}
		for _, m := range materials {
			clear(m.Key)
		}
		for i := range current {
			old := DeploymentResult{}
			for _, r := range previous {
				if r.Name == current[i].Name {
					old = r
					break
				}
			}
			current[i].AttemptedAt = a.Now().UTC()
			current[i].HandledRenewalVersion = max(old.HandledRenewalVersion, requested[current[i].Name])
			if current[i].State == "failed" || current[i].State == "rolled_back" {
				current[i].Failures = min(old.Failures+1, 7)
				current[i].NextAttempt = a.Now().Add(deploymentBackoff(current[i].Failures)).UTC()
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
		results = append(results, current...)
		if saveErr := a.saveDeploymentResults(current); saveErr != nil {
			return results, errors.Join(append(errs, saveErr)...)
		}
		if errors.Is(err, ErrACMEAccountRegistration) {
			break // another group would try the same account key again
		}
		if _, err := os.Stat(a.st.path(journalFile)); err == nil {
			// A failed restore keeps its journal for the next startup. Do
			// not replace it with the next group's backups.
			break
		}
	}
	return results, errors.Join(errs...)
}

func groupFailure(group reloadGroup, cause error) []DeploymentResult {
	out := make([]DeploymentResult, 0, len(group.deployments))
	for _, d := range group.deployments {
		out = append(out, DeploymentResult{Name: d.Name, State: "failed", LastError: safeDeployError(cause)})
	}
	return out
}

func safeDeployError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 1000 {
		return text[:1000] + "..."
	}
	return text
}

func (a *Agent) deploymentResults() ([]DeploymentResult, error) {
	data, err := os.ReadFile(a.st.path(deploymentStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []DeploymentResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("deployment state: %w", err)
	}
	return out, nil
}

func (a *Agent) saveDeploymentResults(results []DeploymentResult) error {
	previous, err := a.deploymentResults()
	if err != nil {
		return err
	}
	for _, result := range results {
		previous = slices.DeleteFunc(previous, func(old DeploymentResult) bool { return old.Name == result.Name })
		previous = append(previous, result)
	}
	slices.SortFunc(previous, func(a, b DeploymentResult) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	data, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	return a.durableState(deploymentStateFile, data)
}

func sameDeploymentResult(a, b DeploymentResult) bool {
	return a.Name == b.Name && a.State == b.State && a.Serial == b.Serial && a.NotAfter.Equal(b.NotAfter) &&
		a.Fingerprint == b.Fingerprint && a.DeployedAt.Equal(b.DeployedAt) && a.LastError == b.LastError &&
		a.AttemptedAt.Equal(b.AttemptedAt) && a.Failures == b.Failures && a.NextAttempt.Equal(b.NextAttempt) &&
		a.HandledRenewalVersion == b.HandledRenewalVersion
}

// pruneDeploymentResults deletes only the unchanged results accepted by the
// server. A newer local result must be sent once more before its removal.
func (a *Agent) pruneDeploymentResults(reported []DeploymentResult) (bool, error) {
	previous, err := a.deploymentResults()
	if err != nil {
		return false, err
	}
	for _, result := range reported {
		previous = slices.DeleteFunc(previous, func(old DeploymentResult) bool {
			return old.Name == result.Name && sameDeploymentResult(old, result)
		})
	}
	data, err := json.Marshal(previous)
	if err != nil {
		return false, err
	}
	if writeErr := a.durableState(deploymentStateFile, data); writeErr != nil {
		return false, writeErr
	}
	remaining := slices.ContainsFunc(previous, func(r DeploymentResult) bool {
		return !slices.ContainsFunc(a.cfg.Deployments, func(d Deployment) bool { return d.Name == r.Name })
	})
	return remaining, nil
}

// checkDeploymentTargets catches aliases between profiles and groups
// before ordering or writing. Runtime containment remains in openTarget.
func (a *Agent) checkDeploymentTargets() error {
	seen := map[string]string{}
	for _, d := range a.cfg.Deployments {
		f := deploymentPaths(d)
		for _, path := range []string{f.Certificate, f.Chain, f.Fullchain, f.Key} {
			if path == "" {
				continue
			}
			canonical, err := resolveUnder(a.cfg.Paths, path)
			if err != nil {
				return err
			}
			stateDir, serr := resolveExisting(a.st.dir)
			if serr != nil {
				return serr
			}
			bundle, _ := resolveExisting(a.cfg.CABundle)
			if Under([]string{stateDir}, canonical) || (bundle != "" && canonical == bundle) {
				return errors.New("deployment target overlaps the agent's state or trust anchor")
			}
			if runtime.GOOS == "windows" {
				canonical = strings.ToLower(canonical)
			}
			if old, ok := seen[canonical]; ok {
				return fmt.Errorf("deployment %s and %s share a target file", old, d.Name)
			}
			seen[canonical] = d.Name
		}
	}
	return nil
}

func (a *Agent) obtainCertificate(ctx context.Context, d Deployment) (*Material, error) {
	if a.obtainForTest != nil {
		return a.obtainForTest(ctx, d)
	}
	return a.obtain(ctx, d)
}
