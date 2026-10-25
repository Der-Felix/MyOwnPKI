package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"time"
)

func (a *Agent) runHook(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	command, ok := a.cfg.Hooks[name]
	if !ok || len(command) == 0 {
		return errors.New("deployment: hook is not in agent.yaml")
	}
	if a.runHookForTest != nil {
		return a.runHookForTest(ctx, name)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...) // #nosec G204 G702 -- only fixed argv from the local root-owned allowlist, never a shell
	var stderr tailWriter
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		if output := sanitizeHookOutput(stderr.data); output != "" {
			if a.log != nil {
				a.log.Error("deployment hook failed", slog.String("hook", name), slog.Any("error", err), slog.String("output", output))
			}
			return errors.New(hookErrorText(name, err, output))
		}
		return errors.New(hookErrorText(name, err, ""))
	}
	return nil
}

func (a *Agent) runTests(ctx context.Context, group reloadGroup) error {
	seen := map[string]bool{}
	for _, d := range group.deployments {
		if seen[d.TestHook] {
			continue
		}
		seen[d.TestHook] = true
		if err := a.runHook(ctx, d.TestHook); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) checkServed(ctx context.Context, d Deployment, want string) (string, error) {
	if d.Check == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var got string
	var last error
	for attempt := range 6 {
		if attempt > 0 {
			if err := a.Sleep(ctx, 2*time.Second); err != nil {
				return got, errors.Join(last, err)
			}
		}
		// The expected fingerprint comes from the verified ACME result (or
		// the saved old certificate). This exact pin replaces CA validation
		// for a local served-certificate check, including during rollback.
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: d.Names[0],
			InsecureSkipVerify: true, // #nosec G402 -- VerifyConnection requires the exact expected leaf
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("TLS check: the service sent no certificate")
				}
				got = fingerprint(state.PeerCertificates[0].Raw)
				if got != want {
					return errors.New("TLS check: the service serves another certificate")
				}
				return nil
			},
		}}
		conn, err := dialer.DialContext(ctx, "tcp", d.Check)
		if err == nil {
			_ = conn.Close()
			return got, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return got, fmt.Errorf("TLS check for deployment %q failed: %w", d.Name, last)
}

func (a *Agent) deployGroup(ctx context.Context, group reloadGroup, materials map[string]*Material) ([]DeploymentResult, error) {
	j, err := a.stageGroup(group, materials)
	if err != nil {
		if j == nil {
			return groupFailure(group, err), err
		}
		return a.rollback(ctx, group, j, false, err)
	}
	if err := a.injectStagedFault(group); err != nil {
		return a.rollback(ctx, group, j, false, err)
	}
	if err := a.runTests(ctx, group); err != nil {
		return a.rollback(ctx, group, j, false, err)
	}
	if err := a.saveJournal(j, "reloading"); err != nil {
		return a.rollback(ctx, group, j, false, err)
	}
	if err := a.runHook(ctx, group.deployments[0].ReloadHook); err != nil {
		return a.rollback(ctx, group, j, true, err)
	}
	if err := a.saveJournal(j, "checking"); err != nil {
		return a.rollback(ctx, group, j, true, err)
	}
	var results []DeploymentResult
	for _, d := range group.deployments {
		m := materials[d.Name]
		fp, err := a.checkServed(ctx, d, fingerprint(m.Leaf.Raw))
		if err != nil {
			return a.rollback(ctx, group, j, true, err)
		}
		results = append(results, DeploymentResult{Name: d.Name, State: "deployed", Serial: certificateSerial(m.Leaf),
			NotAfter: m.Leaf.NotAfter.UTC(), Fingerprint: fp, DeployedAt: a.Now().UTC()})
	}
	if err := a.completeJournal(j, results); err != nil {
		return a.rollback(ctx, group, j, true, fmt.Errorf("complete deployment journal: %w", err))
	}
	return results, nil
}

// rollback restores the whole group and performs at most one rollback
// reload. A failed pre-reload test never reaches a reload. First installs
// remove their new files and stay failed because no old service exists.
func (a *Agent) rollback(ctx context.Context, group reloadGroup, j *deployJournal, reload bool, cause error) ([]DeploymentResult, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	phaseErr := a.saveJournal(j, "rollback")
	restoreErr := a.restoreFiles(j)
	rollbackErr := errors.Join(phaseErr, restoreErr)
	observed := map[string]string{}
	if rollbackErr == nil {
		if err := a.runTests(ctx, group); err != nil {
			rollbackErr = fmt.Errorf("restored configuration test failed; the service still has the state from before the rollback: %w", err)
		} else if reload {
			if err := a.runHook(ctx, group.deployments[0].ReloadHook); err != nil {
				rollbackErr = err
			} else {
				for _, d := range group.deployments {
					for _, meta := range j.Deployments {
						if meta.Name != d.Name || meta.First {
							continue
						}
						got, err := a.checkServed(ctx, d, meta.OldFingerprint)
						observed[d.Name] = got
						if err != nil {
							rollbackErr = errors.Join(rollbackErr, err)
						}
					}
				}
			}
		}
	}
	problem := cause
	if rollbackErr != nil {
		problem = errors.Join(cause, fmt.Errorf("rollback failed: %w", rollbackErr))
	}
	var results []DeploymentResult
	hasFirst := false
	for _, meta := range j.Deployments {
		state := "rolled_back"
		if rollbackErr != nil || meta.First {
			state = "failed"
		}
		hasFirst = hasFirst || meta.First
		message := safeDeployError(problem)
		if rollbackErr != nil {
			message = joinedDeployError(cause, rollbackErr)
		}
		results = append(results, DeploymentResult{Name: meta.Name, State: state, Serial: meta.OldSerial, NotAfter: meta.OldNotAfter,
			Fingerprint: observed[meta.Name], LastError: message})
	}
	if restoreErr == nil {
		if err := a.completeJournal(j, results); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	} else if err := a.saveDeploymentResults(results); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if rollbackErr != nil {
		for i := range results {
			results[i].State = "failed"
			results[i].LastError = joinedDeployError(cause, rollbackErr)
		}
		if serr := a.saveDeploymentResults(results); serr != nil {
			rollbackErr = errors.Join(rollbackErr, serr)
		}
		return results, errors.Join(problem, rollbackErr)
	}
	if errors.Is(cause, errInterruptedDeployment) && !hasFirst {
		return results, nil
	}
	return results, cause
}

func clippedError(err error, limit int) string {
	if err == nil {
		return ""
	}
	return clipDeployErrorText(err.Error(), limit)
}
