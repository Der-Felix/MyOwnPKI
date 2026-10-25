//go:build !e2etest

package agent

func (a *Agent) injectStagedFault(reloadGroup) error { return nil }
