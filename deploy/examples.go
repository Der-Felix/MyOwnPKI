// Package deploy exposes the installation examples shipped in release assets.
package deploy

import (
	"embed"
	"fmt"
)

//go:embed agent.example.yaml systemd/myownpki-agent.service systemd/agent-low-ports.conf
var agentExamples embed.FS

// AgentExample returns one immutable agent installation example.
func AgentExample(name string) ([]byte, error) {
	paths := map[string]string{
		"agent.yaml": "agent.example.yaml",
		"unit":       "systemd/myownpki-agent.service",
		"low-ports":  "systemd/agent-low-ports.conf",
	}
	path, ok := paths[name]
	if !ok {
		return nil, fmt.Errorf("unknown agent example %q", name)
	}
	data, err := agentExamples.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent example %s: %w", name, err)
	}
	return data, nil
}
