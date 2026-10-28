//go:build linux

package agent

import (
	"errors"
	"os"
	"os/exec"
)

func platformSetupPreflight() error {
	if os.Geteuid() != 0 {
		return errors.New("setup must run as root; no host files were changed")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("setup requires systemctl; no host files were changed")
	}
	return nil
}
