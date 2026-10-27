//go:build !linux

package agent

import "errors"

func platformSetupPreflight() error {
	return errors.New("setup is supported only on Linux with systemd")
}
