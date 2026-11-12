//go:build !linux

package agent

import (
	"errors"
	"fmt"
)

func platformSetupPreflight() error {
	return errors.New("setup is supported only on Linux with systemd")
}

func platformEditPreflight(command string) error {
	return fmt.Errorf("%s is supported only on Linux with systemd", command)
}
