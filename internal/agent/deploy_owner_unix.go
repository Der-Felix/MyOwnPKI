//go:build !windows

package agent

import (
	"os"
	"syscall"
)

func previousOwner(info os.FileInfo) (int, int) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid), int(stat.Gid)
	}
	return -1, -1
}
