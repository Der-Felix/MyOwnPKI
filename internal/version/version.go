// Package version reports how a MyOwnPKI binary was built.
//
// Release builds set the values at link time, for example:
//
//	go build -ldflags "-X github.com/Der-Felix/MyOwnPKI/internal/version.version=v0.1.0" ./cmd/myownpki
//
// Local builds fall back to the VCS data the Go toolchain embeds automatically
// (commit, commit time, uncommitted changes).
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set by -ldflags "-X ..." in release builds; empty otherwise.
var (
	version string
	commit  string
	date    string
)

// Info describes a build. All times are UTC (RFC 3339).
type Info struct {
	Version   string
	Commit    string
	Date      string
	Modified  bool // built from a working tree with uncommitted changes
	GoVersion string
	Platform  string // GOOS/GOARCH
}

// Get returns the build information of the running binary.
func Get() Info {
	info := Info{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		applyBuildInfo(&info, bi)
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}

// applyBuildInfo fills fields that were not set at link time.
func applyBuildInfo(info *Info, bi *debug.BuildInfo) {
	if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
}

// String formats the build information for --version output, e.g.
//
//	myownpki v0.1.0 (commit 1a2b3c4d5e6f, 2026-10-12T09:30:00Z, go1.27.0, linux/amd64)
func (i Info) String(binary string) string {
	c := "unknown"
	if i.Commit != "" {
		c = i.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		if i.Modified {
			c += "+dirty"
		}
	}
	d := i.Date
	if d == "" {
		d = "unknown date"
	}
	return fmt.Sprintf("%s %s (commit %s, %s, %s, %s)", binary, i.Version, c, d, i.GoVersion, i.Platform)
}
