package version

import (
	"runtime/debug"
	"testing"
)

func TestString(t *testing.T) {
	t.Parallel()
	base := Info{Version: "v0.1.0", GoVersion: "go1.27.0", Platform: "linux/amd64"}
	tests := []struct {
		name string
		mod  func(*Info)
		want string
	}{
		{
			name: "no vcs data",
			mod:  func(*Info) {},
			want: "myownpki v0.1.0 (commit unknown, unknown date, go1.27.0, linux/amd64)",
		},
		{
			name: "commit is shortened",
			mod: func(i *Info) {
				i.Commit = "1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d"
				i.Date = "2026-10-12T09:30:00Z"
			},
			want: "myownpki v0.1.0 (commit 1a2b3c4d5e6f, 2026-10-12T09:30:00Z, go1.27.0, linux/amd64)",
		},
		{
			name: "dirty tree is visible",
			mod: func(i *Info) {
				i.Commit = "1a2b3c4d5e6f7a8b"
				i.Modified = true
			},
			want: "myownpki v0.1.0 (commit 1a2b3c4d5e6f+dirty, unknown date, go1.27.0, linux/amd64)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info := base
			tt.mod(&info)
			if got := info.String("myownpki"); got != tt.want {
				t.Errorf("String() =\n  %q\nwant\n  %q", got, tt.want)
			}
		})
	}
}

func TestApplyBuildInfo(t *testing.T) {
	t.Parallel()
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.2.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc"},
			{Key: "vcs.time", Value: "2026-10-12T09:30:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	t.Run("fills empty fields", func(t *testing.T) {
		t.Parallel()
		var info Info
		applyBuildInfo(&info, bi)
		want := Info{Version: "v0.2.0", Commit: "abc", Date: "2026-10-12T09:30:00Z", Modified: true}
		if info != want {
			t.Errorf("got %+v, want %+v", info, want)
		}
	})

	t.Run("link-time values win", func(t *testing.T) {
		t.Parallel()
		info := Info{Version: "v1.0.0", Commit: "release", Date: "2026-01-01T00:00:00Z"}
		applyBuildInfo(&info, bi)
		if info.Version != "v1.0.0" || info.Commit != "release" || info.Date != "2026-01-01T00:00:00Z" {
			t.Errorf("link-time values were overwritten: %+v", info)
		}
	})

	t.Run("devel version is ignored", func(t *testing.T) {
		t.Parallel()
		var info Info
		applyBuildInfo(&info, &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}})
		if info.Version != "" {
			t.Errorf("Version = %q, want empty", info.Version)
		}
	})
}

func TestGetHasDefaults(t *testing.T) {
	t.Parallel()
	info := Get()
	if info.Version == "" || info.GoVersion == "" || info.Platform == "" {
		t.Errorf("Get() returned empty fields: %+v", info)
	}
}
