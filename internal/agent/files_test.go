package agent

import (
	"slices"
	"strings"
	"testing"
)

func TestFilesTargetsAreInOneFixedOrderWithoutEmptyOnes(t *testing.T) {
	t.Parallel()
	f := Files{Key: "/k", Fullchain: "/f", Chain: "/c", Certificate: "/p"}
	if got, want := f.Targets(), []string{"/p", "/c", "/f", "/k"}; !slices.Equal(got, want) {
		t.Errorf("Targets() = %v, want %v", got, want)
	}
	if got := (Files{Fullchain: "/f", Key: "/k"}).Targets(); !slices.Equal(got, []string{"/f", "/k"}) {
		t.Errorf("Targets() = %v", got)
	}
	if got := (Files{}).Targets(); len(got) != 0 {
		t.Errorf("Targets() of nothing = %v", got)
	}
}

func TestFilesCertPathPrefersTheFullchain(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		f         Files
		cert, key string
	}{
		{Files{Certificate: "/p", Fullchain: "/f", Key: "/k"}, "/f", "/k"},
		{Files{Certificate: "/p", Chain: "/c", Key: "/k"}, "/p", "/k"},
		{Files{Fullchain: "/f", Key: "/k"}, "/f", "/k"},
	} {
		if tc.f.CertPath() != tc.cert || tc.f.KeyPath() != tc.key {
			t.Errorf("%+v: CertPath %q KeyPath %q", tc.f, tc.f.CertPath(), tc.f.KeyPath())
		}
	}
}

// Map reaches every field: a field that Map forgets would escape the test
// root of the dry run, and fields lists the same names agent.yaml uses.
func TestFilesMapAndFieldsCoverEveryTarget(t *testing.T) {
	t.Parallel()
	every := Files{Certificate: "/a", Chain: "/b", Fullchain: "/c", Key: "/d", Combined: "/e"}
	mapped := every.Map(func(p string) string { return "/root" + p })
	if got, want := mapped.Targets(), []string{"/root/a", "/root/b", "/root/c", "/root/d", "/root/e"}; !slices.Equal(got, want) {
		t.Errorf("Map: %v, want %v", got, want)
	}
	if got := every.Map(func(p string) string { return p }); got != every {
		t.Errorf("identity Map changed the files: %+v", got)
	}
	var names []string
	for _, f := range every.fields() {
		names = append(names, f.Name)
	}
	if got := strings.Join(names, ","); got != "certificate,chain,fullchain,key,combined" {
		t.Errorf("fields() = %s", got)
	}
}
