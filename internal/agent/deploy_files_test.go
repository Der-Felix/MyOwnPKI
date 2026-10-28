package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDeploymentProfileFiles(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{ProfileNginx, ProfileFile} {
		t.Run(profile, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			a := &Agent{cfg: &Config{Paths: []string{root}}}
			d := Deployment{Name: "proxy", Profile: profile, Dir: filepath.Join(root, "nginx"),
				Files: Files{Certificate: filepath.Join(root, "leaf.pem"), Chain: filepath.Join(root, "chain.pem"),
					Fullchain: filepath.Join(root, "fullchain.pem"), Key: filepath.Join(root, "key.pem")}}
			// Replace complete generations, including a distinct local key.
			for _, serial := range []int64{1, 2} {
				material := testMaterial(t, "proxy.homelab.lan", serial)
				files, err := targets(d, material)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					if err := a.atomicTarget(file); err != nil {
						t.Fatal(err)
					}
					data, info, err := a.readTarget(file.path)
					if err != nil || !bytes.Equal(data, file.data) {
						t.Fatalf("profile %s did not write the complete file: %v", profile, err)
					}
					if runtime.GOOS != "windows" && info.Mode().Perm() != file.mode {
						t.Fatalf("profile %s: mode=%o, want %o", profile, info.Mode().Perm(), file.mode)
					}
				}
			}
			material := testMaterial(t, "proxy.homelab.lan", 3)
			files, err := targets(d, material)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if writeErr := a.atomicTarget(file); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			written, err := a.writtenLeafFingerprint(d, fingerprint(material.Leaf.Raw))
			if err != nil || written != fingerprint(material.Leaf.Raw) {
				t.Errorf("written fingerprint = %q, %v", written, err)
			}
			d.Check = "127.0.0.1:443"
			if ignored, err := a.writtenLeafFingerprint(d, fingerprint(material.Leaf.Raw)); err != nil || ignored != "" {
				t.Errorf("check deployment used written proof: %q, %v", ignored, err)
			}
			outside := filepath.Join(t.TempDir(), "keep.pem")
			if err := a.atomicTarget(targetFile{path: outside, data: []byte("refused"), mode: 0o600, uid: -1, gid: -1}); err == nil {
				t.Fatal("profile writer accepted a path outside paths")
			}
			if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("profile writer touched a path outside paths")
			}
		})
	}
}
