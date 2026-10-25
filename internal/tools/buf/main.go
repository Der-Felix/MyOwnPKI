// Command buf runs the pinned buf CLI (docs/PHASE3.md §4) for `task generate`:
// it downloads the release binary for this system once into .tools/, checks
// its SHA-256 against the pins below, and runs it in the repository root.
//
//	go run ./internal/tools/buf lint
//	go run ./internal/tools/buf generate
//
// buf is a development tool only: it is never in go.mod and never in a
// binary. New version: change bufVersion and the sums (from the release's
// sha256.txt), and keep the two-week rule.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const bufVersion = "1.73.0" // released 2026-09-11

// assets: the release file and its SHA-256 per GOOS/GOARCH.
var assets = map[string]struct{ file, sum string }{
	"linux/amd64":   {"buf-Linux-x86_64", "8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1"},
	"linux/arm64":   {"buf-Linux-aarch64", "902b75267db7f4391e99b7fa0756050e5354234cc0437ef50eee9c788950c7a3"},
	"darwin/amd64":  {"buf-Darwin-x86_64", "ff78d0ebf34180ebfa81d370275851ec630fcb088bf33e213fd723d0fd7444a6"},
	"darwin/arm64":  {"buf-Darwin-arm64", "6e6df0fef4522e4e43dfe7c341873c3f2c29ceb45a9dfa5e0bad5580b8b2022f"},
	"windows/amd64": {"buf-Windows-x86_64.exe", "13542f2892c4f774150ddb525266d6421d457b3e741297056b64427853526e36"},
	"windows/arm64": {"buf-Windows-arm64.exe", "2250d5cba96a64f6ebc78d67221feab113622a24fbaf2909d43c87f8586d1bed"},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "buf:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	bin, err := ensure(root)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(context.Background(), bin, args...) //nolint:gosec // the pinned, checksum-checked binary
	cmd.Dir = root
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// moduleRoot walks up from the working directory to go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod above the working directory")
		}
		dir = parent
	}
}

// ensure returns the path of the checked binary, downloading it if needed.
func ensure(root string) (string, error) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	a, ok := assets[platform]
	if !ok {
		return "", fmt.Errorf("no pinned buf release for %s – generate on Linux, macOS or Windows", platform)
	}
	dir := filepath.Join(root, ".tools", "buf-"+bufVersion)
	bin := filepath.Join(dir, "buf")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if sum, err := fileSum(bin); err == nil && sum == a.sum {
		return bin, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	url := "https://github.com/bufbuild/buf/releases/download/v" + bufVersion + "/" + a.file
	fmt.Fprintln(os.Stderr, "buf: downloading", url)
	tmp, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url) //nolint:noctx // a development tool with a timeout
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_ = tmp.Close()
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 256<<20)); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.sum {
		return "", fmt.Errorf("%s: SHA-256 %s, pinned %s – not used", a.file, got, a.sum)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil { //nolint:gosec // an executable
		return "", err
	}
	if err := os.Rename(tmp.Name(), bin); err != nil {
		return "", err
	}
	return bin, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
