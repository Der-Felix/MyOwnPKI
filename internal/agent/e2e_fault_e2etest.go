//go:build e2etest

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

const stagedFaultMarker = "e2etest-corrupt-staged-key"

func (a *Agent) injectStagedFault(group reloadGroup) error {
	marker := a.st.path(stagedFaultMarker)
	if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, deployment := range group.deployments {
		files := deploymentPaths(deployment)
		damaged := data
		if files.Combined != "" {
			// The one-file target: keep the staged certificates and swap the key.
			staged, _, err := a.readTarget(files.Combined)
			if err != nil {
				return err
			}
			damaged = swapKeyBlock(staged, data)
		}
		if err := a.atomicTarget(targetFile{path: files.KeyPath(), data: damaged, mode: 0o600, uid: -1, gid: -1}); err != nil {
			return err
		}
	}
	return os.Remove(marker)
}

// swapKeyBlock returns the PEM blocks of file without its private key, followed by key.
func swapKeyBlock(file, key []byte) []byte {
	var out []byte
	for rest := file; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			out = append(out, pem.EncodeToMemory(block)...)
		}
	}
	return append(out, key...)
}
