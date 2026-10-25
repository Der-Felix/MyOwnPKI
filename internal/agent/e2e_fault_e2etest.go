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
		if err := a.atomicTarget(targetFile{path: deploymentPaths(deployment).Key, data: data, mode: 0o600, uid: -1, gid: -1}); err != nil {
			return err
		}
	}
	return os.Remove(marker)
}
