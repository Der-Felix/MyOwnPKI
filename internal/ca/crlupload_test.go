package ca

import (
	"strings"
	"testing"
)

// Found by fuzzing: x509.ParseRevocationList ignores what follows the CRL, and uploadCRL stored and served the
// DER as it came – so the signature covered only the first part of what the public listener handed out.
func TestUploadedCRLHasNothingAfterIt(t *testing.T) {
	t.Parallel()
	crl := testCRL(t)
	if _, err := parseUploadedCRL(crl); err != nil {
		t.Fatalf("the plain CRL: %v", err)
	}
	for name, tail := range map[string]string{"a byte": "x", "a newline": "\n", "a second CRL": string(crl)} {
		_, err := parseUploadedCRL(append(append([]byte{}, crl...), tail...))
		if err == nil || !strings.Contains(err.Error(), "there is data after the CRL") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
