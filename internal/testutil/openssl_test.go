package testutil

import "testing"

func TestIsOpenSSL3(t *testing.T) {
	t.Parallel()
	for version, want := range map[string]bool{
		"OpenSSL 3.0.13 30 Jan 2024":     true,
		"OpenSSL 3.5.7 30 Sep 2025":      true,
		"OpenSSL 4.0.0 1 Apr 2026":       true,
		"OpenSSL 1.1.1w  11 Sep 2023":    false,
		"LibreSSL 3.3.6":                 false,
		"OpenSSL":                        false,
		"OpenSSL x.y":                    false,
		"something else printed OpenSSL": false,
	} {
		if got := isOpenSSL3(version); got != want {
			t.Errorf("%q: %v, want %v", version, got, want)
		}
	}
}
