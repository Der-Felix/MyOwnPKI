package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestParseIndex(t *testing.T) {
	t.Parallel()
	data := strings.Join([]string{
		"V\t270101000000Z\t\t1A2B\tunknown\t/CN=valid",
		"R\t270101000000Z\t261018120000Z,superseded\t00FF\tunknown\t/CN=superseded",
		"R\t270101000000Z\t261018120000Z\t0A\tunknown\t/CN=no reason",
		"R\t270101000000Z\t261018120000Z,keyTime,261017080000Z\t0B\tunknown\t/CN=key",
		"R\t270101000000Z\t261018120000Z,CAkeyTime,261017080000Z\t0C\tunknown\t/CN=ca key",
		"R\t270101000000Z\t261018120000Z,holdInstruction,1.2.840.10040.2.2\t0D\tunknown\t/CN=hold",
		"E\t20510101000000Z\t\t0E\tunknown\t/CN=generalized",
		"V\t500101000000Z\t\t0F\tunknown\t/CN=1950",
		"",
		"X\t270101000000Z\t\t10\tunknown\t/CN=bad status",
		"V\t270101000000Z\t\tnothex\tunknown\t/CN=bad serial",
		"R\t270101000000Z\t261018120000Z,certificateHold,extra\t11\tunknown\t/CN=bad extra",
		"V\t27-01-01\t\t12\tunknown\t/CN=bad date",
		"V\t270101000000Z\t\t13\tunknown",
	}, "\n")
	entries, problems := parseIndex([]byte(data))
	if len(entries) != 8 || len(problems) != 5 {
		t.Fatalf("%d entries, problems %v", len(entries), problems)
	}
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	compromised := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	for i, want := range []struct {
		serial, reason string
		revoked        bool
		invalidity     *time.Time
	}{
		{"1A2B", "", false, nil},
		{"FF", "superseded", true, nil},
		{"0A", "", true, nil},
		{"0B", "keyCompromise", true, &compromised},
		{"0C", "CACompromise", true, &compromised},
		{"0D", "certificateHold", true, nil},
		{"0E", "", false, nil},
		{"0F", "", false, nil},
	} {
		e := entries[i]
		if e.Serial != want.serial || (e.Revoked != nil) != want.revoked {
			t.Errorf("entry %d: %+v", i, e)
			continue
		}
		if e.Revoked == nil {
			continue
		}
		r := e.Revoked
		if !r.Time.Equal(at) || r.Reason != want.reason || (r.Invalidity == nil) != (want.invalidity == nil) ||
			(r.Invalidity != nil && !r.Invalidity.Equal(*want.invalidity)) {
			t.Errorf("entry %d revocation: %+v", i, r)
		}
	}
	if entries[1].File != "00FF" {
		t.Errorf("file name %q: newcerts/ uses the serial as written", entries[1].File)
	}
	if y := entries[6].Expiry.Year(); y != 2051 {
		t.Errorf("GeneralizedTime year %d", y)
	}
	if y := entries[7].Expiry.Year(); y != 1950 {
		t.Errorf("UTCTime 50 is 1950 (RFC 5280), got %d", y)
	}
}

func TestParseKV(t *testing.T) {
	t.Parallel()
	kv, notes := parseKV([]byte("# comment\r\nA=\"quoted # not a comment\"\nB='single'\n  C = bare value # comment\nlower=x\n$(rm -rf /)\nD=\n"))
	want := map[string]string{"A": "quoted # not a comment", "B": "single", "C": "bare value", "D": ""}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("%s = %q, want %q", k, kv[k], v)
		}
	}
	if len(kv) != 4 || len(notes) != 2 {
		t.Errorf("kv %v, notes %v", kv, notes)
	}
}

// encryptPKCS8 writes what `openssl genpkey -aes-256-cbc` writes: PBES2 with
// PBKDF2-HMAC-SHA256 and AES-256-CBC.
func encryptPKCS8(t *testing.T, der []byte, pass string, iterations int) []byte {
	t.Helper()
	salt, iv := make([]byte, 16), make([]byte, 16)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(iv)
	key, err := pbkdf2.Key(sha256.New, pass, salt, iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	plain := append(append([]byte{}, der...), make([]byte, pad)...)
	for i := len(der); i < len(plain); i++ {
		plain[i] = byte(pad)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, plain)
	mustMarshal := func(v any) []byte {
		b, merr := asn1.Marshal(v)
		if merr != nil {
			t.Fatal(merr)
		}
		return b
	}
	kdf := mustMarshal(pbkdf2Params{Salt: salt, Iterations: iterations, PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}})
	params := mustMarshal(pbes2Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Scheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: mustMarshal(iv)}},
	})
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: mustMarshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}}, Data: ct,
	})})
}

func TestEncryptedKeys(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	enc := encryptPKCS8(t, der, "right", 2048)

	got, encrypted, err := parsePrivateKey(enc, []byte("right"))
	if err != nil || !encrypted || !key.Equal(got) {
		t.Fatalf("right passphrase: %v %v", encrypted, err)
	}
	if _, _, err = parsePrivateKey(enc, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, _, err = parsePrivateKey(enc, nil); !errors.Is(err, errNoPassphrase) {
		t.Errorf("no passphrase: %v", err)
	}
	if _, _, err = parsePrivateKey(encryptPKCS8(t, der, "right", maxIterations+1), []byte("right")); err == nil || !strings.Contains(err.Error(), "iteration") {
		t.Errorf("too many iterations: %v", err)
	}
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if got, encrypted, err = parsePrivateKey(plain, nil); err != nil || encrypted || !key.Equal(got) {
		t.Errorf("plain key: %v %v", encrypted, err)
	}
	old := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"}, Bytes: []byte{1}})
	if _, _, err = parsePrivateKey(old, []byte("x")); err == nil || !strings.Contains(err.Error(), "openssl pkey") {
		t.Errorf("old PEM encryption: %v", err)
	}
}

func TestReadRefusesAnotherDirectory(t *testing.T) {
	t.Parallel()
	if _, err := Read(fstest.MapFS{"pki/root/certs/ca.crt": {Data: []byte("x")}}, Passphrases{}); err == nil || !strings.Contains(err.Error(), "--dir") {
		t.Errorf("one level too high: %v", err)
	}
	p, err := Read(fstest.MapFS{"root/certs/ca.crt": {Data: []byte("not a certificate")}}, Passphrases{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Problems) < 2 { // the certificate and index.txt
		t.Errorf("problems %v", p.Problems)
	}
}

func TestEnvName(t *testing.T) {
	t.Parallel()
	if got := EnvName("server-ca.v2@lab"); got != "SERVER_CA_V2_LAB" {
		t.Errorf("EnvName %q", got)
	}
}
