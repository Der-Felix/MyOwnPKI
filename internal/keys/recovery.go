package keys

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

// RecoveryKey is the second way to unlock the root key: 256 random bits,
// shown once at init. It is printed only on purpose (Reveal); String, %v,
// %#v and JSON all show a placeholder, so it can't end up in a log by accident.
type RecoveryKey [32]byte

// ErrRecoveryKeyFormat means a typed recovery key is malformed or has a typo
// (wrong length, unknown character, check characters don't match).
var ErrRecoveryKeyFormat = errors.New("not a valid recovery key")

const redacted = "[recovery key – redacted]"

func (RecoveryKey) String() string               { return redacted }
func (RecoveryKey) GoString() string             { return redacted }
func (RecoveryKey) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (RecoveryKey) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (k *RecoveryKey) clear()                    { clear(k[:]) }
func (k RecoveryKey) equal(other RecoveryKey) bool {
	return subtle.ConstantTimeCompare(k[:], other[:]) == 1
}

// Crockford Base32: no I, L, O, U. Typed I/L are read as 1, O as 0.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	groupSize  = 6
	groupCount = 9 // 54 characters: 256 key bits + 10 check bits + 4 zero bits
)

// NewRecoveryKey creates a random recovery key. Nothing is stored: init and
// rotation show it, let the user confirm it and only then pass it on.
func NewRecoveryKey(rnd io.Reader) (RecoveryKey, error) {
	var k RecoveryKey
	if rnd == nil {
		rnd = defaultRand
	}
	if _, err := io.ReadFull(rnd, k[:]); err != nil {
		return k, fmt.Errorf("random: %w", err)
	}
	return k, nil
}

func checkBits(k RecoveryKey) uint64 {
	sum := sha256.Sum256(append([]byte("myownpki recovery key check"), k[:]...))
	return uint64(sum[0])<<2 | uint64(sum[1]>>6) // first 10 bits
}

// Reveal returns the key for display or the recovery key file: nine groups
// of six characters, e.g. "K7QM2X-9TRPHD-…".
func (k RecoveryKey) Reveal() string {
	return strings.Join(k.Groups(), "-")
}

// Groups returns the nine groups of six characters.
func (k RecoveryKey) Groups() []string {
	n := new(big.Int).SetBytes(k[:])
	n.Lsh(n, 10).Or(n, new(big.Int).SetUint64(checkBits(k)))
	n.Lsh(n, 4) // 270 bits = 54 characters
	chars := make([]byte, groupSize*groupCount)
	mask := big.NewInt(31)
	for i := len(chars) - 1; i >= 0; i-- {
		chars[i] = crockford[new(big.Int).And(n, mask).Int64()]
		n.Rsh(n, 5)
	}
	groups := make([]string, groupCount)
	for i := range groups {
		groups[i] = string(chars[i*groupSize : (i+1)*groupSize])
	}
	return groups
}

// normalize upper-cases, drops separators and maps I/L to 1 and O to 0.
func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case ' ', '-', '\t', '\r', '\n':
		case 'I', 'L':
			b.WriteByte('1')
		case 'O':
			b.WriteByte('0')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseRecoveryKey reads a typed recovery key. Case, spaces and dashes don't
// matter; a typo is reported as ErrRecoveryKeyFormat before anything is tried
// against the database.
func ParseRecoveryKey(s string) (RecoveryKey, error) {
	var k RecoveryKey
	text := normalize(s)
	if len(text) != groupSize*groupCount {
		return k, fmt.Errorf("%w: expected %d characters, got %d", ErrRecoveryKeyFormat, groupSize*groupCount, len(text))
	}
	n := new(big.Int)
	for _, c := range []byte(text) {
		v := strings.IndexByte(crockford, c)
		if v < 0 {
			return k, fmt.Errorf("%w: character %q is not used in recovery keys", ErrRecoveryKeyFormat, c)
		}
		n.Lsh(n, 5).Or(n, big.NewInt(int64(v)))
	}
	if new(big.Int).And(n, big.NewInt(15)).Sign() != 0 {
		return k, fmt.Errorf("%w: check characters don't match (typo?)", ErrRecoveryKeyFormat)
	}
	n.Rsh(n, 4)
	check := new(big.Int).And(n, big.NewInt(1023)).Uint64()
	n.Rsh(n, 10)
	if n.BitLen() > 256 {
		return k, fmt.Errorf("%w: value too large", ErrRecoveryKeyFormat)
	}
	n.FillBytes(k[:])
	if check != checkBits(k) {
		k.clear()
		return k, fmt.Errorf("%w: check characters don't match (typo?)", ErrRecoveryKeyFormat)
	}
	return k, nil
}

// ConfirmIndexes picks two different group positions (0–8, ascending) the
// user must type again before init or a rotation finishes.
func ConfirmIndexes(rnd io.Reader) ([2]int, error) {
	if rnd == nil {
		rnd = defaultRand
	}
	var b [1]byte
	var picked [2]int
	for i := 0; i < 2; {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return picked, err
		}
		v := int(b[0])
		if v >= 252 { // 252 = 28*9: avoid modulo bias
			continue
		}
		v %= groupCount
		if i == 1 && v == picked[0] {
			continue
		}
		picked[i] = v
		i++
	}
	if picked[0] > picked[1] {
		picked[0], picked[1] = picked[1], picked[0]
	}
	return picked, nil
}

// CheckGroups reports whether every typed group matches the key at its
// position (1st group = index 0). At least one group must be given.
func (k RecoveryKey) CheckGroups(typed map[int]string) bool {
	if len(typed) == 0 {
		return false
	}
	groups := k.Groups()
	ok := 1
	for i, g := range typed {
		if i < 0 || i >= groupCount {
			return false
		}
		ok &= subtle.ConstantTimeCompare([]byte(normalize(g)), []byte(groups[i]))
	}
	return ok == 1
}

// RecoveryOutput is where init shows a new recovery key.
type RecoveryOutput int

// Output targets.
const (
	ShowOnTerminal RecoveryOutput = iota + 1
	WriteToFile
)

// ErrRecoveryKeyNeedsFile: without an interactive terminal (Docker, systemd,
// a pipe) the key would end up in a log, so it may only go to a file.
var ErrRecoveryKeyNeedsFile = errors.New("standard output is not an interactive terminal – " +
	"the recovery key would end up in a log; use --recovery-key-file <path>")

// ChooseRecoveryOutput applies the rule (owner decision 2026-10-13): a file
// if one is given, the terminal only if stdout is interactive, otherwise
// refuse.
func ChooseRecoveryOutput(interactive bool, file string) (RecoveryOutput, error) {
	switch {
	case file != "":
		return WriteToFile, nil
	case interactive:
		return ShowOnTerminal, nil
	}
	return 0, ErrRecoveryKeyNeedsFile
}

// IsTerminal reports whether f is a character device (a terminal). Note: a
// container started with -t has a terminal whose output still reaches the
// container log – the docs tell operators to use --recovery-key-file there.
func IsTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// WriteRecoveryKeyFile writes the key to a new file with mode 0600. An
// existing file is never overwritten.
func WriteRecoveryKeyFile(path string, k RecoveryKey) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("recovery key file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	_, err = fmt.Fprintf(f, "# MyOwnPKI recovery key – unlocks the CA together with a backup.\n"+
		"# Store it offline, apart from the passphrase and the backups, and delete this file from the server.\n"+
		"%s\n", k.Reveal())
	return err
}
