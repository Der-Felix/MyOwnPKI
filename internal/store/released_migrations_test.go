package store

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
)

// pinFile lists every migration file a release shipped (PHASE3 §19.5, step
// 107). scripts/ci/pin-migrations.sh writes it: --print recomputes it from the
// release tags, --add-tree pins the files of a new release in its release
// commit.
const pinFile = "testdata/released-migrations.txt"

// pin is one line of the pin file.
type pin struct {
	Kind    Kind
	Version int
	Name    string
	SHA256  string // as the migration runner stores it: LF line endings
	Release string // the release that shipped the file first
}

func (p pin) file() string { return fmt.Sprintf("%04d_%s.sql", p.Version, p.Name) }

var (
	hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	releaseID = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
)

// parsePins reads the pin file text. Comment lines (#) and empty lines are
// skipped; anything else must have five fields.
func parsePins(text string) ([]pin, error) {
	var pins []pin
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 5 {
			return nil, fmt.Errorf("line %d: want \"kind version name sha256 release\", got %d fields", n, len(f))
		}
		version, err := strconv.Atoi(f[1])
		if err != nil || version < 1 || len(f[1]) != 4 {
			return nil, fmt.Errorf("line %d: version %q is not a four-digit number", n, f[1])
		}
		if !hexSHA256.MatchString(f[3]) {
			return nil, fmt.Errorf("line %d: %q is not a lower-case hex SHA-256", n, f[3])
		}
		if !releaseID.MatchString(f[4]) {
			return nil, fmt.Errorf("line %d: %q is not a release tag vX.Y.Z", n, f[4])
		}
		p := pin{Kind: Kind(f[0]), Version: version, Name: f[2], SHA256: f[3], Release: f[4]}
		key := f[0] + "/" + f[1]
		if seen[key] {
			return nil, fmt.Errorf("line %d: %s %s is pinned twice", n, f[0], f[1])
		}
		seen[key] = true
		pins = append(pins, p)
	}
	return pins, sc.Err()
}

// frozenProblems compares the pins with the migration sets of this build and
// returns one sentence per problem; empty means every released migration is
// unchanged. A file without a pin is allowed (it belongs to the release that
// is being prepared; the release commit pins it), as long as every pinned
// version of its kind comes before it.
func frozenProblems(pins []pin, sets map[Kind][]migrate.Migration) []string {
	var out []string
	pinned := map[Kind]map[int]bool{}
	for _, p := range pins {
		if pinned[p.Kind] == nil {
			pinned[p.Kind] = map[int]bool{}
		}
		pinned[p.Kind][p.Version] = true
		set, ok := sets[p.Kind]
		if !ok {
			out = append(out, fmt.Sprintf("the pin file names the database kind %q, which this build does not have", p.Kind))
			continue
		}
		if p.Version > len(set) {
			out = append(out, fmt.Sprintf("released migration %s/%s (first shipped in %s) is gone: this build has only %d %s migrations. "+
				"A released migration is never deleted; put the change in a new migration", p.Kind, p.file(), p.Release, len(set), p.Kind))
			continue
		}
		m := set[p.Version-1]
		switch {
		case m.Name != p.Name:
			out = append(out, fmt.Sprintf("released migration %s/%s (first shipped in %s) is now called %04d_%s.sql. "+
				"A released migration is never renamed: databases of that release stored its name", p.Kind, p.file(), p.Release, m.Version, m.Name))
		case m.Checksum != p.SHA256:
			out = append(out, fmt.Sprintf("released migration %s/%s (first shipped in %s) was edited: pinned SHA-256 %s…, file %s…. "+
				"Databases that applied the old text would refuse to start (ErrModified). Restore the file with git and put the change "+
				"in a new migration %04d_<name>.sql instead", p.Kind, p.file(), p.Release, p.SHA256[:12], m.Checksum[:12], len(set)+1))
		}
	}
	for kind, set := range sets {
		first := 0 // the first version without a pin
		for _, m := range set {
			if !pinned[kind][m.Version] {
				first = m.Version
				break
			}
		}
		if first == 0 {
			continue
		}
		for _, m := range set {
			if m.Version > first && pinned[kind][m.Version] {
				out = append(out, fmt.Sprintf("%s/%04d_%s.sql is pinned but %04d is not: the pinned files must be the first ones of a kind", kind, m.Version, m.Name, first))
				break
			}
		}
	}
	return out
}

// TestReleasedMigrationsAreFrozen: a migration that a release shipped never
// changes. The runner already refuses an edited file on a database that applied
// the old text; this test refuses it in the repository, before any database is
// involved.
func TestReleasedMigrationsAreFrozen(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(pinFile)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := parsePins(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", pinFile, err)
	}
	sets := map[Kind][]migrate.Migration{}
	for _, k := range Kinds {
		set, merr := Migrations(k)
		if merr != nil {
			t.Fatal(merr)
		}
		sets[k] = set
	}
	if problems := frozenProblems(pins, sets); len(problems) > 0 {
		t.Fatalf("released migrations changed:\n  %s", strings.Join(problems, "\n  "))
	}
	// A new file is fine until the release commit pins it; say how many there are.
	total := 0
	for _, set := range sets {
		total += len(set)
	}
	if fresh := total - len(pins); fresh > 0 {
		t.Logf("%d migration file(s) are not released yet (not pinned): scripts/ci/pin-migrations.sh --add-tree vX.Y.Z pins them in the release commit", fresh)
	}
}

// TestReleasedMigrationPinsAreComplete: deleting lines from the pin file would
// switch the protection off for those files. The files of v0.3.12, the newest
// release when the pins were made, must all be pinned, without a gap.
func TestReleasedMigrationPinsAreComplete(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(pinFile)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := parsePins(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", pinFile, err)
	}
	// A floor, never lowered: the migration counts of v0.3.12 (PHASE3 §19.1).
	floor := map[Kind]int{KindSystem: 15, KindPKI: 21, KindAudit: 2}
	pinned := map[Kind]map[int]bool{}
	for _, p := range pins {
		if pinned[p.Kind] == nil {
			pinned[p.Kind] = map[int]bool{}
		}
		pinned[p.Kind][p.Version] = true
	}
	for kind, n := range floor {
		for v := 1; v <= n; v++ {
			if !pinned[kind][v] {
				t.Errorf("%s: migration %04d of v0.3.12 has no pin in %s", kind, v, pinFile)
			}
		}
	}
}

// migrationFixture builds a migration set of the given names; the checksum of
// file n is "sha<n>" padded to 64 hex digits so a pin can name it.
func migrationFixture(names ...string) []migrate.Migration {
	var set []migrate.Migration
	for i, n := range names {
		set = append(set, migrate.Migration{Version: i + 1, Name: n, SQL: "SELECT 1;", Checksum: fixtureSum(i + 1)})
	}
	return set
}

func fixtureSum(n int) string { return fmt.Sprintf("%064x", n) }

func fixturePin(kind Kind, version int, name string) pin {
	return pin{Kind: kind, Version: version, Name: name, SHA256: fixtureSum(version), Release: "v0.1.0"}
}

func TestFrozenProblems(t *testing.T) {
	t.Parallel()
	sets := func() map[Kind][]migrate.Migration {
		return map[Kind][]migrate.Migration{KindPKI: migrationFixture("init", "outbox", "keys")}
	}
	allPinned := []pin{fixturePin(KindPKI, 1, "init"), fixturePin(KindPKI, 2, "outbox"), fixturePin(KindPKI, 3, "keys")}

	tests := []struct {
		name string
		pins []pin
		mod  func(map[Kind][]migrate.Migration)
		want string // a piece of the single expected problem; "" = none
	}{
		{name: "everything pinned and unchanged", pins: allPinned},
		{name: "a new file after the pins is allowed", pins: allPinned[:2]},
		{name: "no pins at all is allowed", pins: nil},
		{
			name: "an edited file",
			pins: allPinned,
			mod:  func(s map[Kind][]migrate.Migration) { s[KindPKI][1].Checksum = fixtureSum(99) },
			want: "pki/0002_outbox.sql (first shipped in v0.1.0) was edited",
		},
		{
			name: "a renamed file",
			pins: allPinned,
			mod:  func(s map[Kind][]migrate.Migration) { s[KindPKI][0].Name = "start" },
			want: "pki/0001_init.sql (first shipped in v0.1.0) is now called 0001_start.sql",
		},
		{
			name: "a deleted last file",
			pins: allPinned,
			mod:  func(s map[Kind][]migrate.Migration) { s[KindPKI] = s[KindPKI][:2] },
			want: "pki/0003_keys.sql (first shipped in v0.1.0) is gone",
		},
		{
			name: "a pinned file after an unpinned one",
			pins: []pin{allPinned[0], allPinned[2]},
			want: "is pinned but 0002 is not",
		},
		{
			name: "a kind that does not exist",
			pins: append([]pin{fixturePin("metrics", 1, "init")}, allPinned...),
			want: `database kind "metrics"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := sets()
			if tt.mod != nil {
				tt.mod(s)
			}
			got := frozenProblems(tt.pins, s)
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected problems: %v", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tt.want) {
				t.Fatalf("problems = %q, want one containing %q", got, tt.want)
			}
		})
	}
}

func TestParsePins(t *testing.T) {
	t.Parallel()
	good := "# comment\n\n" +
		"pki 0001 init " + strings.Repeat("a", 64) + " v0.1.0\n" +
		"system 0002 outbox " + strings.Repeat("b", 64) + " v0.2.0\n"
	pins, err := parsePins(good)
	if err != nil || len(pins) != 2 || pins[1].Kind != KindSystem || pins[1].Version != 2 || pins[1].Release != "v0.2.0" {
		t.Fatalf("parsePins(good) = %+v, %v", pins, err)
	}
	for name, text := range map[string]string{
		"too few fields": "pki 0001 init v0.1.0\n",
		"version":        "pki 1 init " + strings.Repeat("a", 64) + " v0.1.0\n",
		"upper case sum": "pki 0001 init " + strings.Repeat("A", 64) + " v0.1.0\n",
		"short sum":      "pki 0001 init abc v0.1.0\n",
		"release":        "pki 0001 init " + strings.Repeat("a", 64) + " 0.1.0\n",
		"duplicate":      "pki 0001 init " + strings.Repeat("a", 64) + " v0.1.0\npki 0001 other " + strings.Repeat("b", 64) + " v0.2.0\n",
	} {
		if _, err := parsePins(text); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
