package settingsver

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The two guard tests make "a secret cannot enter a snapshot" structural
// (docs/PHASE3.md section 16.2, decision 10). A field or column that is added
// later fails them until someone decides: is it a setting (put it in the
// snapshot and the allow-list) or not (say why on the "not a setting" list).

// domainFields maps every leaf of DomainSnapshot (by JSON path) to the
// column of table domains it carries. It is the reviewed allow-list.
var domainFields = map[string]string{
	"name":               "name",
	"ca_id":              "ca_id",
	"include_subdomains": "include_subdomains",
	"wildcards":          "wildcards",
	"challenge_types":    "challenge_types",
	"approval":           "approval",
	"preset":             "preset",
	"validity_days":      "validity_days",
	"address_policy":     "address_policy",
	"ip_ranges":          "ip_ranges",
}

// domainNotSettings: columns of domains that are deliberately not versioned.
var domainNotSettings = map[string]string{
	"id":         "identity: it is the object ID of the history, not a setting",
	"created_at": "a timestamp, not a setting",
	"updated_at": "a timestamp, not a setting (the version's created_at says when)",
}

// tenantFields maps every leaf of TenantSnapshot to its column of tenants.
var tenantFields = map[string]string{
	"allow_server_keygen":      "allow_server_keygen",
	"organization":             "subject_o",
	"organizational_unit":      "subject_ou",
	"locality":                 "subject_l",
	"state":                    "subject_st",
	"country":                  "subject_c",
	"acme.orders_per_account":  "acme_orders_per_hour",
	"acme.failed_per_name":     "acme_failed_per_name",
	"acme.accounts_per_ip":     "acme_accounts_per_ip",
	"trust_page":               "trust_page",
	"agent_enrollment":         "agent_enrollment",
	"step_up_minutes":          "step_up_minutes",
	"agent_predecessor.choice": "agent_predecessor_choice",
	"agent_predecessor.days":   "agent_predecessor_days",
	"other_predecessor.choice": "other_predecessor_choice",
	"other_predecessor.days":   "other_predecessor_days",
}

// tenantNotSettings: columns of tenants that are deliberately not versioned.
var tenantNotSettings = map[string]string{
	"id":         "identity: it is the object ID of the history, not a setting",
	"name":       "the display name is set when the tenant is created and has no writer",
	"created_at": "a timestamp, not a setting",
}

// leaf is one scalar of a snapshot type.
type leaf struct {
	path string
	kind reflect.Kind
}

// snapshotLeaves walks a snapshot type and reports its leaves (JSON paths)
// and every property that makes the type not closed: a field without a JSON
// name, or of a kind that could carry anything (map, interface, pointer,
// raw bytes, a float, a struct from elsewhere).
func snapshotLeaves(t reflect.Type, prefix string) (leaves []leaf, problems []string) {
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "" || name == "-" {
			problems = append(problems, fmt.Sprintf("%s.%s: needs an exported name and a json name", t.Name(), f.Name))
			continue
		}
		path := prefix + name
		switch ft := f.Type; {
		case ft.Kind() == reflect.Bool, ft.Kind() == reflect.String, ft.Kind() == reflect.Int:
			leaves = append(leaves, leaf{path, ft.Kind()})
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String:
			leaves = append(leaves, leaf{path, reflect.Slice})
		case ft.Kind() == reflect.Struct && ft.PkgPath() == t.PkgPath():
			l, p := snapshotLeaves(ft, path+".")
			leaves, problems = append(leaves, l...), append(problems, p...)
		default:
			problems = append(problems, fmt.Sprintf("%s: type %s is not allowed in a snapshot (bool, string, int, []string and structs of this package only)", path, ft))
		}
	}
	return leaves, problems
}

// secretName reports whether a snapshot path names a secret: any word of
// the path that contains password, secret, token, credential or passphrase,
// or is exactly key or keys ("allow_server_keygen" is a switch, not a key).
func secretName(path string) bool {
	for _, word := range strings.FieldsFunc(strings.ToLower(path), func(r rune) bool { return r == '.' || r == '_' || r == '-' }) {
		if word == "key" || word == "keys" {
			return true
		}
		for _, bad := range []string{"password", "secret", "token", "credential", "passphrase"} {
			if strings.Contains(word, bad) {
				return true
			}
		}
	}
	return false
}

// unclassified lists what is wrong between a snapshot's leaves and its
// allow-list: a leaf nobody reviewed, and an entry without a leaf.
func unclassified(leaves []leaf, allowed map[string]string) []string {
	var out []string
	have := map[string]bool{}
	for _, l := range leaves {
		have[l.path] = true
		if _, ok := allowed[l.path]; !ok {
			out = append(out, fmt.Sprintf("snapshot field %q is not on the reviewed allow-list", l.path))
		}
		if secretName(l.path) {
			out = append(out, fmt.Sprintf("snapshot field %q is named like a secret", l.path))
		}
	}
	for path := range allowed {
		if !have[path] {
			out = append(out, fmt.Sprintf("allow-list entry %q has no snapshot field", path))
		}
	}
	slices.Sort(out)
	return out
}

func TestSnapshotsHaveNoSecrets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		typ     reflect.Type
		allowed map[string]string
	}{
		{reflect.TypeFor[DomainSnapshot](), domainFields},
		{reflect.TypeFor[TenantSnapshot](), tenantFields},
	} {
		leaves, problems := snapshotLeaves(tc.typ, "")
		problems = append(problems, unclassified(leaves, tc.allowed)...)
		for _, p := range problems {
			t.Errorf("%s: %s", tc.typ.Name(), p)
		}
		// Fields() lists exactly the snapshot's leaves, so a field cannot be
		// stored and left out of the diff.
		snap, ok := reflect.New(tc.typ).Elem().Interface().(Snapshot)
		if !ok {
			t.Fatalf("%s is not a Snapshot", tc.typ.Name())
		}
		var keys []string
		for _, f := range snap.Fields() {
			keys = append(keys, f.Key)
		}
		var want []string
		for _, l := range leaves {
			want = append(want, l.path)
		}
		slices.Sort(keys)
		slices.Sort(want)
		if !slices.Equal(keys, want) {
			t.Errorf("%s: Fields() keys %v differ from the struct's fields %v", tc.typ.Name(), keys, want)
		}
	}
}

// The guard itself: it must refuse what it is there to refuse.
func TestSnapshotGuardCatchesNewAndRiskyFields(t *testing.T) {
	t.Parallel()
	type inner struct {
		Days int `json:"days"`
	}
	type bad struct {
		Name      string         `json:"name"`
		Added     string         `json:"added_later"`
		APIKey    string         `json:"api_key"`
		Free      map[string]any `json:"free"`
		Ptr       *string        `json:"ptr"`
		Raw       []byte         `json:"raw"`
		NoTag     string
		Inner     inner  `json:"inner"`
		TokenHash string `json:"token_hash"`
	}
	leaves, problems := snapshotLeaves(reflect.TypeFor[bad](), "")
	problems = append(problems, unclassified(leaves, map[string]string{"name": "name", "inner.days": "days"})...)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		`"added_later" is not on the reviewed allow-list`,
		`"api_key" is named like a secret`,
		`"token_hash" is named like a secret`,
		"free: type map[string]interface {} is not allowed",
		"ptr: type *string is not allowed",
		"raw: type []uint8 is not allowed",
		"bad.NoTag: needs an exported name",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the guard did not report %q; it reported:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, `"name"`) || strings.Contains(joined, `"inner.days"`) {
		t.Errorf("the guard reported fields that are classified:\n%s", joined)
	}
	if _, p := snapshotLeaves(reflect.TypeFor[DomainSnapshot](), ""); len(p) != 0 {
		t.Errorf("DomainSnapshot has open types: %v", p)
	}
	for _, name := range []string{"password", "Password", "totp_secret", "api_token", "client-secret", "credentials", "key", "private.keys", "passphrase_hint"} {
		if !secretName(name) {
			t.Errorf("%q should be taken for a secret name", name)
		}
	}
	for _, name := range []string{"allow_server_keygen", "name", "ca_id", "acme.orders_per_account", "keyboard_layout"} {
		if secretName(name) {
			t.Errorf("%q should not be taken for a secret name", name)
		}
	}
}

// columnsOf lists the columns of a table with PRAGMA table_info and checks
// that it lists all of them: STRICT tables (the plan's open question) behave
// like any other table here, and table_list's column count agrees.
func columnsOf(ctx context.Context, t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err = rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	var ncol, strict int
	if err = db.QueryRowContext(ctx, `SELECT ncol, strict FROM pragma_table_list(?) WHERE schema = 'main'`, table).Scan(&ncol, &strict); err != nil {
		t.Fatal(err)
	}
	if strict != 1 {
		t.Errorf("table %s is not STRICT any more: check that this test still lists every column", table)
	}
	if len(cols) != ncol || len(cols) == 0 {
		t.Fatalf("PRAGMA table_info(%s) lists %d columns, table_list says %d", table, len(cols), ncol)
	}
	return cols
}

func TestEveryColumnIsClassified(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	pki, sys := openDBs(t)
	for _, tc := range []struct {
		table      string
		db         *sql.DB
		versioned  map[string]string // snapshot path -> column
		notSetting map[string]string // column -> why
	}{
		{"domains", pki.Read, domainFields, domainNotSettings},
		{"tenants", sys.Read, tenantFields, tenantNotSettings},
	} {
		inSnapshot := map[string]bool{}
		for _, col := range tc.versioned {
			inSnapshot[col] = true
		}
		cols := columnsOf(ctx, t, tc.db, tc.table)
		for _, col := range cols {
			switch {
			case inSnapshot[col] && tc.notSetting[col] != "":
				t.Errorf("%s.%s is both versioned and on the not-a-setting list", tc.table, col)
			case !inSnapshot[col] && tc.notSetting[col] == "":
				t.Errorf("%s.%s is new: put it in the snapshot (and the allow-list), or on the not-a-setting list with the reason", tc.table, col)
			}
		}
		for col := range inSnapshot {
			if !slices.Contains(cols, col) {
				t.Errorf("the snapshot names column %s.%s, which does not exist", tc.table, col)
			}
		}
		for col := range tc.notSetting {
			if !slices.Contains(cols, col) {
				t.Errorf("the not-a-setting list names column %s.%s, which does not exist", tc.table, col)
			}
		}
		// A column on the secret-sounding list would need a very good reason.
		for _, col := range cols {
			if secretName(col) {
				t.Errorf("%s.%s is named like a secret", tc.table, col)
			}
		}
	}
}
