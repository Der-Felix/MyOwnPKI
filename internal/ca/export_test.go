package ca

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/pkcs12"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

const exportPassword = "correct horse battery"

// exportFixture is a chain root > issuing with one certificate whose key the
// server generated (cn nas.homelab.lan) and one that came with a CSR.
type exportFixture struct {
	v         *env
	root      *fixtureCA
	issuing   *fixtureCA
	withKey   *Issued
	withCSR   *Issued
	operator  keys.Who // may download keys of "issuing", fresh second factor
	pkcs8DER  []byte   // the key, as the engine stored it
	leafCert  *x509.Certificate
	chainCert []*x509.Certificate // the issuing CA, no root
}

func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{})
	f := &exportFixture{v: v, root: root, issuing: issuing}
	f.withKey = v.issue(t, Request{CA: "issuing", Preset: "server", Subject: Subject{CommonName: "nas.homelab.lan"}, DNSNames: []string{"nas.homelab.lan"}})
	f.withCSR = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"csr.homelab.lan"},
		CSR: makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{DNSNames: []string{"csr.homelab.lan"}})})
	f.operator = signedIn("op", v.clk.Now(), authz.Binding{CA: "issuing", Role: authz.Operator})
	f.leafCert = parse(t, f.withKey.CertDER)
	f.chainCert = []*x509.Certificate{issuing.cert}
	// What the engine stored, decrypted the way the engine does it.
	stored, err := keys.LoadKey(t.Context(), v.pki, f.withKey.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err = unsealed.WithSigner(stored.ID, stored.Purpose, stored.Algorithm, stored.Envelope, func(s crypto.Signer) error {
		f.pkcs8DER, err = x509.MarshalPKCS8PrivateKey(s)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *exportFixture) export(t *testing.T, mod func(*ExportRequest)) (*Export, error) {
	t.Helper()
	req := ExportRequest{ID: f.withKey.ID, Format: ExportPKCS8PEM, Password: exportPassword, Who: f.operator}
	if mod != nil {
		mod(&req)
	}
	return f.v.e.Export(t.Context(), req)
}

// TestExportFormats: each format holds exactly the certificate, the chain
// below the root and the key of the certificate – nothing else.
func TestExportFormats(t *testing.T) {
	t.Parallel()
	f := newExportFixture(t)
	t.Run("pkcs8-pem", func(t *testing.T) {
		t.Parallel()
		out, err := f.export(t, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.ContentType != "application/x-pem-file" || out.FileName != "nas.homelab.lan.key.pem" || out.KeyDeleted {
			t.Errorf("%q %q deleted %v", out.ContentType, out.FileName, out.KeyDeleted)
		}
		block, rest := pem.Decode(out.Data)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, f.pkcs8DER) {
			t.Errorf("not exactly the PKCS#8 key: %v", block)
		}
	})
	t.Run("combined-pem", func(t *testing.T) {
		t.Parallel()
		out, err := f.export(t, func(r *ExportRequest) { r.Format = ExportCombinedPEM })
		if err != nil {
			t.Fatal(err)
		}
		if out.ContentType != "application/x-pem-file" || out.FileName != "nas.homelab.lan.combined.pem" {
			t.Errorf("%q %q", out.ContentType, out.FileName)
		}
		var types []string
		var ders [][]byte
		for rest := out.Data; ; {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			types = append(types, b.Type)
			ders = append(ders, b.Bytes)
		}
		// HAProxy order: leaf, the chain without the root, key last.
		if strings.Join(types, ",") != "CERTIFICATE,CERTIFICATE,PRIVATE KEY" ||
			!bytes.Equal(ders[0], f.withKey.CertDER) || !bytes.Equal(ders[1], f.issuing.cert.Raw) || !bytes.Equal(ders[2], f.pkcs8DER) {
			t.Errorf("blocks %v", types)
		}
		if bytes.Contains(out.Data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.cert.Raw})) {
			t.Error("the root is in the combined file")
		}
	})
	t.Run("pkcs12", func(t *testing.T) {
		t.Parallel()
		out, err := f.export(t, func(r *ExportRequest) { r.Format = ExportPKCS12 })
		if err != nil {
			t.Fatal(err)
		}
		if out.ContentType != "application/x-pkcs12" || out.FileName != "nas.homelab.lan.p12" {
			t.Errorf("%q %q", out.ContentType, out.FileName)
		}
		file := filepath.Join(t.TempDir(), "export.p12")
		if err = os.WriteFile(file, out.Data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := testutil.OpenSSLPKCS12(t, file, exportPassword, false)
		if err != nil {
			t.Fatal(err)
		}
		if problems := got.Problems(f.leafCert, f.chainCert, "nas.homelab.lan"); len(problems) != 0 {
			t.Errorf("OpenSSL read a different file than what was ordered: %v", problems)
		}
		if _, err = testutil.OpenSSLPKCS12(t, file, "not the password", false); err == nil {
			t.Error("OpenSSL opened the file with a wrong password")
		}
	})
}

// TestExportRefusals: what is refused, with the reason – and no key leaves.
func TestExportRefusals(t *testing.T) {
	t.Parallel()
	f := newExportFixture(t)
	short11 := strings.Repeat("a", pkcs12.MinPassword-1)
	// Counted in characters, not bytes: 11 two-byte characters are 22 bytes.
	short11Umlauts := strings.Repeat("ä", pkcs12.MinPassword-1)
	tests := []struct {
		name string
		mod  func(*ExportRequest)
		want string
	}{
		{"unknown format", func(r *ExportRequest) { r.Format = "jks" }, `unknown export format "jks" (allowed: pkcs12, pkcs8-pem, combined-pem)`},
		{"no format", func(r *ExportRequest) { r.Format = "" }, `unknown export format ""`},
		{"PKCS#12 without a password", func(r *ExportRequest) { r.Format = ExportPKCS12; r.Password = "" }, "the PKCS#12 password needs at least 12 characters"},
		{"PKCS#12 with 11 characters", func(r *ExportRequest) { r.Format = ExportPKCS12; r.Password = short11 }, "needs at least 12 characters"},
		{"PKCS#12 with 11 two-byte characters", func(r *ExportRequest) { r.Format = ExportPKCS12; r.Password = short11Umlauts }, "needs at least 12 characters"},
	}
	for _, tt := range tests {
		_, err := f.export(t, tt.mod)
		if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
	// The password check doesn't apply to the PEM formats; 12 characters, even two-byte ones, are enough.
	if _, err := f.export(t, func(r *ExportRequest) { r.Password = "" }); err != nil {
		t.Errorf("PEM without a password: %v", err)
	}
	if _, err := f.export(t, func(r *ExportRequest) { r.Format = ExportPKCS12; r.Password = strings.Repeat("ä", pkcs12.MinPassword) }); err != nil {
		t.Errorf("PKCS#12 with 12 two-byte characters: %v", err)
	}

	if _, err := f.export(t, func(r *ExportRequest) { r.ID = f.withCSR.ID }); !errors.Is(err, ErrNoStoredKey) {
		t.Errorf("a certificate issued from a CSR: %v", err)
	}
	if _, err := f.export(t, func(r *ExportRequest) { r.ID = "crt_nope" }); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown certificate: %v", err)
	}
	f.v.e.Keys = keys.New(nil, nil, f.v.clk)
	if _, err := f.export(t, nil); !errors.Is(err, keys.ErrSealed) {
		t.Errorf("a sealed server: %v", err)
	}
}

// TestExportNeedsTheStepUp: only whoever may download keys of this CA, with a
// fresh second factor – and every refusal is audited as key.download denied.
func TestExportNeedsTheStepUp(t *testing.T) {
	t.Parallel()
	f := newExportFixture(t)
	now := f.v.clk.Now()
	var noStepUp time.Time
	token := signedIn("tok", now, authz.Binding{CA: "issuing", Role: authz.Operator})
	token.Principal.ViaToken = true
	tests := []struct {
		name string
		who  keys.Who
		want error
	}{
		{"viewer", signedIn("view", now, authz.Binding{Role: authz.Viewer}), authz.ErrDenied},
		{"operator without a second factor", signedIn("op", noStepUp, authz.Binding{CA: "issuing", Role: authz.Operator}), authz.ErrStepUpRequired},
		{"operator whose step-up is six minutes old", signedIn("op", now.Add(-6*time.Minute), authz.Binding{CA: "issuing", Role: authz.Operator}), authz.ErrStepUpRequired},
		{"an API token", token, authz.ErrDenied},
		{"nobody", keys.Who{Actor: tester.Actor}, ErrNotFound},
	}
	for _, tt := range tests {
		out, err := f.export(t, func(r *ExportRequest) { r.Who = tt.who })
		if out != nil || !errors.Is(err, tt.want) {
			t.Errorf("%s: %v %v", tt.name, out, err)
		}
	}
	// Another CA's operator doesn't even see the certificate.
	other := signedIn("other", now, authz.Binding{CA: "root", Role: authz.Operator})
	if out, err := f.export(t, func(r *ExportRequest) { r.Who = other }); out != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("operator of another CA: %v %v", out, err)
	}

	denied := 0
	for _, row := range f.v.auditRows(t) {
		if row.action == ActionKeyDownload && row.result == "denied" && row.target == f.withKey.ID {
			denied++
		}
		if row.action == ActionKeyDownload && row.result == "success" {
			t.Errorf("a refused download is audited as a success: %+v", row)
		}
	}
	if denied < 3 {
		t.Errorf("%d denied key.download entries, want at least 3", denied)
	}
	if out, err := f.export(t, nil); err != nil || out == nil {
		t.Errorf("operator with a fresh second factor: %v", err)
	}
}

// TestExportNeverWritesTheKey: the key is handed to the caller and nowhere
// else – not into a database row, not into the audit log, not into an error.
func TestExportNeverWritesTheKey(t *testing.T) {
	t.Parallel()
	f := newExportFixture(t)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: f.pkcs8DER})
	for _, format := range ExportFormats {
		if _, err := f.export(t, func(r *ExportRequest) { r.Format = format }); err != nil {
			t.Fatal(format, err)
		}
	}
	rows := f.v.auditRows(t)
	// The search itself works: it finds the certificate, which is stored.
	if tbl, _ := dbContains(t, f.v.pki, f.withKey.CertDER); tbl != "certificates" {
		t.Fatalf("the control search found the certificate in %q, want table certificates", tbl)
	}
	for _, db := range []struct {
		name string
		path string
	}{{"pki.db", "pki"}, {"audit.db", "audit"}} {
		d := f.v.pki
		if db.path == "audit" {
			d = f.v.audit
		}
		for _, needle := range [][]byte{f.pkcs8DER, pemKey} {
			if tbl, col := dbContains(t, d, needle); tbl != "" {
				t.Errorf("the plain key is in %s: table %s, column %s", db.name, tbl, col)
			}
		}
	}
	downloads := 0
	for _, row := range rows {
		if row.action == ActionKeyDownload {
			downloads++
			if row.result != "success" || row.details["delete_key"] != false || row.details["serial"] != f.withKey.SerialHex {
				t.Errorf("download entry %+v", row)
			}
		}
	}
	if downloads != len(ExportFormats) {
		t.Errorf("%d key.download entries, want %d", downloads, len(ExportFormats))
	}
	// Still encrypted and usable afterwards.
	if _, err := keys.LoadKey(t.Context(), f.v.pki, f.withKey.KeyID); err != nil {
		t.Errorf("the stored key after three exports: %v", err)
	}
}

// queryRows runs a query and hands every row to visit until it returns true.
func queryRows(t *testing.T, db pkidb.DBTX, query string, visit func(rows *sql.Rows) bool) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if visit(rows) {
			return
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func queryColumn(t *testing.T, db pkidb.DBTX, query string) []string {
	t.Helper()
	var out []string
	queryRows(t, db, query, func(rows *sql.Rows) bool {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
		return false
	})
	return out
}

// dbContains looks for needle in every column of every table.
func dbContains(t *testing.T, db pkidb.DBTX, needle []byte) (table, column string) {
	t.Helper()
	for _, name := range queryColumn(t, db, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`) {
		for _, col := range queryColumn(t, db, `SELECT name FROM pragma_table_info('`+name+`')`) {
			queryRows(t, db, `SELECT CAST("`+col+`" AS BLOB) FROM "`+name+`" WHERE "`+col+`" IS NOT NULL`, func(rows *sql.Rows) bool {
				var b []byte
				if err := rows.Scan(&b); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(b, needle) {
					table, column = name, col
					return true
				}
				return false
			})
			if table != "" {
				return table, column
			}
		}
	}
	return "", ""
}

// TestExportDeleteKey: the key is destroyed after the file was built and the
// download audited; a second export finds nothing; a failing audit or a
// failing destroy hands out nothing.
func TestExportDeleteKey(t *testing.T) {
	t.Parallel()
	t.Run("destroyed after the download", func(t *testing.T) {
		t.Parallel()
		f := newExportFixture(t)
		out, err := f.export(t, func(r *ExportRequest) { r.DeleteKey = true })
		if err != nil || !out.KeyDeleted || !bytes.Contains(out.Data, []byte("PRIVATE KEY")) {
			t.Fatalf("export with DeleteKey: %+v %v", out, err)
		}
		if _, err = keys.LoadKey(t.Context(), f.v.pki, f.withKey.KeyID); !errors.Is(err, keys.ErrKeyDestroyed) {
			t.Errorf("the key after the export: %v", err)
		}
		var wrapped, cipher []byte
		if err = f.v.pki.QueryRowContext(t.Context(), `SELECT wrapped_dek, key_ciphertext FROM keys WHERE id = ?`, f.withKey.KeyID).Scan(&wrapped, &cipher); err != nil ||
			!bytes.Equal(wrapped, []byte{0}) || !bytes.Equal(cipher, []byte{0}) {
			t.Errorf("the key material is still in the row: %x %x (%v)", wrapped, cipher, err)
		}
		if _, err = f.export(t, nil); !errors.Is(err, ErrKeyDeleted) {
			t.Errorf("a second export: %v", err)
		}
		actions := map[string]string{}
		for _, row := range f.v.auditRows(t) {
			if row.action == ActionKeyDownload || row.action == ActionKeyDestroy {
				actions[row.action] = row.result
				if row.action == ActionKeyDestroy && (row.details["trigger"] != "download" || row.details["serial"] != f.withKey.SerialHex) {
					t.Errorf("destroy details %v", row.details)
				}
			}
		}
		if actions[ActionKeyDownload] != "success" || actions[ActionKeyDestroy] != "success" {
			t.Errorf("audit %v", actions)
		}
	})
	t.Run("the audit entry can't be written", func(t *testing.T) {
		t.Parallel()
		f := newExportFixture(t)
		if _, err := f.v.audit.ExecContext(t.Context(), `CREATE TRIGGER no_audit BEFORE INSERT ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit disk full'); END`); err != nil {
			t.Fatal(err)
		}
		out, err := f.export(t, func(r *ExportRequest) { r.DeleteKey = true })
		if out != nil || err == nil || !strings.Contains(err.Error(), "key download refused – the audit entry can't be written") {
			t.Fatalf("export without an audit log: %v %v", out, err)
		}
		if _, err = keys.LoadKey(t.Context(), f.v.pki, f.withKey.KeyID); err != nil {
			t.Errorf("the key was destroyed although nothing was handed out: %v", err)
		}
	})
	t.Run("the key can't be destroyed", func(t *testing.T) {
		t.Parallel()
		f := newExportFixture(t)
		if _, err := f.v.pki.ExecContext(t.Context(), `CREATE TRIGGER keep_keys BEFORE UPDATE ON keys BEGIN SELECT RAISE(ABORT, 'read-only'); END`); err != nil {
			t.Fatal(err)
		}
		out, err := f.export(t, func(r *ExportRequest) { r.DeleteKey = true })
		if out != nil || err == nil || !strings.Contains(err.Error(), "the key was not deleted, so nothing is handed out – try again") {
			t.Fatalf("export with a failing destroy: %v %v", out, err)
		}
		if _, err = keys.LoadKey(t.Context(), f.v.pki, f.withKey.KeyID); err != nil {
			t.Errorf("the key after a failed destroy: %v", err)
		}
	})
}

// TestFileBase: the file name stem is the CN in safe characters, else the
// serial – never a path.
func TestFileBase(t *testing.T) {
	t.Parallel()
	for cn, want := range map[string]string{
		"nas.homelab.lan":      "nas.homelab.lan",
		"*.homelab.lan":        "_.homelab.lan",
		"Max Müller/../x":      "MaxMller..x",
		`a\b:c*d`:              "abc_d",
		"../../etc/passwd":     "....etcpasswd",
		"":                     "0A1B",
		"***":                  "0A1B",
		"...":                  "0A1B",
		"_.-":                  "_.-",
		"ünïcödé":              "ncd",
		"-":                    "-",
		"with\x00nul\nnewline": "withnulnewline",
	} {
		if got := fileBase(&CertificateInfo{CommonName: cn, Serial: "0A1B"}); got != want {
			t.Errorf("CN %q: %q, want %q", cn, got, want)
		}
	}
}
