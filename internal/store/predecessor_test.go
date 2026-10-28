package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func TestPredecessorMigrationLeavesExistingCertificatesUntouched(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path, pathErr := Layout{DataDir: t.TempDir()}.TenantDB(DefaultTenant, KindPKI)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, openErr := Open(ctx, path)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer func() { _ = db.Close() }()
	set, setErr := Migrations(KindPKI)
	if setErr != nil {
		t.Fatal(setErr)
	}
	now := func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	if _, err := migrate.Apply(ctx, db.Write, set[:13], now); err != nil {
		t.Fatal(err)
	}
	q := pkidb.New(db.Write)
	if err := q.InsertCertificate(ctx, pkidb.InsertCertificateParams{
		ID: "crt-existing", Source: "external", SerialHex: "AB01", SubjectDn: "CN=existing", CommonName: "existing",
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", KeyAlgorithm: "ecdsa-p256", CertDer: []byte{1},
		FingerprintSha256: "AA01", RequestedBy: "test", CreatedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertCertificate(ctx, pkidb.InsertCertificateParams{
		ID: "crt-existing-revoked", Source: "external", SerialHex: "AB02", SubjectDn: "CN=revoked", CommonName: "revoked",
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", KeyAlgorithm: "ecdsa-p256", CertDer: []byte{2},
		FingerprintSha256: "AA02", RequestedBy: "test", CreatedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertRevocation(ctx, pkidb.InsertRevocationParams{
		CertificateID: "crt-existing-revoked", Reason: "keyCompromise", RevokedAt: "2026-01-02T00:00:00Z", RevokedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, db.Write, set, now); err != nil {
		t.Fatal(err)
	}
	cert, err := q.GetCertificate(ctx, "crt-existing")
	if err != nil || cert.SerialHex != "AB01" {
		t.Fatalf("existing certificate changed: %+v, %v", cert, err)
	}
	var plans, revocations, history int
	for query, target := range map[string]*int{
		"SELECT count(*) FROM certificate_revocation_plans":  &plans,
		"SELECT count(*) FROM revocations":                   &revocations,
		"SELECT count(*) FROM agent_deployment_certificates": &history,
	} {
		if scanErr := db.Read.QueryRowContext(ctx, query).Scan(target); scanErr != nil {
			t.Fatal(scanErr)
		}
	}
	if plans != 0 || revocations != 1 || history != 0 {
		t.Errorf("migration acted on unchanged serials: plans=%d revocations=%d history=%d", plans, revocations, history)
	}
	revocation, err := q.GetRevocation(ctx, "crt-existing-revoked")
	if err != nil || revocation.Reason != "keyCompromise" || revocation.RevokedAt != "2026-01-02T00:00:00Z" {
		t.Errorf("existing revocation changed: %+v, %v", revocation, err)
	}
}
