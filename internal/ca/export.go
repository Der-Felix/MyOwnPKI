package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/pkcs12"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Export of a certificate with its server-generated key (PHASE1 step 18):
// PKCS#8 PEM, PKCS#12 with a password, or a combined PEM (certificate,
// chain, key – HAProxy). Optionally the key is destroyed on the server
// after the file was built and the download audited.

// Export formats.
const (
	ExportPKCS8PEM    = "pkcs8-pem"
	ExportPKCS12      = "pkcs12"
	ExportCombinedPEM = "combined-pem"
)

// ExportFormats lists the formats in the order the UI offers them.
var ExportFormats = []string{ExportPKCS12, ExportPKCS8PEM, ExportCombinedPEM}

// ActionKeyDestroy is the audit action of a destroyed key.
const ActionKeyDestroy = "key.destroy"

// ErrKeyDeleted: the key was destroyed after an earlier download.
var ErrKeyDeleted = errors.New("the private key was deleted from the server after an earlier download")

// ExportRequest asks for a key export.
type ExportRequest struct {
	ID, Format string
	// Password protects a PKCS#12 file (at least pkcs12.MinPassword characters).
	Password string
	// DeleteKey destroys the key on the server after the export.
	DeleteKey bool
	Who       keys.Who
}

// Export is the file to hand out.
type Export struct {
	Data                  []byte
	ContentType, FileName string
	KeyDeleted            bool
}

// Export builds the export file. It needs key.download (operator on the
// issuing CA, fresh second factor) and an unsealed server; the download is
// audited before the file leaves (fail-closed).
func (e *Engine) Export(ctx context.Context, req ExportRequest) (*Export, error) {
	now := e.now()
	info, err := e.Certificate(ctx, req.Who, req.ID)
	if err != nil {
		return nil, err
	}
	target := audit.Target{Type: "certificate", ID: info.ID}
	details := map[string]any{"serial": info.Serial, "ca": info.CAName, "format": req.Format, "delete_key": req.DeleteKey}
	if derr := e.authorize(req.Who, authz.DownloadKey, info.CAName, now); derr != nil {
		if aerr := e.refuse(ctx, now, ActionKeyDownload, req.Who, target, details, derr); aerr != nil {
			return nil, errors.Join(derr, fmt.Errorf("audit: %w", aerr))
		}
		return nil, derr
	}
	switch req.Format {
	case ExportPKCS8PEM, ExportCombinedPEM:
	case ExportPKCS12:
		if len([]rune(req.Password)) < pkcs12.MinPassword {
			return nil, deny("the PKCS#12 password needs at least %d characters – the importing system asks for it", pkcs12.MinPassword)
		}
	default:
		return nil, deny("unknown export format %q (allowed: %s)", short(req.Format), strings.Join(ExportFormats, ", "))
	}
	if !info.KeyStored {
		return nil, ErrNoStoredKey
	}
	if e.Keys.Status().Sealed {
		return nil, keys.ErrSealed
	}
	key, err := keys.LoadKey(ctx, e.PKI, info.keyID)
	if errors.Is(err, keys.ErrKeyDestroyed) {
		return nil, ErrKeyDeleted
	}
	if err != nil {
		return nil, err
	}
	certDER, chain, err := e.CertificateChain(ctx, req.Who, req.ID)
	if err != nil {
		return nil, err
	}
	name := fileBase(info)
	out := &Export{}
	err = e.Keys.WithKey(key.ID, key.Purpose, key.Algorithm, key.Envelope, func(pkcs8 []byte) error {
		if _, perr := x509.ParsePKCS8PrivateKey(pkcs8); perr != nil {
			return fmt.Errorf("key %s: not a PKCS#8 private key", key.ID)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		switch req.Format {
		case ExportPKCS8PEM:
			out.Data, out.ContentType, out.FileName = keyPEM, "application/x-pem-file", name+".key.pem"
		case ExportCombinedPEM:
			var b bytes.Buffer
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
			for _, c := range chain {
				b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c}))
			}
			b.Write(keyPEM)
			clear(keyPEM)
			out.Data, out.ContentType, out.FileName = b.Bytes(), "application/x-pem-file", name+".combined.pem"
		case ExportPKCS12:
			clear(keyPEM)
			certs := make([]*x509.Certificate, 0, 1+len(chain))
			for _, der := range append([][]byte{certDER}, chain...) {
				c, perr := x509.ParseCertificate(der)
				if perr != nil {
					return perr
				}
				certs = append(certs, c)
			}
			p12, perr := pkcs12.Encode(e.rand(), pkcs8, certs, info.CommonName, req.Password)
			if perr != nil {
				return perr
			}
			out.Data, out.ContentType, out.FileName = p12, "application/x-pkcs12", name+".p12"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, _, aerr := audit.Append(ctx, e.Audit, e.Scope, audit.Entry{
		Time: now, Actor: req.Who.Actor, Action: ActionKeyDownload, Target: target,
		Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: details,
	}, ""); aerr != nil {
		clear(out.Data)
		return nil, fmt.Errorf("key download refused – the audit entry can't be written: %w", aerr)
	}
	if req.DeleteKey {
		if derr := e.destroyKey(ctx, info, req.Who); derr != nil {
			clear(out.Data)
			return nil, fmt.Errorf("the key was not deleted, so nothing is handed out – try again: %w", derr)
		}
		out.KeyDeleted = true
	}
	return out, nil
}

// destroyKey overwrites the stored key with secure_delete on, so the freed
// pages don't keep the ciphertext either. Older backups still hold it.
func (e *Engine) destroyKey(ctx context.Context, info *CertificateInfo, who keys.Who) error {
	now := e.now()
	if _, err := e.PKI.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return err
	}
	return e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, err := q.DestroyKey(ctx, pkidb.DestroyKeyParams{DestroyedAt: sql.NullString{String: now.Format(dbTime), Valid: true}, ID: info.keyID})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrKeyDeleted
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionKeyDestroy, Target: audit.Target{Type: "certificate", ID: info.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"serial": info.Serial, "ca": info.CAName, "trigger": "download"},
		})
	})
}

// fileBase is the file name stem of a certificate's downloads: the CN in
// safe characters, else the serial.
func fileBase(info *CertificateInfo) string {
	base := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		case r == '*':
			return '_'
		}
		return -1
	}, info.CommonName)
	if base == "" || strings.Trim(base, "._") == "" {
		return info.Serial
	}
	return base
}
