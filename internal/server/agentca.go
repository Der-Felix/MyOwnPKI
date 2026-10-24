package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// oidClientAuth is id-kp-clientAuth (RFC 5280 §4.2.1.12) as the CA table
// stores EKU limits: dotted.
const oidClientAuth = "1.3.6.1.5.5.7.3.2"

// AgentCAProblem says what is wrong with the CA that agent.ca names; "" =
// nothing. The agent CA must be an active intermediate whose EKU limit is
// exactly clientAuth (docs/PHASE3.md §1.1): then nothing it signs can ever
// act as a server, whatever a preset or a bug would put into a certificate.
// The listener accepts client certificates from this CA only.
func AgentCAProblem(ctx context.Context, db pkidb.DBTX, name string) (string, error) {
	row, err := pkidb.New(db).GetCAByName(ctx, name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Sprintf("there is no CA named %q (agent.ca) – create an intermediate with the EKU limit clientAuth only", name), nil
	case err != nil:
		return "", err
	case row.Kind == ca.KindRoot:
		return fmt.Sprintf("CA %s is a root – agent.ca names an intermediate with the EKU limit clientAuth only", name), nil
	case row.Status != ca.StatusActive:
		return fmt.Sprintf("CA %s is %s – agent.ca needs an active CA", name, row.Status), nil
	}
	var limit []string
	if err := json.Unmarshal([]byte(row.EkuLimit), &limit); err != nil {
		return "", fmt.Errorf("CA %q: eku_limit: %w", name, err)
	}
	if !slices.Equal(limit, []string{oidClientAuth}) {
		return fmt.Sprintf("CA %s may sign more than client certificates – the agent CA needs the EKU limit clientAuth only (agent.ca)", name), nil
	}
	return "", nil
}

// AgentCAProblems is AgentCAProblem for cfg, read from the CA database
// without changing it (`config check`); nothing while the agent listener is
// off. An error means the database couldn't be read.
func AgentCAProblems(ctx context.Context, cfg config.Config) ([]string, error) {
	if !cfg.Agent.Enabled() {
		return nil, nil
	}
	file, err := store.Layout{DataDir: cfg.DataDir}.TenantDB(store.DefaultTenant, store.KindPKI)
	if err != nil {
		return nil, err
	}
	db, err := store.OpenReadOnly(ctx, file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	p, err := AgentCAProblem(ctx, db.Read, cfg.Agent.CA)
	if err != nil || p == "" {
		return nil, err
	}
	return []string{p}, nil
}
