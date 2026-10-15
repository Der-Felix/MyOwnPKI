package setup

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// DemoWarning is logged at every start of a demo instance (step 12) and
// shown as a banner in the UI (step 14).
const DemoWarning = "DEMO instance – all secrets are in one file, do not use in production"

// Instance is what init left behind.
type Instance struct {
	Initialized   bool
	Demo          bool
	InitializedAt string
}

// ReadInstance reads the instance row; q may be a read connection.
func ReadInstance(ctx context.Context, q systemdb.DBTX) (Instance, error) {
	row, err := systemdb.New(q).GetInstance(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, nil
	}
	if err != nil {
		return Instance{}, err
	}
	return Instance{Initialized: true, Demo: row.Demo == 1, InitializedAt: row.InitializedAt}, nil
}
