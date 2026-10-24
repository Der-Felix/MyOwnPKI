package agents

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"connectrpc.com/connect"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// TestRPCErrors: what the agent can act on gets its Connect code and text;
// anything else is an internal error without details.
func TestRPCErrors(t *testing.T) {
	t.Parallel()
	s := &Service{Log: slog.New(slog.DiscardHandler)}
	for err, want := range map[error]connect.Code{
		fmt.Errorf("%w: CSR", ErrInvalid):          connect.CodeInvalidArgument,
		ErrNotFound:                                connect.CodeNotFound,
		ErrQueueFull:                               connect.CodeResourceExhausted,
		ErrRateLimited:                             connect.CodeResourceExhausted, // also the renewal limit
		ErrUnknownAgent:                            connect.CodePermissionDenied,
		keys.ErrSealed:                             connect.CodeUnavailable,
		fmt.Errorf("%w: decided", ErrConflict):     connect.CodeFailedPrecondition,
		&ca.DeniedError{Reasons: []string{"name"}}: connect.CodeFailedPrecondition,
		errors.New("database is locked"):           connect.CodeInternal,
	} {
		got := s.rpcError("test", err)
		if connect.CodeOf(got) != want {
			t.Errorf("%v: %v, want %v", err, connect.CodeOf(got), want)
		}
		if want == connect.CodeInternal && errors.Is(got, err) {
			t.Errorf("%v: the internal error reaches the agent", err)
		}
	}
}
