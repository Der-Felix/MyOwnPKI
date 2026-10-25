package agents

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"

	"connectrpc.com/connect"
)

func recoverConnect(s *Service) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (response connect.AnyResponse, err error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger := s.Log
					if logger == nil {
						logger = slog.New(slog.DiscardHandler)
					}
					logger.ErrorContext(ctx, "agent RPC panic",
						slog.String("procedure", req.Spec().Procedure), slog.Any("panic", recovered), slog.String("stack", string(debug.Stack())))
					response = nil
					err = connect.NewError(connect.CodeInternal, errors.New("the server failed – its log has the details"))
				}
			}()
			return next(ctx, req)
		}
	}
}
