package server

import (
	"context"
	"log/slog"
	"strings"
)

type httpErrorLogHandler struct{ slog.Handler }

func (h httpErrorLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if strings.Contains(record.Message, "panic") {
		record.Level = slog.LevelError
	} else {
		record.Level = slog.LevelDebug
	}
	return h.Handler.Handle(ctx, record)
}
