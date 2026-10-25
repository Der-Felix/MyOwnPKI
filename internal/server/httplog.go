package server

import (
	"context"
	"log/slog"
	"strings"
)

type httpErrorLogHandler struct{ slog.Handler }

func (h httpErrorLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h httpErrorLogHandler) Handle(ctx context.Context, record slog.Record) error {
	level := slog.LevelDebug
	if strings.Contains(record.Message, "panic") {
		level = slog.LevelError
	}
	if !h.Handler.Enabled(ctx, level) {
		return nil
	}
	record.Level = level
	return h.Handler.Handle(ctx, record)
}
