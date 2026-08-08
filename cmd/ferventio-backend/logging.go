package main

import (
	"context"
	"log/slog"
)

// healthProbeFilterHandler keeps successful Docker health probes out of the normal
// access log. Readiness failures remain visible because the readiness handler logs
// them separately as warnings before returning 503.
type healthProbeFilterHandler struct {
	next slog.Handler
}

func newHealthProbeFilterHandler(next slog.Handler) slog.Handler {
	return healthProbeFilterHandler{next: next}
}

func (h healthProbeFilterHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h healthProbeFilterHandler) Handle(ctx context.Context, record slog.Record) error {
	if isHealthProbeRequest(record) {
		return nil
	}
	return h.next.Handle(ctx, record)
}

func (h healthProbeFilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return healthProbeFilterHandler{next: h.next.WithAttrs(attrs)}
}

func (h healthProbeFilterHandler) WithGroup(name string) slog.Handler {
	return healthProbeFilterHandler{next: h.next.WithGroup(name)}
}

func isHealthProbeRequest(record slog.Record) bool {
	if record.Message != "request" {
		return false
	}
	isProbe := false
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key != "path" {
			return true
		}
		path := attr.Value.String()
		isProbe = path == "/healthz" || path == "/readyz"
		return false
	})
	return isProbe
}
