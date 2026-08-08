package main

import (
	"log/slog"
	"testing"
	"time"
)

func TestIsHealthProbeRequest(t *testing.T) {
	tests := []struct {
		name   string
		record slog.Record
		want   bool
	}{
		{
			name:   "ready probe",
			record: requestRecord("/readyz"),
			want:   true,
		},
		{
			name:   "health probe",
			record: requestRecord("/healthz"),
			want:   true,
		},
		{
			name:   "normal request",
			record: requestRecord("/v1/auth/token"),
			want:   false,
		},
		{
			name:   "readiness warning is retained",
			record: warningRecord("readiness check failed", slog.String("error", "database unavailable")),
			want:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isHealthProbeRequest(test.record); got != test.want {
				t.Fatalf("isHealthProbeRequest() = %v, want %v", got, test.want)
			}
		})
	}
}

func requestRecord(path string) slog.Record {
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	record.AddAttrs(slog.String("method", "GET"), slog.String("path", path))
	return record
}

func warningRecord(message string, attrs ...slog.Attr) slog.Record {
	record := slog.NewRecord(time.Now(), slog.LevelWarn, message, 0)
	record.AddAttrs(attrs...)
	return record
}
