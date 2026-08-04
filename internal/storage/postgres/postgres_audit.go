package postgres

import (
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"log/slog"
	"time"
)

func (s *PostgresStorage) Append(record AuditRecord) error {
	if record.ID == "" {
		value, err := RandomToken("audit_", 12)
		if err != nil {
			return err
		}
		record.ID = value
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}
	if len(record.Detail) > 1_000 {
		record.Detail = record.Detail[:1_000]
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin audit append", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_records (
			id, timestamp, action, status, installation_id,
			user_id, channel_id, event_id, detail
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		record.ID, record.Timestamp, record.Action, record.Status, record.InstallationID,
		record.UserID, record.ChannelID, record.EventID, record.Detail,
	); err != nil {
		return fmtDatabase("insert audit record", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM audit_records WHERE id IN (
			SELECT id FROM audit_records
			ORDER BY timestamp DESC, id DESC
			OFFSET $1
		)`, MaxAuditRecords); err != nil {
		return fmtDatabase("trim audit records", err)
	}
	return commitDatabaseTx(ctx, tx, "audit append")
}

func (s *PostgresStorage) ListAudit(limit int) []AuditRecord {
	return s.listAudit(limit)
}

func (s *PostgresStorage) listAudit(limit int) []AuditRecord {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	limit = normalizeLimit(limit, 200, 1_000)
	rows, err := s.pool.Query(ctx, `
		SELECT id, timestamp, action, status, installation_id,
		       user_id, channel_id, event_id, detail
		FROM audit_records
		ORDER BY timestamp DESC, id DESC
		LIMIT $1`, limit)
	if err != nil {
		slog.Error("list audit records", "error", err)
		return nil
	}
	defer rows.Close()
	result := make([]AuditRecord, 0, limit)
	for rows.Next() {
		var record AuditRecord
		if err := rows.Scan(
			&record.ID, &record.Timestamp, &record.Action, &record.Status,
			&record.InstallationID, &record.UserID, &record.ChannelID,
			&record.EventID, &record.Detail,
		); err != nil {
			slog.Error("scan audit record", "error", err)
			return nil
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		slog.Error("iterate audit records", "error", err)
		return nil
	}
	return result
}
