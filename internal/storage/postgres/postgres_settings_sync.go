package postgres

import (
	"context"
	"encoding/json"
	"errors"
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) Current(userID string) (SettingsSyncSnapshot, bool) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	snapshot, err := scanSettingsSyncSnapshot(s.pool.QueryRow(ctx, `
		SELECT revision, updated_at, updated_by_installation_id, app_version, content_hash, payload
		FROM settings_sync_snapshots
		WHERE user_id = $1
		ORDER BY revision DESC LIMIT 1`, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return SettingsSyncSnapshot{}, false
	}
	if err != nil {
		slog.Error("load current settings snapshot", "error", err, "user_id", userID)
		return SettingsSyncSnapshot{}, false
	}
	return snapshot, true
}

func (s *PostgresStorage) Put(
	userID, installationID string,
	baseRevision int64,
	force bool,
	appVersion, contentHash string,
	payload json.RawMessage,
) (SettingsSyncSnapshot, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("begin settings sync", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockSettingsSyncUser(ctx, tx, userID); err != nil {
		return SettingsSyncSnapshot{}, err
	}
	current, hasCurrent, err := currentSettingsSyncTx(ctx, tx, userID)
	if err != nil {
		return SettingsSyncSnapshot{}, err
	}
	currentRevision := int64(0)
	if hasCurrent {
		currentRevision = current.Revision
	}
	if !force && baseRevision != currentRevision {
		if hasCurrent {
			return current, ErrSettingsSyncConflict
		}
		return SettingsSyncSnapshot{}, ErrSettingsSyncConflict
	}
	if hasCurrent && current.ContentHash == contentHash {
		if err := tx.Commit(ctx); err != nil {
			return SettingsSyncSnapshot{}, fmtDatabase("commit unchanged settings sync", err)
		}
		return current, nil
	}
	if !json.Valid(payload) {
		return SettingsSyncSnapshot{}, errors.New("settings payload must contain valid JSON")
	}
	next := SettingsSyncSnapshot{
		Revision:                currentRevision + 1,
		UpdatedAt:               time.Now().UTC(),
		UpdatedByInstallationID: installationID,
		AppVersion:              appVersion,
		ContentHash:             contentHash,
		Payload:                 append(json.RawMessage(nil), payload...),
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO settings_sync_snapshots (
			user_id, revision, updated_at, updated_by_installation_id,
			app_version, content_hash, payload
		) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
		userID, next.Revision, next.UpdatedAt, installationID, appVersion, contentHash, []byte(payload),
	); err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("insert settings snapshot", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM settings_sync_snapshots
		WHERE user_id = $1 AND revision NOT IN (
			SELECT revision FROM settings_sync_snapshots
			WHERE user_id = $1 ORDER BY revision DESC LIMIT $2
		)`, userID, MaxSettingsSyncHistory+1); err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("trim settings snapshots", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("commit settings sync", err)
	}
	return next, nil
}

func (s *PostgresStorage) History(userID string) []SettingsSyncSnapshot {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	rows, err := s.pool.Query(ctx, `
		SELECT revision, updated_at, updated_by_installation_id, app_version, content_hash, payload
		FROM settings_sync_snapshots
		WHERE user_id = $1
		ORDER BY revision DESC
		LIMIT $2`, userID, MaxSettingsSyncHistory+1)
	if err != nil {
		slog.Error("list settings snapshots", "error", err, "user_id", userID)
		return nil
	}
	defer rows.Close()
	result := make([]SettingsSyncSnapshot, 0, MaxSettingsSyncHistory+1)
	for rows.Next() {
		snapshot, err := scanSettingsSyncSnapshot(rows)
		if err != nil {
			slog.Error("scan settings snapshot", "error", err)
			return nil
		}
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		slog.Error("iterate settings snapshots", "error", err, "user_id", userID)
		return nil
	}
	return result
}

func (s *PostgresStorage) Restore(
	userID, installationID string,
	revision int64,
) (SettingsSyncSnapshot, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("begin restore settings", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockSettingsSyncUser(ctx, tx, userID); err != nil {
		return SettingsSyncSnapshot{}, err
	}
	source, err := scanSettingsSyncSnapshot(tx.QueryRow(ctx, `
		SELECT revision, updated_at, updated_by_installation_id, app_version, content_hash, payload
		FROM settings_sync_snapshots WHERE user_id = $1 AND revision = $2`, userID, revision))
	if errors.Is(err, pgx.ErrNoRows) {
		return SettingsSyncSnapshot{}, ErrSettingsSyncRevisionNotFound
	}
	if err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("load settings revision", err)
	}
	current, hasCurrent, err := currentSettingsSyncTx(ctx, tx, userID)
	if err != nil {
		return SettingsSyncSnapshot{}, err
	}
	currentRevision := int64(0)
	if hasCurrent {
		currentRevision = current.Revision
	}
	next := SettingsSyncSnapshot{
		Revision:                currentRevision + 1,
		UpdatedAt:               time.Now().UTC(),
		UpdatedByInstallationID: installationID,
		AppVersion:              source.AppVersion,
		ContentHash:             source.ContentHash,
		Payload:                 append(json.RawMessage(nil), source.Payload...),
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO settings_sync_snapshots (
			user_id, revision, updated_at, updated_by_installation_id,
			app_version, content_hash, payload
		) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
		userID, next.Revision, next.UpdatedAt, installationID,
		next.AppVersion, next.ContentHash, []byte(next.Payload),
	); err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("insert restored settings snapshot", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM settings_sync_snapshots
		WHERE user_id = $1 AND revision NOT IN (
			SELECT revision FROM settings_sync_snapshots
			WHERE user_id = $1 ORDER BY revision DESC LIMIT $2
		)`, userID, MaxSettingsSyncHistory+1); err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("trim restored settings snapshots", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SettingsSyncSnapshot{}, fmtDatabase("commit restored settings snapshot", err)
	}
	return next, nil
}

func lockSettingsSyncUser(ctx context.Context, tx pgx.Tx, userID string) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", settingsSyncLockKey(userID)); err != nil {
		return fmtDatabase("lock settings sync user", err)
	}
	return nil
}

func settingsSyncLockKey(userID string) int64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte("ferventio:settings-sync:"))
	_, _ = hasher.Write([]byte(userID))
	return int64(hasher.Sum64())
}

func currentSettingsSyncTx(ctx context.Context, tx pgx.Tx, userID string) (SettingsSyncSnapshot, bool, error) {
	snapshot, err := scanSettingsSyncSnapshot(tx.QueryRow(ctx, `
		SELECT revision, updated_at, updated_by_installation_id, app_version, content_hash, payload
		FROM settings_sync_snapshots
		WHERE user_id = $1 ORDER BY revision DESC LIMIT 1 FOR UPDATE`, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return SettingsSyncSnapshot{}, false, nil
	}
	if err != nil {
		return SettingsSyncSnapshot{}, false, fmtDatabase("load current settings snapshot", err)
	}
	return snapshot, true, nil
}

func scanSettingsSyncSnapshot(scanner databaseScanner) (SettingsSyncSnapshot, error) {
	var snapshot SettingsSyncSnapshot
	var payload []byte
	if err := scanner.Scan(
		&snapshot.Revision, &snapshot.UpdatedAt, &snapshot.UpdatedByInstallationID,
		&snapshot.AppVersion, &snapshot.ContentHash, &payload,
	); err != nil {
		return SettingsSyncSnapshot{}, err
	}
	snapshot.Payload = append(json.RawMessage(nil), payload...)
	return snapshot, nil
}
