package postgres

import (
	"context"
	"encoding/json"
	"errors"
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const deliveryColumns = `
	id, event_id, installation_id,
	notification_type, notification_title, notification_body,
	notification_channel_id, notification_channel_login, notification_message_id,
	notification_actor_id, notification_actor_login, notification_actor_display_name,
	notification_destination, notification_silent, notification_created_at_epoch_millis,
	status, attempt_count, available_at, expires_at, created_at, sent_at, acked_at, last_error`

const eventSubInboxColumns = `
	message_id, challenge, subscription_id, subscription_type, subscription_version,
	subscription_status, subscription_condition, event_payload,
	status, attempt_count, available_at, expires_at, received_at, last_attempt_at, last_error`

func (s *PostgresStorage) Enqueue(record DeliveryRecord) (DeliveryRecord, bool, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.EventID) == "" || strings.TrimSpace(record.InstallationID) == "" {
		return DeliveryRecord{}, false, errors.New("delivery id, event id, and installation id are required")
	}
	if record.Status == "" {
		record.Status = DeliveryStatusPending
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.AvailableAt.IsZero() {
		record.AvailableAt = now
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = now.Add(24 * time.Hour)
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DeliveryRecord{}, false, fmtDatabase("begin enqueue delivery", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := cleanupDeliveriesTx(ctx, tx, now); err != nil {
		return DeliveryRecord{}, false, err
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM deliveries").Scan(&count); err != nil {
		return DeliveryRecord{}, false, fmtDatabase("count deliveries", err)
	}
	if count >= MaxDeliveryRecords {
		return DeliveryRecord{}, false, errors.New("delivery queue is full")
	}
	inserted, err := scanDelivery(tx.QueryRow(ctx, `
		INSERT INTO deliveries (`+deliveryColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NULL,NULL,$21)
		ON CONFLICT (installation_id, event_id) DO NOTHING
		RETURNING `+deliveryColumns,
		record.ID, record.EventID, record.InstallationID,
		record.Notification.Type, record.Notification.Title, record.Notification.Body,
		record.Notification.ChannelID, record.Notification.ChannelLogin, record.Notification.MessageID,
		record.Notification.ActorID, record.Notification.ActorLogin, record.Notification.ActorDisplayName,
		record.Notification.Destination, record.Notification.Silent, record.Notification.CreatedAtEpochMillis,
		record.Status, record.AttemptCount, record.AvailableAt, record.ExpiresAt, record.CreatedAt, record.LastError,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, loadErr := scanDelivery(tx.QueryRow(ctx,
			"SELECT "+deliveryColumns+" FROM deliveries WHERE installation_id = $1 AND event_id = $2",
			record.InstallationID, record.EventID,
		))
		if loadErr != nil {
			return DeliveryRecord{}, false, fmtDatabase("load duplicate delivery", loadErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return DeliveryRecord{}, false, fmtDatabase("commit duplicate delivery lookup", err)
		}
		return existing, false, nil
	}
	if err != nil {
		return DeliveryRecord{}, false, fmtDatabase("insert delivery", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeliveryRecord{}, false, fmtDatabase("commit delivery", err)
	}
	return inserted, true, nil
}

func (s *PostgresStorage) ListDeliveries(limit int) []DeliveryRecord {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	limit = normalizeLimit(limit, 200, 1_000)
	rows, err := s.pool.Query(ctx,
		"SELECT "+deliveryColumns+" FROM deliveries ORDER BY created_at DESC, id DESC LIMIT $1", limit,
	)
	if err != nil {
		slog.Error("list deliveries", "error", err)
		return nil
	}
	defer rows.Close()
	result := make([]DeliveryRecord, 0, limit)
	for rows.Next() {
		record, err := scanDelivery(rows)
		if err != nil {
			slog.Error("scan delivery", "error", err)
			return nil
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		slog.Error("iterate deliveries", "error", err)
		return nil
	}
	return result
}

func (s *PostgresStorage) PendingForInstallation(installationID string, limit int, now time.Time) []DeliveryRecord {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	limit = normalizeLimit(limit, 100, 1_000)
	rows, err := s.pool.Query(ctx, `
		SELECT `+deliveryColumns+` FROM deliveries
		WHERE installation_id = $1
		  AND status IN ('pending','sent')
		  AND available_at <= $2
		  AND expires_at > $2
		ORDER BY created_at ASC, id ASC LIMIT $3`, installationID, now, limit)
	if err != nil {
		slog.Error("list pending deliveries", "error", err, "installation_id", installationID)
		return nil
	}
	defer rows.Close()
	result := make([]DeliveryRecord, 0, limit)
	for rows.Next() {
		record, err := scanDelivery(rows)
		if err != nil {
			slog.Error("scan pending delivery", "error", err)
			return nil
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		slog.Error("iterate pending deliveries", "error", err, "installation_id", installationID)
		return nil
	}
	return result
}

func (s *PostgresStorage) MarkSent(id string, sentAt time.Time) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, `
		UPDATE deliveries SET
			status = 'sent', attempt_count = attempt_count + 1,
			sent_at = $2, last_error = '',
			available_at = $2 + make_interval(secs => LEAST(64, power(2, GREATEST(attempt_count, 0))::int))
		WHERE id = $1`, id, sentAt)
	if err != nil {
		return fmtDatabase("mark delivery sent", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) MarkFailed(id string, failure error, failedAt time.Time) error {
	message := ""
	if failure != nil {
		message = failure.Error()
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, `
		UPDATE deliveries SET
			attempt_count = attempt_count + 1,
			last_error = $3,
			status = CASE WHEN attempt_count + 1 >= 8 OR $2 >= expires_at THEN 'dead' ELSE 'pending' END,
			available_at = CASE
				WHEN attempt_count + 1 >= 8 OR $2 >= expires_at THEN available_at
				ELSE $2 + make_interval(secs => LEAST(64, power(2, GREATEST(attempt_count, 0))::int))
			END
		WHERE id = $1`, id, failedAt, message)
	if err != nil {
		return fmtDatabase("mark delivery failed", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) AckThrough(installationID, eventID string, ackedAt time.Time) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, `
		WITH target AS (
			SELECT created_at FROM deliveries WHERE installation_id = $1 AND event_id = $2
		)
		UPDATE deliveries SET status = 'acked', acked_at = $3, last_error = ''
		WHERE installation_id = $1 AND created_at <= (SELECT created_at FROM target)`,
		installationID, eventID, ackedAt)
	if err != nil {
		return fmtDatabase("ack deliveries through event", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) Ack(installationID, eventID string, ackedAt time.Time) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, `
		UPDATE deliveries SET status = 'acked', acked_at = $3, last_error = ''
		WHERE installation_id = $1 AND event_id = $2`, installationID, eventID, ackedAt)
	if err != nil {
		return fmtDatabase("ack delivery", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) DeleteForInstallation(installationID string) (int, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, "DELETE FROM deliveries WHERE installation_id = $1", installationID)
	if err != nil {
		return 0, fmtDatabase("delete installation deliveries", err)
	}
	return int(command.RowsAffected()), nil
}

func (s *PostgresStorage) EnqueueEventSub(messageID string, envelope EventSubEnvelope, now time.Time) (EventSubInboxRecord, bool, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return EventSubInboxRecord{}, false, errors.New("EventSub message id is required")
	}
	condition, err := json.Marshal(envelope.Subscription.Condition)
	if err != nil {
		return EventSubInboxRecord{}, false, err
	}
	event, err := json.Marshal(envelope.Event)
	if err != nil {
		return EventSubInboxRecord{}, false, err
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return EventSubInboxRecord{}, false, fmtDatabase("begin enqueue EventSub", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "DELETE FROM eventsub_seen WHERE seen_at < $1", now.Add(-24*time.Hour)); err != nil {
		return EventSubInboxRecord{}, false, fmtDatabase("clean EventSub deduplication records", err)
	}
	var seen bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM eventsub_seen WHERE message_id = $1)", messageID).Scan(&seen); err != nil {
		return EventSubInboxRecord{}, false, fmtDatabase("check EventSub deduplication record", err)
	}
	if seen {
		if err := tx.Commit(ctx); err != nil {
			return EventSubInboxRecord{}, false, fmtDatabase("commit EventSub seen lookup", err)
		}
		return EventSubInboxRecord{}, false, nil
	}
	record, err := scanEventSubInbox(tx.QueryRow(ctx, `
		INSERT INTO eventsub_inbox (
			message_id, challenge, subscription_id, subscription_type, subscription_version,
			subscription_status, subscription_condition, event_payload,
			status, attempt_count, available_at, expires_at, received_at, last_attempt_at, last_error
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',0,$9,$10,$9,NULL,'')
		ON CONFLICT (message_id) DO NOTHING
		RETURNING `+eventSubInboxColumns,
		messageID, envelope.Challenge, envelope.Subscription.ID, envelope.Subscription.Type,
		envelope.Subscription.Version, envelope.Subscription.Status, condition, event,
		now, now.Add(24*time.Hour),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, loadErr := scanEventSubInbox(tx.QueryRow(ctx,
			"SELECT "+eventSubInboxColumns+" FROM eventsub_inbox WHERE message_id = $1", messageID,
		))
		if loadErr != nil {
			return EventSubInboxRecord{}, false, fmtDatabase("load duplicate EventSub inbox record", loadErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return EventSubInboxRecord{}, false, fmtDatabase("commit duplicate EventSub lookup", err)
		}
		return existing, false, nil
	}
	if err != nil {
		return EventSubInboxRecord{}, false, fmtDatabase("insert EventSub inbox record", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return EventSubInboxRecord{}, false, fmtDatabase("commit EventSub inbox record", err)
	}
	return record, true, nil
}

func (s *PostgresStorage) PendingEventSub(limit int, now time.Time) []EventSubInboxRecord {
	return s.listEventSubInbox(`status = 'pending' AND available_at <= $1 AND expires_at > $1`, now, limit, true)
}

func (s *PostgresStorage) ListEventSubInbox(limit int) []EventSubInboxRecord {
	return s.listEventSubInbox("TRUE", time.Time{}, limit, false)
}

func (s *PostgresStorage) listEventSubInbox(where string, now time.Time, limit int, ascending bool) []EventSubInboxRecord {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	limit = normalizeLimit(limit, 200, 1_000)
	order := "DESC"
	args := []any{limit}
	queryWhere := where
	if ascending {
		order = "ASC"
		args = []any{now, limit}
	}
	limitPlaceholder := "$1"
	if ascending {
		limitPlaceholder = "$2"
	}
	rows, err := s.pool.Query(ctx,
		"SELECT "+eventSubInboxColumns+" FROM eventsub_inbox WHERE "+queryWhere+" ORDER BY received_at "+order+", message_id "+order+" LIMIT "+limitPlaceholder,
		args...,
	)
	if err != nil {
		slog.Error("list EventSub inbox", "error", err)
		return nil
	}
	defer rows.Close()
	result := make([]EventSubInboxRecord, 0, limit)
	for rows.Next() {
		record, err := scanEventSubInbox(rows)
		if err != nil {
			slog.Error("scan EventSub inbox", "error", err)
			return nil
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		slog.Error("iterate EventSub inbox", "error", err)
		return nil
	}
	return result
}

func (s *PostgresStorage) CompleteEventSub(messageID string, completedAt time.Time) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin complete EventSub", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, "DELETE FROM eventsub_inbox WHERE message_id = $1", messageID)
	if err != nil {
		return fmtDatabase("delete completed EventSub inbox record", err)
	}
	if command.RowsAffected() == 0 {
		var seen bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM eventsub_seen WHERE message_id = $1)", messageID).Scan(&seen); err != nil {
			return fmtDatabase("check completed EventSub record", err)
		}
		if !seen {
			return ErrNotFound
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO eventsub_seen(message_id, seen_at) VALUES ($1,$2)
		ON CONFLICT (message_id) DO UPDATE SET seen_at = EXCLUDED.seen_at`, messageID, completedAt); err != nil {
		return fmtDatabase("record completed EventSub message", err)
	}
	return commitDatabaseTx(ctx, tx, "complete EventSub")
}

func (s *PostgresStorage) MarkEventSubFailed(messageID string, failure error, failedAt time.Time) error {
	message := ""
	if failure != nil {
		message = failure.Error()
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, `
		UPDATE eventsub_inbox SET
			attempt_count = attempt_count + 1,
			last_attempt_at = $2,
			last_error = $3,
			status = CASE WHEN attempt_count + 1 >= 8 OR $2 >= expires_at THEN 'dead' ELSE 'pending' END,
			available_at = CASE
				WHEN attempt_count + 1 >= 8 OR $2 >= expires_at THEN available_at
				ELSE $2 + make_interval(secs => LEAST(64, power(2, GREATEST(attempt_count, 0))::int))
			END
		WHERE message_id = $1`, messageID, failedAt, message)
	if err != nil {
		return fmtDatabase("mark EventSub inbox failed", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) RetryEventSub(messageID string, now time.Time) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	command, err := s.pool.Exec(ctx, `
		UPDATE eventsub_inbox SET
			status = 'pending', attempt_count = 0, available_at = $2,
			expires_at = $2 + interval '24 hours', last_error = ''
		WHERE message_id = $1`, messageID, now)
	if err != nil {
		return fmtDatabase("retry EventSub inbox record", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) HasSeenEventSub(messageID string, now time.Time, ttl time.Duration) bool {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	if _, err := s.pool.Exec(ctx, "DELETE FROM eventsub_seen WHERE seen_at < $1", now.Add(-ttl)); err != nil {
		slog.Error("clean EventSub seen records", "error", err)
		return false
	}
	var seen bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM eventsub_seen WHERE message_id = $1)", messageID).Scan(&seen); err != nil {
		slog.Error("check EventSub seen record", "error", err)
		return false
	}
	return seen
}

func (s *PostgresStorage) SeenEventSub(messageID string, now time.Time, ttl time.Duration) (bool, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmtDatabase("begin EventSub seen transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "DELETE FROM eventsub_seen WHERE seen_at < $1", now.Add(-ttl)); err != nil {
		return false, fmtDatabase("clean EventSub seen records", err)
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO eventsub_seen(message_id, seen_at) VALUES ($1,$2)
		ON CONFLICT (message_id) DO NOTHING`, messageID, now)
	if err != nil {
		return false, fmtDatabase("insert EventSub seen record", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmtDatabase("commit EventSub seen record", err)
	}
	return command.RowsAffected() == 0, nil
}

func (s *PostgresStorage) ForgetEventSub(messageID string) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	_, err := s.pool.Exec(ctx, "DELETE FROM eventsub_seen WHERE message_id = $1", messageID)
	return fmtDatabase("forget EventSub message", err)
}

func (s *PostgresStorage) ChannelStateChanges(channelID, title, categoryName string) (bool, bool, bool, error) {
	if strings.TrimSpace(channelID) == "" {
		return false, false, false, errors.New("channel id is required")
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	var previousTitle, previousCategory string
	err := s.pool.QueryRow(ctx,
		"SELECT title, category_name FROM channel_notification_states WHERE channel_id = $1", channelID,
	).Scan(&previousTitle, &previousCategory)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, true, nil
	}
	if err != nil {
		return false, false, false, fmtDatabase("load channel notification state", err)
	}
	return previousTitle != title, previousCategory != categoryName, false, nil
}

func (s *PostgresStorage) SaveChannelState(channelID, title, categoryName string, now time.Time) error {
	if strings.TrimSpace(channelID) == "" {
		return errors.New("channel id is required")
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO channel_notification_states(channel_id, title, category_name, updated_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (channel_id) DO UPDATE SET
			title = EXCLUDED.title, category_name = EXCLUDED.category_name, updated_at = EXCLUDED.updated_at`,
		channelID, title, categoryName, now)
	return fmtDatabase("save channel notification state", err)
}

func (s *PostgresStorage) UpdateChannelState(channelID, title, categoryName string, now time.Time) (bool, bool, bool, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	if strings.TrimSpace(channelID) == "" {
		return false, false, false, errors.New("channel id is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, false, false, fmtDatabase("begin update channel notification state", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var previousTitle, previousCategory string
	err = tx.QueryRow(ctx,
		"SELECT title, category_name FROM channel_notification_states WHERE channel_id = $1 FOR UPDATE", channelID,
	).Scan(&previousTitle, &previousCategory)
	initialized := false
	if errors.Is(err, pgx.ErrNoRows) {
		initialized = true
	} else if err != nil {
		return false, false, false, fmtDatabase("load channel notification state", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO channel_notification_states(channel_id, title, category_name, updated_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (channel_id) DO UPDATE SET
			title = EXCLUDED.title, category_name = EXCLUDED.category_name, updated_at = EXCLUDED.updated_at`,
		channelID, title, categoryName, now); err != nil {
		return false, false, false, fmtDatabase("save channel notification state", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, false, false, fmtDatabase("commit channel notification state", err)
	}
	return !initialized && previousTitle != title, !initialized && previousCategory != categoryName, initialized, nil
}

func (s *PostgresStorage) Cleanup(now time.Time) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin storage cleanup", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := cleanupDeliveriesTx(ctx, tx, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE eventsub_inbox SET status = 'dead', last_error = 'EventSub inbox item expired before processing'
		WHERE expires_at <= $1 AND status <> 'dead'`, now); err != nil {
		return fmtDatabase("expire EventSub inbox records", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM eventsub_inbox WHERE status = 'dead' AND received_at < $1`, now.Add(-7*24*time.Hour)); err != nil {
		return fmtDatabase("delete old EventSub inbox records", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM eventsub_seen WHERE seen_at < $1", now.Add(-24*time.Hour)); err != nil {
		return fmtDatabase("delete old EventSub deduplication records", err)
	}
	return commitDatabaseTx(ctx, tx, "storage cleanup")
}

func cleanupDeliveriesTx(ctx context.Context, tx pgx.Tx, now time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE deliveries SET status = 'dead'
		WHERE expires_at <= $1 AND status <> 'acked'`, now); err != nil {
		return fmtDatabase("expire deliveries", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM deliveries
		WHERE (status = 'acked' AND acked_at < $1)
		   OR (status = 'dead' AND created_at < $1)`, now.Add(-7*24*time.Hour)); err != nil {
		return fmtDatabase("delete old deliveries", err)
	}
	return nil
}

func scanDelivery(scanner databaseScanner) (DeliveryRecord, error) {
	var record DeliveryRecord
	var sentAt, ackedAt *time.Time
	err := scanner.Scan(
		&record.ID, &record.EventID, &record.InstallationID,
		&record.Notification.Type, &record.Notification.Title, &record.Notification.Body,
		&record.Notification.ChannelID, &record.Notification.ChannelLogin, &record.Notification.MessageID,
		&record.Notification.ActorID, &record.Notification.ActorLogin, &record.Notification.ActorDisplayName,
		&record.Notification.Destination, &record.Notification.Silent, &record.Notification.CreatedAtEpochMillis,
		&record.Status, &record.AttemptCount, &record.AvailableAt, &record.ExpiresAt, &record.CreatedAt,
		&sentAt, &ackedAt, &record.LastError,
	)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if sentAt != nil {
		record.SentAt = sentAt.UTC()
	}
	if ackedAt != nil {
		record.AckedAt = ackedAt.UTC()
	}
	return record, nil
}

func scanEventSubInbox(scanner databaseScanner) (EventSubInboxRecord, error) {
	var record EventSubInboxRecord
	var condition, event []byte
	var lastAttemptAt *time.Time
	err := scanner.Scan(
		&record.MessageID, &record.Envelope.Challenge,
		&record.Envelope.Subscription.ID, &record.Envelope.Subscription.Type,
		&record.Envelope.Subscription.Version, &record.Envelope.Subscription.Status,
		&condition, &event,
		&record.Status, &record.AttemptCount, &record.AvailableAt, &record.ExpiresAt,
		&record.ReceivedAt, &lastAttemptAt, &record.LastError,
	)
	if err != nil {
		return EventSubInboxRecord{}, err
	}
	if err := json.Unmarshal(condition, &record.Envelope.Subscription.Condition); err != nil {
		return EventSubInboxRecord{}, err
	}
	if err := json.Unmarshal(event, &record.Envelope.Event); err != nil {
		return EventSubInboxRecord{}, err
	}
	if lastAttemptAt != nil {
		record.LastAttemptAt = lastAttemptAt.UTC()
	}
	return record, nil
}
