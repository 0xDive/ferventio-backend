package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LegacyImportReport summarizes a one-time import from the pre-PostgreSQL backend.
type LegacyImportReport struct {
	Registrations     int `json:"registrations"`
	Credentials       int `json:"credentials"`
	Sessions          int `json:"sessions"`
	PendingAuth       int `json:"pendingAuth"`
	Handoffs          int `json:"handoffs"`
	Deliveries        int `json:"deliveries"`
	EventSubSeen      int `json:"eventSubSeen"`
	EventSubInbox     int `json:"eventSubInbox"`
	ChannelStates     int `json:"channelStates"`
	AuditRecords      int `json:"auditRecords"`
	SettingsSnapshots int `json:"settingsSnapshots"`
}

// ImportLegacyState imports the five JSON state files used by older versions.
// The operation is idempotent: stable primary keys are upserted or ignored.
func ImportLegacyState(ctx context.Context, storage *PostgresStorage, directory string) (LegacyImportReport, error) {
	if storage == nil || storage.pool == nil {
		return LegacyImportReport{}, errors.New("PostgreSQL storage is not initialized")
	}
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return LegacyImportReport{}, errors.New("legacy state directory is required")
	}
	tx, err := storage.pool.Begin(ctx)
	if err != nil {
		return LegacyImportReport{}, fmtDatabase("begin legacy state import", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var report LegacyImportReport
	if err := importLegacyRegistrations(ctx, tx, filepath.Join(directory, "registrations.json"), &report); err != nil {
		return LegacyImportReport{}, err
	}
	if err := importLegacyAuth(ctx, tx, storage, filepath.Join(directory, "auth.json"), &report); err != nil {
		return LegacyImportReport{}, err
	}
	if err := importLegacyDeliveries(ctx, tx, filepath.Join(directory, "deliveries.json"), &report); err != nil {
		return LegacyImportReport{}, err
	}
	if err := importLegacyAudit(ctx, tx, filepath.Join(directory, "audit.json"), &report); err != nil {
		return LegacyImportReport{}, err
	}
	if err := importLegacySettings(ctx, tx, filepath.Join(directory, "settings-sync.json"), &report); err != nil {
		return LegacyImportReport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LegacyImportReport{}, fmtDatabase("commit legacy state import", err)
	}
	return report, nil
}

func importLegacyRegistrations(ctx context.Context, tx databaseExecutor, path string, report *LegacyImportReport) error {
	var registrations map[string]Registration
	found, err := readLegacyJSON(path, &registrations)
	if err != nil || !found {
		return err
	}
	keys := sortedMapKeys(registrations)
	for _, key := range keys {
		registration := registrations[key]
		if registration.InstallationID == "" {
			registration.InstallationID = key
		}
		if registration.DeviceSecretHash == "" && registration.DeviceSecret != "" {
			registration.DeviceSecretHash = HashSecret(registration.DeviceSecret)
		}
		if registration.DeviceSecretHash == "" {
			return fmt.Errorf("legacy registration %q has no device secret", registration.InstallationID)
		}
		if registration.UpdatedAt.IsZero() {
			registration.UpdatedAt = time.Now().UTC()
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO push_registrations (
				installation_id, device_secret_hash, provider, firebase_installation_id,
				endpoint, p256dh, auth, app_version, platform, user_id, user_login,
				channel_ids, moderator_channel_ids, notification_rules, highlight_phrases,
				selected_user_logins, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
			ON CONFLICT (installation_id) DO UPDATE SET
				device_secret_hash = EXCLUDED.device_secret_hash,
				provider = EXCLUDED.provider,
				firebase_installation_id = EXCLUDED.firebase_installation_id,
				endpoint = EXCLUDED.endpoint,
				p256dh = EXCLUDED.p256dh,
				auth = EXCLUDED.auth,
				app_version = EXCLUDED.app_version,
				platform = EXCLUDED.platform,
				user_id = EXCLUDED.user_id,
				user_login = EXCLUDED.user_login,
				channel_ids = EXCLUDED.channel_ids,
				moderator_channel_ids = EXCLUDED.moderator_channel_ids,
				notification_rules = EXCLUDED.notification_rules,
				highlight_phrases = EXCLUDED.highlight_phrases,
				selected_user_logins = EXCLUDED.selected_user_logins,
				updated_at = EXCLUDED.updated_at`,
			registration.InstallationID, registration.DeviceSecretHash, registration.Provider,
			registration.FirebaseInstallation, registration.Endpoint, registration.P256DH,
			registration.Auth, registration.AppVersion, registration.Platform,
			registration.UserID, registration.UserLogin, nonNilStrings(registration.ChannelIDs),
			nonNilStrings(registration.ModeratorChannelIDs), nonNilStrings(registration.NotificationRules),
			nonNilStrings(registration.HighlightPhrases), nonNilStrings(registration.SelectedUserLogins),
			registration.UpdatedAt,
		)
		if err != nil {
			return fmtDatabase("import legacy registration", err)
		}
		report.Registrations++
	}
	return nil
}

func importLegacyAuth(ctx context.Context, tx databaseExecutor, storage *PostgresStorage, path string, report *LegacyImportReport) error {
	var state AuthDiskState
	found, err := readLegacyJSON(path, &state)
	if err != nil || !found {
		return err
	}
	if len(state.Credentials) > 0 && storage.aead == nil {
		return errors.New("AUTH_ENCRYPTION_KEY is required to import legacy OAuth credentials")
	}
	for _, id := range sortedMapKeys(state.Credentials) {
		record := state.Credentials[id]
		if record.ID == "" {
			record.ID = id
		}
		if _, err := OpenAuthValue(storage.aead, record.ID+":access", record.AccessToken); err != nil {
			return fmt.Errorf("validate legacy credential %q: %w", record.ID, err)
		}
		if _, err := OpenAuthValue(storage.aead, record.ID+":refresh", record.RefreshToken); err != nil {
			return fmt.Errorf("validate legacy credential %q: %w", record.ID, err)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO auth_credentials (
				id, client_id, user_id, login, scopes,
				access_nonce, access_ciphertext, refresh_nonce, refresh_ciphertext,
				access_expires_at, last_validated_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (id) DO UPDATE SET
				client_id = EXCLUDED.client_id, user_id = EXCLUDED.user_id,
				login = EXCLUDED.login, scopes = EXCLUDED.scopes,
				access_nonce = EXCLUDED.access_nonce, access_ciphertext = EXCLUDED.access_ciphertext,
				refresh_nonce = EXCLUDED.refresh_nonce, refresh_ciphertext = EXCLUDED.refresh_ciphertext,
				access_expires_at = EXCLUDED.access_expires_at,
				last_validated_at = EXCLUDED.last_validated_at, updated_at = EXCLUDED.updated_at`,
			record.ID, record.ClientID, record.UserID, record.Login, nonNilStrings(record.Scopes),
			record.AccessToken.Nonce, record.AccessToken.Ciphertext,
			record.RefreshToken.Nonce, record.RefreshToken.Ciphertext,
			record.AccessExpiresAt, record.LastValidatedAt, record.UpdatedAt,
		)
		if err != nil {
			return fmtDatabase("import legacy auth credential", err)
		}
		report.Credentials++
	}
	for tokenHash, record := range state.Sessions {
		_, err := tx.Exec(ctx, `
			INSERT INTO auth_sessions(token_hash, credential_id, installation_id, device_hash, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (token_hash) DO UPDATE SET
				credential_id = EXCLUDED.credential_id, installation_id = EXCLUDED.installation_id,
				device_hash = EXCLUDED.device_hash, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`,
			tokenHash, record.CredentialID, record.InstallationID, record.DeviceHash,
			record.CreatedAt, record.ExpiresAt,
		)
		if err != nil {
			return fmtDatabase("import legacy auth session", err)
		}
		report.Sessions++
	}
	for stateHash, record := range state.Pending {
		_, err := tx.Exec(ctx, `
			INSERT INTO auth_pending(state_hash, installation_id, device_hash, app_callback_uri, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (state_hash) DO UPDATE SET
				installation_id = EXCLUDED.installation_id, device_hash = EXCLUDED.device_hash,
				app_callback_uri = EXCLUDED.app_callback_uri, created_at = EXCLUDED.created_at,
				expires_at = EXCLUDED.expires_at`,
			stateHash, record.InstallationID, record.DeviceHash, record.AppCallbackURI,
			record.CreatedAt, record.ExpiresAt,
		)
		if err != nil {
			return fmtDatabase("import legacy pending auth", err)
		}
		report.PendingAuth++
	}
	for codeHash, record := range state.Handoffs {
		_, err := tx.Exec(ctx, `
			INSERT INTO auth_handoffs(
				code_hash, credential_id, installation_id, device_hash,
				app_callback_uri, state_hash, created_at, expires_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (code_hash) DO UPDATE SET
				credential_id = EXCLUDED.credential_id, installation_id = EXCLUDED.installation_id,
				device_hash = EXCLUDED.device_hash, app_callback_uri = EXCLUDED.app_callback_uri,
				state_hash = EXCLUDED.state_hash, created_at = EXCLUDED.created_at,
				expires_at = EXCLUDED.expires_at`,
			codeHash, record.CredentialID, record.InstallationID, record.DeviceHash,
			record.AppCallbackURI, record.StateHash, record.CreatedAt, record.ExpiresAt,
		)
		if err != nil {
			return fmtDatabase("import legacy auth handoff", err)
		}
		report.Handoffs++
	}
	return nil
}

func importLegacyDeliveries(ctx context.Context, tx databaseExecutor, path string, report *LegacyImportReport) error {
	var state DeliveryDiskState
	found, err := readLegacyJSON(path, &state)
	if err != nil || !found {
		return err
	}
	for _, id := range sortedMapKeys(state.Records) {
		record := state.Records[id]
		if record.ID == "" {
			record.ID = id
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO deliveries (`+deliveryColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
			ON CONFLICT (id) DO UPDATE SET
				event_id = EXCLUDED.event_id, installation_id = EXCLUDED.installation_id,
				notification_type = EXCLUDED.notification_type, notification_title = EXCLUDED.notification_title,
				notification_body = EXCLUDED.notification_body,
				notification_channel_id = EXCLUDED.notification_channel_id,
				notification_channel_login = EXCLUDED.notification_channel_login,
				notification_message_id = EXCLUDED.notification_message_id,
				notification_actor_id = EXCLUDED.notification_actor_id,
				notification_actor_login = EXCLUDED.notification_actor_login,
				notification_actor_display_name = EXCLUDED.notification_actor_display_name,
				notification_destination = EXCLUDED.notification_destination,
				notification_silent = EXCLUDED.notification_silent,
				notification_created_at_epoch_millis = EXCLUDED.notification_created_at_epoch_millis,
				status = EXCLUDED.status, attempt_count = EXCLUDED.attempt_count,
				available_at = EXCLUDED.available_at, expires_at = EXCLUDED.expires_at,
				created_at = EXCLUDED.created_at, sent_at = EXCLUDED.sent_at,
				acked_at = EXCLUDED.acked_at, last_error = EXCLUDED.last_error`,
			record.ID, record.EventID, record.InstallationID,
			record.Notification.Type, record.Notification.Title, record.Notification.Body,
			record.Notification.ChannelID, record.Notification.ChannelLogin, record.Notification.MessageID,
			record.Notification.ActorID, record.Notification.ActorLogin, record.Notification.ActorDisplayName,
			record.Notification.Destination, record.Notification.Silent, record.Notification.CreatedAtEpochMillis,
			record.Status, record.AttemptCount, record.AvailableAt, record.ExpiresAt, record.CreatedAt,
			nullableTime(record.SentAt), nullableTime(record.AckedAt), record.LastError,
		)
		if err != nil {
			return fmtDatabase("import legacy delivery", err)
		}
		report.Deliveries++
	}
	for messageID, seenAt := range state.Seen {
		if _, err := tx.Exec(ctx, `
			INSERT INTO eventsub_seen(message_id, seen_at) VALUES ($1,$2)
			ON CONFLICT (message_id) DO UPDATE SET seen_at = EXCLUDED.seen_at`, messageID, seenAt); err != nil {
			return fmtDatabase("import legacy EventSub seen record", err)
		}
		report.EventSubSeen++
	}
	for messageID, record := range state.EventSubInbox {
		condition, err := json.Marshal(record.Envelope.Subscription.Condition)
		if err != nil {
			return err
		}
		event, err := json.Marshal(record.Envelope.Event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO eventsub_inbox (
				message_id, challenge, subscription_id, subscription_type, subscription_version,
				subscription_status, subscription_condition, event_payload,
				status, attempt_count, available_at, expires_at, received_at, last_attempt_at, last_error
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (message_id) DO UPDATE SET
				challenge = EXCLUDED.challenge, subscription_id = EXCLUDED.subscription_id,
				subscription_type = EXCLUDED.subscription_type,
				subscription_version = EXCLUDED.subscription_version,
				subscription_status = EXCLUDED.subscription_status,
				subscription_condition = EXCLUDED.subscription_condition,
				event_payload = EXCLUDED.event_payload, status = EXCLUDED.status,
				attempt_count = EXCLUDED.attempt_count, available_at = EXCLUDED.available_at,
				expires_at = EXCLUDED.expires_at, received_at = EXCLUDED.received_at,
				last_attempt_at = EXCLUDED.last_attempt_at, last_error = EXCLUDED.last_error`,
			messageID, record.Envelope.Challenge, record.Envelope.Subscription.ID,
			record.Envelope.Subscription.Type, record.Envelope.Subscription.Version,
			record.Envelope.Subscription.Status, condition, event, record.Status,
			record.AttemptCount, record.AvailableAt, record.ExpiresAt, record.ReceivedAt,
			nullableTime(record.LastAttemptAt), record.LastError,
		); err != nil {
			return fmtDatabase("import legacy EventSub inbox record", err)
		}
		report.EventSubInbox++
	}
	for channelID, state := range state.ChannelStates {
		if _, err := tx.Exec(ctx, `
			INSERT INTO channel_notification_states(channel_id, title, category_name, updated_at)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (channel_id) DO UPDATE SET
				title = EXCLUDED.title, category_name = EXCLUDED.category_name,
				updated_at = EXCLUDED.updated_at`,
			channelID, state.Title, state.CategoryName, state.UpdatedAt,
		); err != nil {
			return fmtDatabase("import legacy channel state", err)
		}
		report.ChannelStates++
	}
	return nil
}

func importLegacyAudit(ctx context.Context, tx databaseExecutor, path string, report *LegacyImportReport) error {
	var state AuditDiskState
	found, err := readLegacyJSON(path, &state)
	if err != nil || !found {
		return err
	}
	for _, record := range state.Records {
		if record.ID == "" {
			record.ID, err = RandomToken("audit_", 12)
			if err != nil {
				return err
			}
		}
		if record.Timestamp.IsZero() {
			record.Timestamp = time.Now().UTC()
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_records(
				id, timestamp, action, status, installation_id,
				user_id, channel_id, event_id, detail
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (id) DO NOTHING`,
			record.ID, record.Timestamp, record.Action, record.Status,
			record.InstallationID, record.UserID, record.ChannelID,
			record.EventID, record.Detail,
		); err != nil {
			return fmtDatabase("import legacy audit record", err)
		}
		report.AuditRecords++
	}
	return nil
}

func importLegacySettings(ctx context.Context, tx databaseExecutor, path string, report *LegacyImportReport) error {
	var state SettingsSyncDiskState
	found, err := readLegacyJSON(path, &state)
	if err != nil || !found {
		return err
	}
	for userID, userState := range state.Users {
		snapshots := append([]SettingsSyncSnapshot(nil), userState.History...)
		if userState.Current != nil {
			snapshots = append(snapshots, *userState.Current)
		}
		sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].Revision < snapshots[j].Revision })
		seen := make(map[int64]struct{}, len(snapshots))
		for _, snapshot := range snapshots {
			if _, duplicate := seen[snapshot.Revision]; duplicate {
				continue
			}
			seen[snapshot.Revision] = struct{}{}
			if !json.Valid(snapshot.Payload) {
				return fmt.Errorf("legacy settings payload for user %q revision %d is invalid JSON", userID, snapshot.Revision)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO settings_sync_snapshots(
					user_id, revision, updated_at, updated_by_installation_id,
					app_version, content_hash, payload
				) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
				ON CONFLICT (user_id, revision) DO UPDATE SET
					updated_at = EXCLUDED.updated_at,
					updated_by_installation_id = EXCLUDED.updated_by_installation_id,
					app_version = EXCLUDED.app_version,
					content_hash = EXCLUDED.content_hash,
					payload = EXCLUDED.payload`,
				userID, snapshot.Revision, snapshot.UpdatedAt,
				snapshot.UpdatedByInstallationID, snapshot.AppVersion,
				snapshot.ContentHash, []byte(snapshot.Payload),
			); err != nil {
				return fmtDatabase("import legacy settings snapshot", err)
			}
			report.SettingsSnapshots++
		}
	}
	return nil
}

func readLegacyJSON(path string, target any) (bool, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read legacy state %q: %w", path, err)
	}
	if len(strings.TrimSpace(string(contents))) == 0 {
		return true, nil
	}
	if err := json.Unmarshal(contents, target); err != nil {
		return false, fmt.Errorf("decode legacy state %q: %w", path, err)
	}
	return true, nil
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
