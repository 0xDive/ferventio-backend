package postgres

import (
	"errors"
	"fmt"
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

const registrationColumns = `
    installation_id, device_secret_hash, provider, firebase_installation_id,
    endpoint, p256dh, auth, app_version, platform, user_id, user_login,
    channel_ids, moderator_channel_ids, notification_rules, highlight_phrases,
    selected_user_logins, updated_at`

func (s *PostgresStorage) Upsert(registration Registration) error {
	if strings.TrimSpace(registration.InstallationID) == "" || registration.DeviceSecret == "" {
		return ErrSecretMismatch
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin registration upsert", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingHash string
	err = tx.QueryRow(ctx,
		"SELECT device_secret_hash FROM push_registrations WHERE installation_id = $1 FOR UPDATE",
		registration.InstallationID,
	).Scan(&existingHash)
	switch {
	case err == nil && !SecureHashEqual(existingHash, HashSecret(registration.DeviceSecret)):
		return ErrSecretMismatch
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return fmtDatabase("load registration for upsert", err)
	}

	registration.DeviceSecretHash = HashSecret(registration.DeviceSecret)
	registration.DeviceSecret = ""
	_, err = tx.Exec(ctx, `
        INSERT INTO push_registrations (
            installation_id, device_secret_hash, provider, firebase_installation_id,
            endpoint, p256dh, auth, app_version, platform, user_id, user_login,
            channel_ids, moderator_channel_ids, notification_rules, highlight_phrases,
            selected_user_logins, updated_at
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
        )
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
		registration.InstallationID,
		registration.DeviceSecretHash,
		registration.Provider,
		registration.FirebaseInstallation,
		registration.Endpoint,
		registration.P256DH,
		registration.Auth,
		registration.AppVersion,
		registration.Platform,
		registration.UserID,
		registration.UserLogin,
		nonNilStrings(registration.ChannelIDs),
		nonNilStrings(registration.ModeratorChannelIDs),
		nonNilStrings(registration.NotificationRules),
		nonNilStrings(registration.HighlightPhrases),
		nonNilStrings(registration.SelectedUserLogins),
		registration.UpdatedAt,
	)
	if err != nil {
		return fmtDatabase("upsert registration", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmtDatabase("commit registration upsert", err)
	}
	return nil
}

func (s *PostgresStorage) List() []Registration {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	rows, err := s.pool.Query(ctx, "SELECT "+registrationColumns+" FROM push_registrations ORDER BY installation_id")
	if err != nil {
		slog.Error("list PostgreSQL registrations", "error", err)
		return nil
	}
	defer rows.Close()
	result := make([]Registration, 0)
	for rows.Next() {
		registration, err := scanRegistration(rows)
		if err != nil {
			slog.Error("scan PostgreSQL registration", "error", err)
			return nil
		}
		result = append(result, publicRegistration(registration))
	}
	if err := rows.Err(); err != nil {
		slog.Error("iterate PostgreSQL registrations", "error", err)
		return nil
	}
	return result
}

func (s *PostgresStorage) Get(installationID string) (Registration, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	registration, err := scanRegistration(s.pool.QueryRow(ctx,
		"SELECT "+registrationColumns+" FROM push_registrations WHERE installation_id = $1",
		installationID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Registration{}, ErrNotFound
	}
	if err != nil {
		return Registration{}, fmtDatabase("get registration", err)
	}
	return publicRegistration(registration), nil
}

func (s *PostgresStorage) Authenticate(installationID, deviceSecret string) (Registration, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	registration, err := scanRegistration(s.pool.QueryRow(ctx,
		"SELECT "+registrationColumns+" FROM push_registrations WHERE installation_id = $1",
		installationID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Registration{}, ErrNotFound
	}
	if err != nil {
		return Registration{}, fmtDatabase("authenticate registration", err)
	}
	if !SecureHashEqual(registration.DeviceSecretHash, HashSecret(deviceSecret)) {
		return Registration{}, ErrSecretMismatch
	}
	return publicRegistration(registration), nil
}

func (s *PostgresStorage) Delete(installationID, deviceSecret string) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	var secretHash string
	err := s.pool.QueryRow(ctx,
		"SELECT device_secret_hash FROM push_registrations WHERE installation_id = $1",
		installationID,
	).Scan(&secretHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmtDatabase("load registration for delete", err)
	}
	if !SecureHashEqual(secretHash, HashSecret(deviceSecret)) {
		return ErrSecretMismatch
	}
	tag, err := s.pool.Exec(ctx,
		"DELETE FROM push_registrations WHERE installation_id = $1 AND device_secret_hash = $2",
		installationID, secretHash,
	)
	if err != nil {
		return fmtDatabase("delete registration", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) DeleteForAccount(userID string, installationIDs []string) ([]string, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	userID = strings.TrimSpace(userID)
	installationIDs = compactStrings(installationIDs)
	rows, err := s.pool.Query(ctx, `
        DELETE FROM push_registrations
        WHERE ($1 <> '' AND user_id = $1)
           OR installation_id = ANY($2::text[])
        RETURNING installation_id`, userID, installationIDs)
	if err != nil {
		return nil, fmtDatabase("delete registrations for account", err)
	}
	defer rows.Close()
	removed := make([]string, 0)
	for rows.Next() {
		var installationID string
		if err := rows.Scan(&installationID); err != nil {
			return nil, fmtDatabase("scan deleted registration", err)
		}
		removed = append(removed, installationID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmtDatabase("iterate deleted registrations", err)
	}
	sort.Strings(removed)
	return removed, nil
}

type registrationScanner interface {
	Scan(dest ...any) error
}

func scanRegistration(scanner registrationScanner) (Registration, error) {
	var registration Registration
	err := scanner.Scan(
		&registration.InstallationID,
		&registration.DeviceSecretHash,
		&registration.Provider,
		&registration.FirebaseInstallation,
		&registration.Endpoint,
		&registration.P256DH,
		&registration.Auth,
		&registration.AppVersion,
		&registration.Platform,
		&registration.UserID,
		&registration.UserLogin,
		&registration.ChannelIDs,
		&registration.ModeratorChannelIDs,
		&registration.NotificationRules,
		&registration.HighlightPhrases,
		&registration.SelectedUserLogins,
		&registration.UpdatedAt,
	)
	return registration, err
}

func publicRegistration(registration Registration) Registration {
	registration.DeviceSecret = ""
	registration.DeviceSecretHash = ""
	registration.ChannelIDs = append([]string(nil), registration.ChannelIDs...)
	registration.ModeratorChannelIDs = append([]string(nil), registration.ModeratorChannelIDs...)
	registration.NotificationRules = append([]string(nil), registration.NotificationRules...)
	registration.HighlightPhrases = append([]string(nil), registration.HighlightPhrases...)
	registration.SelectedUserLogins = append([]string(nil), registration.SelectedUserLogins...)
	return registration
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func fmtDatabase(operation string, err error) error {
	return fmt.Errorf("%s: %w", operation, err)
}
