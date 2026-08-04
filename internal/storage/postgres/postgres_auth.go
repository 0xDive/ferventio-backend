package postgres

import (
	"context"
	"errors"
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const AuthCredentialColumns = `
    id, client_id, user_id, login, scopes,
    access_nonce, access_ciphertext, refresh_nonce, refresh_ciphertext,
    access_expires_at, last_validated_at, updated_at`

func (s *PostgresStorage) PutPending(state string, record PendingAuthRecord) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin pending auth transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, "DELETE FROM auth_pending WHERE expires_at < $1", now); err != nil {
		return fmtDatabase("clean expired pending auth", err)
	}
	if _, err := tx.Exec(ctx,
		"DELETE FROM auth_pending WHERE installation_id = $1 AND device_hash = $2",
		record.InstallationID, record.DeviceHash,
	); err != nil {
		return fmtDatabase("replace pending auth", err)
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM auth_pending").Scan(&count); err != nil {
		return fmtDatabase("count pending auth", err)
	}
	if count >= MaxPendingAuthRecords {
		return ErrAuthCapacity
	}
	_, err = tx.Exec(ctx, `
        INSERT INTO auth_pending (
            state_hash, installation_id, device_hash, app_callback_uri, created_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6)`,
		HashSecret(state), record.InstallationID, record.DeviceHash, record.AppCallbackURI,
		record.CreatedAt, record.ExpiresAt,
	)
	if err != nil {
		return fmtDatabase("insert pending auth", err)
	}
	return commitDatabaseTx(ctx, tx, "pending auth")
}

func (s *PostgresStorage) GetPending(state string) (PendingAuthRecord, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	record, err := scanPendingAuth(s.pool.QueryRow(ctx, `
        SELECT installation_id, device_hash, app_callback_uri, created_at, expires_at
        FROM auth_pending WHERE state_hash = $1`, HashSecret(state)))
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingAuthRecord{}, ErrAuthNotFound
	}
	if err != nil {
		return PendingAuthRecord{}, fmtDatabase("get pending auth", err)
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return PendingAuthRecord{}, ErrAuthExpired
	}
	return record, nil
}

func (s *PostgresStorage) ConsumePending(state string) (PendingAuthRecord, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	record, err := scanPendingAuth(s.pool.QueryRow(ctx, `
        DELETE FROM auth_pending WHERE state_hash = $1
        RETURNING installation_id, device_hash, app_callback_uri, created_at, expires_at`,
		HashSecret(state),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingAuthRecord{}, ErrAuthNotFound
	}
	if err != nil {
		return PendingAuthRecord{}, fmtDatabase("consume pending auth", err)
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return PendingAuthRecord{}, ErrAuthExpired
	}
	return record, nil
}

func (s *PostgresStorage) PutHandoff(code string, record AuthHandoffRecord) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin auth handoff transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.putHandoffTx(ctx, tx, code, record); err != nil {
		return err
	}
	return commitDatabaseTx(ctx, tx, "auth handoff")
}

func (s *PostgresStorage) ConsumeHandoff(code, installationID, deviceSecret, state string) (AuthHandoffRecord, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AuthHandoffRecord{}, fmtDatabase("begin consume handoff transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	record, err := scanAuthHandoff(tx.QueryRow(ctx, `
        SELECT credential_id, installation_id, device_hash, app_callback_uri, state_hash, created_at, expires_at
        FROM auth_handoffs WHERE code_hash = $1 FOR UPDATE`, HashSecret(code)))
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthHandoffRecord{}, ErrAuthNotFound
	}
	if err != nil {
		return AuthHandoffRecord{}, fmtDatabase("load auth handoff", err)
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		_, _ = tx.Exec(ctx, "DELETE FROM auth_handoffs WHERE code_hash = $1", HashSecret(code))
		if err := tx.Commit(ctx); err != nil {
			return AuthHandoffRecord{}, fmtDatabase("commit expired handoff delete", err)
		}
		return AuthHandoffRecord{}, ErrAuthExpired
	}
	if record.InstallationID != installationID || !SecureHashEqual(record.DeviceHash, HashSecret(deviceSecret)) {
		return AuthHandoffRecord{}, ErrAuthDeviceMismatch
	}
	if !SecureHashEqual(record.StateHash, HashSecret(state)) {
		return AuthHandoffRecord{}, ErrAuthStateMismatch
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth_handoffs WHERE code_hash = $1", HashSecret(code)); err != nil {
		return AuthHandoffRecord{}, fmtDatabase("delete consumed handoff", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthHandoffRecord{}, fmtDatabase("commit consumed handoff", err)
	}
	return record, nil
}

func (s *PostgresStorage) PutCredential(credential AuthCredential) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	return s.putCredential(ctx, s.pool, credential)
}

func (s *PostgresStorage) PutCredentialAndHandoff(
	credential AuthCredential,
	code string,
	record AuthHandoffRecord,
) error {
	if credential.ID == "" || record.CredentialID != credential.ID {
		return errors.New("credential and handoff do not match")
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin credential and handoff transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.putCredential(ctx, tx, credential); err != nil {
		return err
	}
	if err := s.putHandoffTx(ctx, tx, code, record); err != nil {
		return err
	}
	return commitDatabaseTx(ctx, tx, "credential and handoff")
}

func (s *PostgresStorage) putCredential(ctx context.Context, query databaseExecutor, credential AuthCredential) error {
	access, err := SealAuthValue(s.aead, credential.ID+":access", credential.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := SealAuthValue(s.aead, credential.ID+":refresh", credential.RefreshToken)
	if err != nil {
		return err
	}
	_, err = query.Exec(ctx, `
        INSERT INTO auth_credentials (
            id, client_id, user_id, login, scopes,
            access_nonce, access_ciphertext, refresh_nonce, refresh_ciphertext,
            access_expires_at, last_validated_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (id) DO UPDATE SET
            client_id = EXCLUDED.client_id,
            user_id = EXCLUDED.user_id,
            login = EXCLUDED.login,
            scopes = EXCLUDED.scopes,
            access_nonce = EXCLUDED.access_nonce,
            access_ciphertext = EXCLUDED.access_ciphertext,
            refresh_nonce = EXCLUDED.refresh_nonce,
            refresh_ciphertext = EXCLUDED.refresh_ciphertext,
            access_expires_at = EXCLUDED.access_expires_at,
            last_validated_at = EXCLUDED.last_validated_at,
            updated_at = EXCLUDED.updated_at`,
		credential.ID, credential.ClientID, credential.UserID, credential.Login,
		nonNilStrings(credential.Scopes), access.Nonce, access.Ciphertext,
		refresh.Nonce, refresh.Ciphertext, credential.AccessExpiresAt,
		credential.LastValidatedAt, credential.UpdatedAt,
	)
	if err != nil {
		return fmtDatabase("upsert auth credential", err)
	}
	return nil
}

func (s *PostgresStorage) putHandoffTx(
	ctx context.Context,
	tx pgx.Tx,
	code string,
	record AuthHandoffRecord,
) error {
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, "DELETE FROM auth_handoffs WHERE expires_at < $1", now); err != nil {
		return fmtDatabase("clean expired auth handoffs", err)
	}
	if _, err := tx.Exec(ctx,
		"DELETE FROM auth_handoffs WHERE installation_id = $1 AND device_hash = $2",
		record.InstallationID, record.DeviceHash,
	); err != nil {
		return fmtDatabase("replace auth handoff", err)
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM auth_handoffs").Scan(&count); err != nil {
		return fmtDatabase("count auth handoffs", err)
	}
	if count >= MaxAuthHandoffs {
		return ErrAuthCapacity
	}
	_, err := tx.Exec(ctx, `
        INSERT INTO auth_handoffs (
            code_hash, credential_id, installation_id, device_hash,
            app_callback_uri, state_hash, created_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		HashSecret(code), record.CredentialID, record.InstallationID, record.DeviceHash,
		record.AppCallbackURI, record.StateHash, record.CreatedAt, record.ExpiresAt,
	)
	if err != nil {
		return fmtDatabase("insert auth handoff", err)
	}
	return nil
}

func (s *PostgresStorage) GetCredential(id string) (AuthCredential, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	return s.scanCredential(s.pool.QueryRow(ctx,
		"SELECT "+AuthCredentialColumns+" FROM auth_credentials WHERE id = $1", id,
	))
}

func (s *PostgresStorage) CredentialForInstallation(installationID, deviceSecret string) (AuthCredential, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	credential, err := s.scanCredential(s.pool.QueryRow(ctx, `
        SELECT `+prefixedCredentialColumns("c")+`
        FROM auth_sessions session
        JOIN auth_credentials c ON c.id = session.credential_id
        WHERE session.installation_id = $1
          AND session.device_hash = $2
          AND session.expires_at > $3
        ORDER BY session.expires_at DESC
        LIMIT 1`, installationID, HashSecret(deviceSecret), time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthCredential{}, ErrAuthNotFound
	}
	return credential, err
}

func (s *PostgresStorage) CreateSession(
	credentialID,
	installationID,
	deviceSecret string,
	ttl time.Duration,
) (string, time.Time, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, fmtDatabase("begin create auth session", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth_credentials WHERE id = $1)", credentialID,
	).Scan(&exists); err != nil {
		return "", time.Time{}, fmtDatabase("check auth credential", err)
	}
	if !exists {
		return "", time.Time{}, ErrAuthNotFound
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx,
		"DELETE FROM auth_sessions WHERE expires_at < $1 OR installation_id = $2",
		now, installationID,
	); err != nil {
		return "", time.Time{}, fmtDatabase("clean auth sessions", err)
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM auth_sessions").Scan(&count); err != nil {
		return "", time.Time{}, fmtDatabase("count auth sessions", err)
	}
	if count >= MaxAuthSessions {
		return "", time.Time{}, ErrAuthCapacity
	}
	token, err := RandomToken("fsv1_", 32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(ttl)
	_, err = tx.Exec(ctx, `
        INSERT INTO auth_sessions (
            token_hash, credential_id, installation_id, device_hash, created_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6)`,
		HashSecret(token), credentialID, installationID, HashSecret(deviceSecret), now, expiresAt,
	)
	if err != nil {
		return "", time.Time{}, fmtDatabase("insert auth session", err)
	}
	if err := deleteOrphanCredentials(ctx, tx); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, fmtDatabase("commit auth session", err)
	}
	return token, expiresAt, nil
}

func (s *PostgresStorage) ResolveSession(
	token,
	installationID,
	deviceSecret string,
	renewTTL time.Duration,
) (AuthSessionRecord, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AuthSessionRecord{}, fmtDatabase("begin resolve auth session", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tokenHash := HashSecret(token)
	record, err := scanAuthSession(tx.QueryRow(ctx, `
        SELECT credential_id, installation_id, device_hash, created_at, expires_at
        FROM auth_sessions WHERE token_hash = $1 FOR UPDATE`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthSessionRecord{}, ErrAuthNotFound
	}
	if err != nil {
		return AuthSessionRecord{}, fmtDatabase("load auth session", err)
	}
	now := time.Now().UTC()
	if now.After(record.ExpiresAt) {
		if _, err := tx.Exec(ctx, "DELETE FROM auth_sessions WHERE token_hash = $1", tokenHash); err != nil {
			return AuthSessionRecord{}, fmtDatabase("delete expired auth session", err)
		}
		if err := deleteCredentialIfUnusedTx(ctx, tx, record.CredentialID); err != nil {
			return AuthSessionRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AuthSessionRecord{}, fmtDatabase("commit expired auth session", err)
		}
		return AuthSessionRecord{}, ErrAuthExpired
	}
	if record.InstallationID != installationID || !SecureHashEqual(record.DeviceHash, HashSecret(deviceSecret)) {
		return AuthSessionRecord{}, ErrAuthDeviceMismatch
	}
	if renewTTL > 0 && record.ExpiresAt.Before(now.Add(renewTTL/2)) {
		record.ExpiresAt = now.Add(renewTTL)
		if _, err := tx.Exec(ctx,
			"UPDATE auth_sessions SET expires_at = $1 WHERE token_hash = $2",
			record.ExpiresAt, tokenHash,
		); err != nil {
			return AuthSessionRecord{}, fmtDatabase("renew auth session", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthSessionRecord{}, fmtDatabase("commit resolved auth session", err)
	}
	return record, nil
}

func (s *PostgresStorage) SessionAccount(token, installationID, deviceSecret string) (string, bool, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	var userID, storedInstallationID, deviceHash string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `
        SELECT c.user_id, session.installation_id, session.device_hash, session.expires_at
        FROM auth_sessions session
        JOIN auth_credentials c ON c.id = session.credential_id
        WHERE session.token_hash = $1`, HashSecret(token),
	).Scan(&userID, &storedInstallationID, &deviceHash, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrAuthNotFound
	}
	if err != nil {
		return "", false, fmtDatabase("resolve session account", err)
	}
	if storedInstallationID != installationID || !SecureHashEqual(deviceHash, HashSecret(deviceSecret)) {
		return "", false, ErrAuthDeviceMismatch
	}
	if strings.TrimSpace(userID) == "" {
		return "", false, ErrAuthNotFound
	}
	return userID, time.Now().UTC().After(expiresAt), nil
}

func (s *PostgresStorage) DeleteSession(token, installationID, deviceSecret string) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmtDatabase("begin delete auth session", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tokenHash := HashSecret(token)
	record, err := scanAuthSession(tx.QueryRow(ctx, `
        SELECT credential_id, installation_id, device_hash, created_at, expires_at
        FROM auth_sessions WHERE token_hash = $1 FOR UPDATE`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAuthNotFound
	}
	if err != nil {
		return fmtDatabase("load auth session for delete", err)
	}
	if record.InstallationID != installationID || !SecureHashEqual(record.DeviceHash, HashSecret(deviceSecret)) {
		return ErrAuthDeviceMismatch
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth_sessions WHERE token_hash = $1", tokenHash); err != nil {
		return fmtDatabase("delete auth session", err)
	}
	if err := deleteCredentialIfUnusedTx(ctx, tx, record.CredentialID); err != nil {
		return err
	}
	return commitDatabaseTx(ctx, tx, "delete auth session")
}

func (s *PostgresStorage) InstallationBinding(installationID, deviceSecret string) (bool, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	rows, err := s.pool.Query(ctx, `
        SELECT device_hash FROM auth_sessions WHERE installation_id = $1
        UNION ALL
        SELECT device_hash FROM auth_pending WHERE installation_id = $1
        UNION ALL
        SELECT device_hash FROM auth_handoffs WHERE installation_id = $1`, installationID)
	if err != nil {
		return false, fmtDatabase("load installation auth binding", err)
	}
	defer rows.Close()
	found := false
	expected := HashSecret(deviceSecret)
	for rows.Next() {
		found = true
		var deviceHash string
		if err := rows.Scan(&deviceHash); err != nil {
			return false, fmtDatabase("scan installation auth binding", err)
		}
		if SecureHashEqual(deviceHash, expected) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmtDatabase("iterate installation auth binding", err)
	}
	if found {
		return false, ErrAuthDeviceMismatch
	}
	return false, ErrAuthNotFound
}

func (s *PostgresStorage) RevokeInstallation(installationID, deviceSecret string) (int, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmtDatabase("begin revoke installation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
        SELECT device_hash FROM (
            SELECT device_hash FROM auth_sessions WHERE installation_id = $1
            UNION ALL
            SELECT device_hash FROM auth_pending WHERE installation_id = $1
            UNION ALL
            SELECT device_hash FROM auth_handoffs WHERE installation_id = $1
        ) AS installation_artifacts`, installationID)
	if err != nil {
		return 0, fmtDatabase("lock installation auth artifacts", err)
	}
	expected := HashSecret(deviceSecret)
	found := false
	for rows.Next() {
		found = true
		var deviceHash string
		if err := rows.Scan(&deviceHash); err != nil {
			rows.Close()
			return 0, fmtDatabase("scan installation auth artifact", err)
		}
		if !SecureHashEqual(deviceHash, expected) {
			rows.Close()
			return 0, ErrAuthDeviceMismatch
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmtDatabase("iterate installation auth artifacts", err)
	}
	if !found {
		return 0, nil
	}
	var removedSessions int
	if err := tx.QueryRow(ctx, `
        WITH deleted AS (
            DELETE FROM auth_sessions WHERE installation_id = $1 RETURNING 1
        ) SELECT count(*) FROM deleted`, installationID,
	).Scan(&removedSessions); err != nil {
		return 0, fmtDatabase("delete installation auth sessions", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth_pending WHERE installation_id = $1", installationID); err != nil {
		return 0, fmtDatabase("delete installation pending auth", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth_handoffs WHERE installation_id = $1", installationID); err != nil {
		return 0, fmtDatabase("delete installation auth handoffs", err)
	}
	if err := deleteOrphanCredentials(ctx, tx); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmtDatabase("commit installation revocation", err)
	}
	return removedSessions, nil
}

func (s *PostgresStorage) AccountRevocationTargets(userID string) (AccountRevocationTargets, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return AccountRevocationTargets{}, ErrAuthNotFound
	}
	rows, err := s.pool.Query(ctx,
		"SELECT "+AuthCredentialColumns+" FROM auth_credentials WHERE user_id = $1 ORDER BY id",
		userID,
	)
	if err != nil {
		return AccountRevocationTargets{}, fmtDatabase("load account credentials", err)
	}
	credentials := make([]AuthCredential, 0)
	credentialIDs := make([]string, 0)
	for rows.Next() {
		credential, err := s.scanCredential(rows)
		if err != nil {
			rows.Close()
			return AccountRevocationTargets{}, err
		}
		credentials = append(credentials, credential)
		credentialIDs = append(credentialIDs, credential.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return AccountRevocationTargets{}, fmtDatabase("iterate account credentials", err)
	}
	installations := make([]string, 0)
	if len(credentialIDs) > 0 {
		installationRows, err := s.pool.Query(ctx, `
            SELECT DISTINCT installation_id
            FROM auth_sessions
            WHERE credential_id = ANY($1::text[])
            ORDER BY installation_id`, credentialIDs)
		if err != nil {
			return AccountRevocationTargets{}, fmtDatabase("load account installations", err)
		}
		for installationRows.Next() {
			var installationID string
			if err := installationRows.Scan(&installationID); err != nil {
				installationRows.Close()
				return AccountRevocationTargets{}, fmtDatabase("scan account installation", err)
			}
			installations = append(installations, installationID)
		}
		installationRows.Close()
		if err := installationRows.Err(); err != nil {
			return AccountRevocationTargets{}, fmtDatabase("iterate account installations", err)
		}
	}
	return AccountRevocationTargets{InstallationIDs: installations, Credentials: credentials}, nil
}

func (s *PostgresStorage) RevokeAccount(
	userID string,
	extraInstallationIDs []string,
) (AccountRevocationResult, error) {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return AccountRevocationResult{}, ErrAuthNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AccountRevocationResult{}, fmtDatabase("begin account revocation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	credentialRows, err := tx.Query(ctx,
		"SELECT id FROM auth_credentials WHERE user_id = $1 FOR UPDATE", userID,
	)
	if err != nil {
		return AccountRevocationResult{}, fmtDatabase("lock account credentials", err)
	}
	credentialIDs := make([]string, 0)
	for credentialRows.Next() {
		var id string
		if err := credentialRows.Scan(&id); err != nil {
			credentialRows.Close()
			return AccountRevocationResult{}, fmtDatabase("scan account credential id", err)
		}
		credentialIDs = append(credentialIDs, id)
	}
	credentialRows.Close()
	if err := credentialRows.Err(); err != nil {
		return AccountRevocationResult{}, fmtDatabase("iterate account credential ids", err)
	}

	installations := compactStrings(extraInstallationIDs)
	if len(credentialIDs) > 0 {
		rows, err := tx.Query(ctx,
			"SELECT DISTINCT installation_id FROM auth_sessions WHERE credential_id = ANY($1::text[])",
			credentialIDs,
		)
		if err != nil {
			return AccountRevocationResult{}, fmtDatabase("load account session installations", err)
		}
		for rows.Next() {
			var installationID string
			if err := rows.Scan(&installationID); err != nil {
				rows.Close()
				return AccountRevocationResult{}, fmtDatabase("scan account session installation", err)
			}
			installations = append(installations, installationID)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return AccountRevocationResult{}, fmtDatabase("iterate account session installations", err)
		}
	}
	installations = compactStrings(installations)

	result := AccountRevocationResult{}
	if len(credentialIDs) > 0 {
		if err := tx.QueryRow(ctx, `
            WITH deleted AS (
                DELETE FROM auth_sessions WHERE credential_id = ANY($1::text[]) RETURNING 1
            ) SELECT count(*) FROM deleted`, credentialIDs,
		).Scan(&result.RemovedSessions); err != nil {
			return AccountRevocationResult{}, fmtDatabase("delete account sessions", err)
		}
	}
	if len(credentialIDs) > 0 || len(installations) > 0 {
		if _, err := tx.Exec(ctx, `
            DELETE FROM auth_handoffs
            WHERE credential_id = ANY($1::text[])
               OR installation_id = ANY($2::text[])`, credentialIDs, installations); err != nil {
			return AccountRevocationResult{}, fmtDatabase("delete account handoffs", err)
		}
	}
	if len(installations) > 0 {
		if _, err := tx.Exec(ctx,
			"DELETE FROM auth_pending WHERE installation_id = ANY($1::text[])", installations,
		); err != nil {
			return AccountRevocationResult{}, fmtDatabase("delete account pending auth", err)
		}
	}
	if err := tx.QueryRow(ctx, `
        WITH deleted AS (
            DELETE FROM auth_credentials WHERE user_id = $1 RETURNING 1
        ) SELECT count(*) FROM deleted`, userID,
	).Scan(&result.RemovedCredentials); err != nil {
		return AccountRevocationResult{}, fmtDatabase("delete account credentials", err)
	}
	if err := deleteOrphanCredentials(ctx, tx); err != nil {
		return AccountRevocationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AccountRevocationResult{}, fmtDatabase("commit account revocation", err)
	}
	return result, nil
}

func (s *PostgresStorage) DeleteCredentialIfUnused(credentialID string) error {
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	return deleteCredentialIfUnusedTx(ctx, s.pool, credentialID)
}

func (s *PostgresStorage) scanCredential(scanner databaseScanner) (AuthCredential, error) {
	var record AuthCredentialRecord
	err := scanner.Scan(
		&record.ID,
		&record.ClientID,
		&record.UserID,
		&record.Login,
		&record.Scopes,
		&record.AccessToken.Nonce,
		&record.AccessToken.Ciphertext,
		&record.RefreshToken.Nonce,
		&record.RefreshToken.Ciphertext,
		&record.AccessExpiresAt,
		&record.LastValidatedAt,
		&record.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthCredential{}, ErrAuthNotFound
	}
	if err != nil {
		return AuthCredential{}, fmtDatabase("scan auth credential", err)
	}
	access, err := OpenAuthValue(s.aead, record.ID+":access", record.AccessToken)
	if err != nil {
		return AuthCredential{}, err
	}
	refresh, err := OpenAuthValue(s.aead, record.ID+":refresh", record.RefreshToken)
	if err != nil {
		return AuthCredential{}, err
	}
	return AuthCredential{
		ID:              record.ID,
		ClientID:        record.ClientID,
		UserID:          record.UserID,
		Login:           record.Login,
		Scopes:          append([]string(nil), record.Scopes...),
		AccessToken:     access,
		RefreshToken:    refresh,
		AccessExpiresAt: record.AccessExpiresAt,
		LastValidatedAt: record.LastValidatedAt,
		UpdatedAt:       record.UpdatedAt,
	}, nil
}

func scanPendingAuth(scanner databaseScanner) (PendingAuthRecord, error) {
	var record PendingAuthRecord
	err := scanner.Scan(
		&record.InstallationID,
		&record.DeviceHash,
		&record.AppCallbackURI,
		&record.CreatedAt,
		&record.ExpiresAt,
	)
	return record, err
}

func scanAuthHandoff(scanner databaseScanner) (AuthHandoffRecord, error) {
	var record AuthHandoffRecord
	err := scanner.Scan(
		&record.CredentialID,
		&record.InstallationID,
		&record.DeviceHash,
		&record.AppCallbackURI,
		&record.StateHash,
		&record.CreatedAt,
		&record.ExpiresAt,
	)
	return record, err
}

func scanAuthSession(scanner databaseScanner) (AuthSessionRecord, error) {
	var record AuthSessionRecord
	err := scanner.Scan(
		&record.CredentialID,
		&record.InstallationID,
		&record.DeviceHash,
		&record.CreatedAt,
		&record.ExpiresAt,
	)
	return record, err
}

func prefixedCredentialColumns(alias string) string {
	columns := []string{
		"id", "client_id", "user_id", "login", "scopes",
		"access_nonce", "access_ciphertext", "refresh_nonce", "refresh_ciphertext",
		"access_expires_at", "last_validated_at", "updated_at",
	}
	for index := range columns {
		columns[index] = alias + "." + columns[index]
	}
	return strings.Join(columns, ", ")
}

func deleteCredentialIfUnusedTx(ctx context.Context, query databaseExecutor, credentialID string) error {
	_, err := query.Exec(ctx, `
        DELETE FROM auth_credentials credential
        WHERE credential.id = $1
          AND NOT EXISTS (
              SELECT 1 FROM auth_sessions session WHERE session.credential_id = credential.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM auth_handoffs handoff WHERE handoff.credential_id = credential.id
          )`, credentialID)
	if err != nil {
		return fmtDatabase("delete unused auth credential", err)
	}
	return nil
}

func deleteOrphanCredentials(ctx context.Context, query databaseExecutor) error {
	_, err := query.Exec(ctx, `
        DELETE FROM auth_credentials credential
        WHERE NOT EXISTS (
            SELECT 1 FROM auth_sessions session WHERE session.credential_id = credential.id
        )
        AND NOT EXISTS (
            SELECT 1 FROM auth_handoffs handoff WHERE handoff.credential_id = credential.id
        )`)
	if err != nil {
		return fmtDatabase("delete orphan auth credentials", err)
	}
	return nil
}

func commitDatabaseTx(ctx context.Context, tx pgx.Tx, name string) error {
	if err := tx.Commit(ctx); err != nil {
		return fmtDatabase("commit "+name+" transaction", err)
	}
	return nil
}

// Keep deterministic ordering for callers that compare snapshots in tests.
func sortCredentials(credentials []AuthCredential) {
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].ID < credentials[j].ID })
}
