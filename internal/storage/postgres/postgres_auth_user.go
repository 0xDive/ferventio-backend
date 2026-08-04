package postgres

import (
	"errors"
	"strings"
	"time"

	. "github.com/0xDive/ferventio-backend/internal/domain"
	"github.com/jackc/pgx/v5"
)

// CredentialForUser returns the newest credential that still has an active
// backend session for the Twitch account. Long-lived EventSub connections use
// this lookup instead of retaining an installation's device secret.
func (s *PostgresStorage) CredentialForUser(userID string) (AuthCredential, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return AuthCredential{}, ErrAuthNotFound
	}
	ctx, cancel := databaseTimeoutContext()
	defer cancel()
	credential, err := s.scanCredential(s.pool.QueryRow(ctx, `
        SELECT `+prefixedCredentialColumns("credential")+`
        FROM auth_credentials credential
        JOIN auth_sessions session ON session.credential_id = credential.id
        WHERE credential.user_id = $1
          AND session.expires_at > $2
        ORDER BY credential.updated_at DESC, session.expires_at DESC
        LIMIT 1`, userID, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthCredential{}, ErrAuthNotFound
	}
	if err != nil {
		return AuthCredential{}, fmtDatabase("get credential for user", err)
	}
	return credential, nil
}
