package application

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompleteMobileReauthorizationPreservesCurrentSessionWhenNewLeaseFails(t *testing.T) {
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "temporary Twitch failure")
	}))
	defer twitch.Close()

	cfg := reauthorizationTestConfig(twitch.URL)
	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), cfg.AuthEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	installationID := "installation-reauth"
	deviceSecret := strings.Repeat("r", 48)
	now := time.Now().UTC()
	oldCredential := authCredential{
		ID:              "credential-old",
		ClientID:        cfg.TwitchClientID,
		UserID:          "user-old",
		Login:           "old-user",
		Scopes:          append([]string(nil), cfg.AuthScopes...),
		AccessToken:     "old-access",
		RefreshToken:    "old-refresh",
		AccessExpiresAt: now.Add(time.Hour),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	if err := store.PutCredential(oldCredential); err != nil {
		t.Fatal(err)
	}
	oldSessionToken, _, err := store.CreateSession(
		oldCredential.ID,
		installationID,
		deviceSecret,
		cfg.AuthSessionTTL,
	)
	if err != nil {
		t.Fatal(err)
	}

	newCredential := authCredential{
		ID:              "credential-new",
		ClientID:        cfg.TwitchClientID,
		UserID:          "user-new",
		Login:           "new-user",
		Scopes:          append([]string(nil), cfg.AuthScopes...),
		AccessToken:     "new-access-expired",
		RefreshToken:    "new-refresh-expired",
		AccessExpiresAt: now.Add(-time.Minute),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	code := "handoff-reauth-failure"
	state := "state-reauth-failure"
	if err := store.PutCredentialAndHandoff(newCredential, code, authHandoffRecord{
		CredentialID:   newCredential.ID,
		InstallationID: installationID,
		DeviceHash:     hashSecret(deviceSecret),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		StateHash:      hashSecret(state),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	server := NewServer(cfg, nil, store, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := completeReauthorization(t, server, installationID, deviceSecret, code, state)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := store.ResolveSession(oldSessionToken, installationID, deviceSecret, 0); err != nil {
		t.Fatalf("old session must remain valid after failed reauthorization: %v", err)
	}
	if _, err := store.GetCredential(newCredential.ID); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("failed reauthorization credential must be removed, got %v", err)
	}
}

func TestCompleteMobileReauthorizationAtomicallyReplacesCurrentSession(t *testing.T) {
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "new-access",
				"refresh_token": "new-refresh-rotated",
				"expires_in":    3600,
				"scope":         []string{"user:read:chat", "user:write:chat"},
				"token_type":    "bearer",
			})
		case "/oauth2/validate":
			if r.Header.Get("Authorization") != "Bearer new-access" {
				writeError(w, http.StatusUnauthorized, "unexpected authorization header")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"client_id":  "server-client",
				"user_id":    "user-new",
				"login":      "new-user",
				"scopes":     []string{"user:read:chat", "user:write:chat"},
				"expires_in": 3500,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer twitch.Close()

	cfg := reauthorizationTestConfig(twitch.URL)
	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), cfg.AuthEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	installationID := "installation-reauth"
	deviceSecret := strings.Repeat("s", 48)
	now := time.Now().UTC()
	oldCredential := authCredential{
		ID:              "credential-old",
		ClientID:        cfg.TwitchClientID,
		UserID:          "user-old",
		Login:           "old-user",
		Scopes:          append([]string(nil), cfg.AuthScopes...),
		AccessToken:     "old-access",
		RefreshToken:    "old-refresh",
		AccessExpiresAt: now.Add(time.Hour),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	if err := store.PutCredential(oldCredential); err != nil {
		t.Fatal(err)
	}
	oldSessionToken, _, err := store.CreateSession(
		oldCredential.ID,
		installationID,
		deviceSecret,
		cfg.AuthSessionTTL,
	)
	if err != nil {
		t.Fatal(err)
	}

	newCredential := authCredential{
		ID:              "credential-new",
		ClientID:        cfg.TwitchClientID,
		UserID:          "user-new",
		Login:           "new-user",
		Scopes:          append([]string(nil), cfg.AuthScopes...),
		AccessToken:     "new-access-expired",
		RefreshToken:    "new-refresh-initial",
		AccessExpiresAt: now.Add(-time.Minute),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	code := "handoff-reauth-success"
	state := "state-reauth-success"
	if err := store.PutCredentialAndHandoff(newCredential, code, authHandoffRecord{
		CredentialID:   newCredential.ID,
		InstallationID: installationID,
		DeviceHash:     hashSecret(deviceSecret),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		StateHash:      hashSecret(state),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	server := NewServer(cfg, nil, store, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := completeReauthorization(t, server, installationID, deviceSecret, code, state)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var completed mobileAuthCompleteResponse
	if err := json.Unmarshal(response.Body.Bytes(), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.SessionToken == "" || completed.Lease.AccessToken != "new-access" {
		t.Fatalf("unexpected completion: %+v", completed)
	}
	if _, err := store.ResolveSession(oldSessionToken, installationID, deviceSecret, 0); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("old session must be revoked only after success, got %v", err)
	}
	newSession, err := store.ResolveSession(completed.SessionToken, installationID, deviceSecret, 0)
	if err != nil {
		t.Fatal(err)
	}
	if newSession.CredentialID != newCredential.ID {
		t.Fatalf("credential=%q", newSession.CredentialID)
	}
	if _, err := store.GetCredential(oldCredential.ID); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("old orphaned credential must be removed, got %v", err)
	}
	storedNew, err := store.GetCredential(newCredential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedNew.AccessToken != "new-access" || storedNew.RefreshToken != "new-refresh-rotated" {
		t.Fatalf("rotated credential not persisted: %+v", storedNew)
	}
}

func reauthorizationTestConfig(twitchURL string) Config {
	return Config{
		TwitchClientID:        "server-client",
		TwitchClientSecret:    "server-secret",
		TwitchRedirectURL:     "https://auth.example.test/v1/auth/twitch/callback",
		TwitchIDBaseURL:       twitchURL,
		PublicBaseURL:         "https://auth.example.test",
		AuthEncryptionKey:     testAuthKey(),
		AuthAllowedAppSchemes: []string{"io.ferventio.app"},
		AuthScopes:            []string{"user:read:chat", "user:write:chat"},
		AuthSessionTTL:        365 * 24 * time.Hour,
		AuthStateTTL:          10 * time.Minute,
		AuthHandoffTTL:        2 * time.Minute,
		AuthLeaseTTL:          time.Minute,
		RequestBodyMaxBytes:   64 << 10,
	}
}

func completeReauthorization(
	t *testing.T,
	server *Server,
	installationID string,
	deviceSecret string,
	code string,
	state string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(mobileAuthCompleteRequest{
		InstallationID: installationID,
		DeviceSecret:   deviceSecret,
		Code:           code,
		State:          state,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/mobile/complete", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	server.completeMobileAuth(response, request)
	return response
}
