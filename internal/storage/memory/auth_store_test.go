package memory

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAuthKey() string {
	return base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func TestAuthStoreEncryptsTwitchTokensAndBindsSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := OpenAuthStore(path, testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credential := authCredential{
		ID:              "credential-1",
		ClientID:        "client-1",
		UserID:          "user-1",
		Login:           "tester",
		Scopes:          []string{"user:read:chat", "user:write:chat"},
		AccessToken:     "plain-access-token-must-not-be-on-disk",
		RefreshToken:    "plain-refresh-token-must-not-be-on-disk",
		AccessExpiresAt: now.Add(time.Hour),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	if err := store.PutCredential(credential); err != nil {
		t.Fatal(err)
	}
	if err := store.PutHandoff("handoff", authHandoffRecord{
		CredentialID:   credential.ID,
		InstallationID: "installation-1",
		DeviceHash:     hashSecret(strings.Repeat("s", 48)),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		StateHash:      hashSecret("state"),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	encodedState, err := json.Marshal(store.state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedState), credential.AccessToken) || strings.Contains(string(encodedState), credential.RefreshToken) {
		t.Fatal("Twitch tokens were retained in plaintext")
	}

	if _, err := store.ConsumeHandoff("handoff", "installation-1", strings.Repeat("x", 48), "state"); !errors.Is(err, ErrAuthDeviceMismatch) {
		t.Fatalf("expected mismatched device to be rejected, got %v", err)
	}
	if _, err := store.ConsumeHandoff("handoff", "installation-1", strings.Repeat("s", 48), "wrong-state"); !errors.Is(err, ErrAuthStateMismatch) {
		t.Fatalf("expected mismatched state to be rejected, got %v", err)
	}
	if _, err := store.ConsumeHandoff("handoff", "installation-1", strings.Repeat("s", 48), "state"); err != nil {
		t.Fatal(err)
	}
	sessionToken, expiresAt, err := store.CreateSession(
		credential.ID,
		"installation-1",
		strings.Repeat("s", 48),
		24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	encodedState, err = json.Marshal(store.state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedState), sessionToken) {
		t.Fatal("backend session token was retained in plaintext")
	}
	if _, err := store.ResolveSession(sessionToken, "installation-1", "wrong-secret-that-is-long-enough-000000", 24*time.Hour); !errors.Is(err, ErrAuthDeviceMismatch) {
		t.Fatalf("expected device mismatch, got %v", err)
	}
	session, err := store.ResolveSession(sessionToken, "installation-1", strings.Repeat("s", 48), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if session.CredentialID != credential.ID || !session.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected session: %+v", session)
	}

	loaded, err := store.GetCredential(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AccessToken != credential.AccessToken || loaded.RefreshToken != credential.RefreshToken {
		t.Fatal("encrypted credential did not round-trip")
	}
	if err := store.DeleteSession(sessionToken, "installation-1", strings.Repeat("s", 48)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetCredential(credential.ID); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("credential should be removed with its last session, got %v", err)
	}
}

func TestAuthStorePendingAndHandoffAreOneTime(t *testing.T) {
	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pending := pendingAuthRecord{
		InstallationID: "installation",
		DeviceHash:     hashSecret(strings.Repeat("d", 48)),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}
	if err := store.PutPending("state", pending); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPending("state"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumePending("state"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumePending("state"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("pending state must be one-time, got %v", err)
	}
}

func TestCreateSessionReplacesPreviousSessionForInstallation(t *testing.T) {
	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credential := func(id string) authCredential {
		return authCredential{
			ID:              id,
			ClientID:        "client",
			UserID:          "user-" + id,
			Login:           "tester",
			Scopes:          []string{"user:read:chat", "user:write:chat"},
			AccessToken:     "access-" + id,
			RefreshToken:    "refresh-" + id,
			AccessExpiresAt: now.Add(time.Hour),
			LastValidatedAt: now,
			UpdatedAt:       now,
		}
	}
	secret := strings.Repeat("q", 48)
	if err := store.PutCredential(credential("one")); err != nil {
		t.Fatal(err)
	}
	oldToken, _, err := store.CreateSession("one", "installation", secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutCredential(credential("two")); err != nil {
		t.Fatal(err)
	}
	newToken, _, err := store.CreateSession("two", "installation", secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveSession(oldToken, "installation", secret, time.Hour); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("old mobile session should be revoked, got %v", err)
	}
	if _, err := store.ResolveSession(newToken, "installation", secret, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetCredential("one"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("orphaned credential should be removed, got %v", err)
	}
}
