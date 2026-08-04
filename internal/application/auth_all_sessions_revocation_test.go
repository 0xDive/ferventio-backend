package application

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func revocationTestConfig(twitchIDBaseURL string) Config {
	if twitchIDBaseURL == "" {
		twitchIDBaseURL = "http://127.0.0.1"
	}
	return Config{
		AuthEncryptionKey:  testAuthKey(),
		AuthSessionTTL:     24 * time.Hour,
		AuthLeaseTTL:       time.Minute,
		TwitchClientID:     "server-client",
		TwitchClientSecret: "server-secret",
		TwitchRedirectURL:  "https://auth.example.test/v1/auth/twitch/callback",
		PublicBaseURL:      "https://auth.example.test",
		TwitchIDBaseURL:    twitchIDBaseURL,
		AuthScopes:         []string{"chat:read", "chat:edit"},
	}
}

func TestRevokeAllMobileSessionsRemovesOnlyAuthenticatedAccount(t *testing.T) {
	var revokeMu sync.Mutex
	var revokedTokens []string
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth2/revoke" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_id") != "server-client" {
			t.Fatalf("unexpected client_id: %q", r.Form.Get("client_id"))
		}
		token := r.Form.Get("token")
		revokeMu.Lock()
		revokedTokens = append(revokedTokens, token)
		revokeMu.Unlock()
		if token == "access-a2" {
			w.WriteHeader(http.StatusBadRequest) // already invalid is idempotent success
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer twitch.Close()

	cfg := revocationTestConfig(twitch.URL)
	temporary := t.TempDir()
	authStore, err := OpenAuthStore(filepath.Join(temporary, "auth.json"), cfg.AuthEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	registrationStore, err := OpenStore(filepath.Join(temporary, "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	deliveryStore, err := OpenDeliveryStore(filepath.Join(temporary, "deliveries.json"))
	if err != nil {
		t.Fatal(err)
	}
	auditStore := newMemoryAuditStore()
	now := time.Now().UTC()
	installA1, secretA1 := "installation-a1", strings.Repeat("a", 48)
	installA2, secretA2 := "installation-a2", strings.Repeat("c", 48)
	installB, secretB := "installation-b", strings.Repeat("b", 48)
	credentialA1 := authCredential{ID: "credential-a1", ClientID: cfg.TwitchClientID, UserID: "user-a", Login: "alpha", AccessToken: "access-a1", RefreshToken: "refresh-a1", AccessExpiresAt: now.Add(time.Hour), LastValidatedAt: now, UpdatedAt: now}
	if err := authStore.PutCredential(credentialA1); err != nil {
		t.Fatal(err)
	}
	tokenA1, _, err := authStore.CreateSession(credentialA1.ID, installA1, secretA1, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	credentialA2 := authCredential{ID: "credential-a2", ClientID: cfg.TwitchClientID, UserID: "user-a", Login: "alpha", AccessToken: "access-a2", RefreshToken: "refresh-a2", AccessExpiresAt: now.Add(time.Hour), LastValidatedAt: now, UpdatedAt: now}
	if err := authStore.PutCredential(credentialA2); err != nil {
		t.Fatal(err)
	}
	tokenA2, _, err := authStore.CreateSession(credentialA2.ID, installA2, secretA2, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	credentialB := authCredential{ID: "credential-b", ClientID: cfg.TwitchClientID, UserID: "user-b", Login: "beta", AccessToken: "access-b", RefreshToken: "refresh-b", AccessExpiresAt: now.Add(time.Hour), LastValidatedAt: now, UpdatedAt: now}
	if err := authStore.PutCredential(credentialB); err != nil {
		t.Fatal(err)
	}
	tokenB, _, err := authStore.CreateSession(credentialB.ID, installB, secretB, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := authStore.PutPending("pending-a", pendingAuthRecord{
		InstallationID: installA2,
		DeviceHash:     hashSecret(secretA2),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	for _, registration := range []Registration{
		{InstallationID: installA1, DeviceSecret: secretA1, Provider: "socket", UserID: "user-a", UserLogin: "alpha"},
		{InstallationID: installA2, DeviceSecret: secretA2, Provider: "socket", UserID: "user-a", UserLogin: "alpha"},
		{InstallationID: installB, DeviceSecret: secretB, Provider: "socket", UserID: "user-b", UserLogin: "beta"},
	} {
		if err := registrationStore.Upsert(registration); err != nil {
			t.Fatal(err)
		}
	}
	for _, delivery := range []DeliveryRecord{
		{ID: "delivery-a1", EventID: "event-a1", InstallationID: installA1},
		{ID: "delivery-a2", EventID: "event-a2", InstallationID: installA2},
		{ID: "delivery-b", EventID: "event-b", InstallationID: installB},
	} {
		if _, _, err := deliveryStore.Enqueue(delivery); err != nil {
			t.Fatal(err)
		}
	}

	server := NewServerWithStores(
		cfg,
		registrationStore,
		authStore,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		deliveryStore,
		auditStore,
	)
	request := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions", nil)
	request.Header.Set("Authorization", "Bearer "+tokenA1)
	request.Header.Set("X-Installation-ID", installA1)
	request.Header.Set("X-Device-Secret", secretA1)
	response := httptest.NewRecorder()
	server.revokeAllMobileSessions(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	// Lost-response retry is safe after the current registration and auth records are gone.
	retry := httptest.NewRecorder()
	server.revokeAllMobileSessions(retry, request)
	if retry.Code != http.StatusNoContent {
		t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
	}

	for _, item := range []struct {
		token, installationID, secret string
	}{{tokenA1, installA1, secretA1}, {tokenA2, installA2, secretA2}} {
		if _, err := authStore.ResolveSession(item.token, item.installationID, item.secret, 0); !errors.Is(err, ErrAuthNotFound) {
			t.Fatalf("account session must be revoked: %v", err)
		}
	}
	if _, err := authStore.ResolveSession(tokenB, installB, secretB, 0); err != nil {
		t.Fatalf("other account session must remain: %v", err)
	}
	for _, credentialID := range []string{"credential-a1", "credential-a2"} {
		if _, err := authStore.GetCredential(credentialID); !errors.Is(err, ErrAuthNotFound) {
			t.Fatalf("credential %s must be removed: %v", credentialID, err)
		}
	}
	if _, err := authStore.GetCredential("credential-b"); err != nil {
		t.Fatalf("other account credential must remain: %v", err)
	}
	if _, err := authStore.GetPending("pending-a"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("pending OAuth record must be removed: %v", err)
	}
	deliveryCheckAt := time.Now().UTC().Add(time.Second)
	for _, installationID := range []string{installA1, installA2} {
		if _, err := registrationStore.Get(installationID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("registration %s must be removed: %v", installationID, err)
		}
		if pending := deliveryStore.PendingForInstallation(installationID, 10, deliveryCheckAt); len(pending) != 0 {
			t.Fatalf("deliveries for %s must be removed: %+v", installationID, pending)
		}
	}
	if _, err := registrationStore.Get(installB); err != nil {
		t.Fatalf("other account registration must remain: %v", err)
	}
	if pending := deliveryStore.PendingForInstallation(installB, 10, deliveryCheckAt); len(pending) != 1 {
		t.Fatalf("other account delivery must remain: %+v", pending)
	}
	revokeMu.Lock()
	sort.Strings(revokedTokens)
	gotRevoked := append([]string(nil), revokedTokens...)
	revokeMu.Unlock()
	if strings.Join(gotRevoked, ",") != "access-a1,access-a2" {
		t.Fatalf("unexpected Twitch revoke calls: %v", gotRevoked)
	}
	records := auditStore.List(10)
	if len(records) != 1 || records[0].Action != "auth.sessions.revoke_all" || records[0].InstallationID != installA1 {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestRevokeAllMobileSessionsRejectsWrongBearerWithoutMutation(t *testing.T) {
	var revokeCalls int
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revokeCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer twitch.Close()
	cfg := revocationTestConfig(twitch.URL)
	authStore, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), cfg.AuthEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credential := authCredential{ID: "credential", ClientID: cfg.TwitchClientID, UserID: "user", Login: "user", AccessToken: "access", RefreshToken: "refresh", AccessExpiresAt: now.Add(time.Hour), LastValidatedAt: now, UpdatedAt: now}
	if err := authStore.PutCredential(credential); err != nil {
		t.Fatal(err)
	}
	installationID, deviceSecret := "installation", strings.Repeat("s", 48)
	token, _, err := authStore.CreateSession(credential.ID, installationID, deviceSecret, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(cfg, nil, authStore, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions", nil)
	request.Header.Set("Authorization", "Bearer wrong-token")
	request.Header.Set("X-Installation-ID", installationID)
	request.Header.Set("X-Device-Secret", deviceSecret)
	response := httptest.NewRecorder()
	server.revokeAllMobileSessions(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := authStore.ResolveSession(token, installationID, deviceSecret, 0); err != nil {
		t.Fatalf("session must remain after rejected request: %v", err)
	}
	if revokeCalls != 0 {
		t.Fatalf("Twitch revoke must not run for rejected request, calls=%d", revokeCalls)
	}
}

func TestRevokeAccessTokenUsesFormEncodedBody(t *testing.T) {
	var form url.Values
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		form = r.Form
		w.WriteHeader(http.StatusOK)
	}))
	defer twitch.Close()
	client := newTwitchOAuthClient(revocationTestConfig(twitch.URL), &AuthStore{})
	if err := client.revokeAccessToken(context.Background(), authCredential{ID: "credential", AccessToken: "token+/="}); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_id") != "server-client" || form.Get("token") != "token+/=" {
		t.Fatalf("unexpected revoke form: %v", form)
	}
}
