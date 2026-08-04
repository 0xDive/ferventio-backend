package application

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"reflect"
)

func TestTwitchOAuthLeaseSerializesRefreshAndPersistsRotation(t *testing.T) {
	var refreshRequests atomic.Int32
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-old" {
				t.Fatalf("unexpected refresh form: %v", url.Values(r.Form))
			}
			refreshRequests.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "access-new",
				"refresh_token": "refresh-new",
				"expires_in":    3600,
				"scope":         []string{"user:read:chat", "user:write:chat"},
				"token_type":    "bearer",
			})
		case "/oauth2/validate":
			if r.Header.Get("Authorization") != "Bearer access-new" {
				t.Fatalf("unexpected validation token: %q", r.Header.Get("Authorization"))
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"client_id":  "client",
				"user_id":    "user",
				"login":      "tester",
				"scopes":     []string{"user:read:chat", "user:write:chat"},
				"expires_in": 3500,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer twitch.Close()

	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.PutCredential(authCredential{
		ID:              "credential",
		ClientID:        "client",
		UserID:          "user",
		Login:           "tester",
		Scopes:          []string{"user:read:chat", "user:write:chat"},
		AccessToken:     "access-old",
		RefreshToken:    "refresh-old",
		AccessExpiresAt: now.Add(-time.Minute),
		LastValidatedAt: now.Add(-time.Hour),
		UpdatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	// Keep the credential alive while the test refreshes it.
	if err := store.PutHandoff("handoff", authHandoffRecord{
		CredentialID:   "credential",
		InstallationID: "installation",
		DeviceHash:     hashSecret("device-secret-that-is-long-enough-000000"),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		StateHash:      hashSecret("state"),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	client := newTwitchOAuthClient(Config{
		TwitchClientID:     "client",
		TwitchClientSecret: "secret",
		TwitchIDBaseURL:    twitch.URL,
		AuthScopes:         []string{"user:read:chat", "user:write:chat"},
		AuthEncryptionKey:  testAuthKey(),
		TwitchRedirectURL:  "https://auth.example.test/v1/auth/twitch/callback",
		PublicBaseURL:      "https://auth.example.test",
	}, store)

	var wg sync.WaitGroup
	results := make(chan authCredential, 2)
	errorsCh := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			credential, leaseErr := client.lease(context.Background(), "credential", false)
			if leaseErr != nil {
				errorsCh <- leaseErr
				return
			}
			results <- credential
		}()
	}
	wg.Wait()
	close(results)
	close(errorsCh)
	for leaseErr := range errorsCh {
		t.Fatal(leaseErr)
	}
	for credential := range results {
		if credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
			t.Fatalf("unexpected refreshed credential: %+v", credential)
		}
	}
	if refreshRequests.Load() != 1 {
		t.Fatalf("refresh must be serialized, requests=%d", refreshRequests.Load())
	}

	disk, err := store.GetCredential("credential")
	if err != nil {
		t.Fatal(err)
	}
	if disk.RefreshToken != "refresh-new" || disk.AccessToken != "access-new" {
		encoded, _ := json.Marshal(disk)
		t.Fatalf("rotated tokens were not persisted: %s", encoded)
	}
}

func TestModeratedChannelIDsUsesVerifiedHelixPages(t *testing.T) {
	requests := 0
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/moderation/channels" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Client-Id") != "client-id" {
			t.Fatalf("client id = %q", r.Header.Get("Client-Id"))
		}
		if r.URL.Query().Get("user_id") != "user-1" {
			t.Fatalf("user_id = %q", r.URL.Query().Get("user_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("after") == "" {
			_, _ = w.Write([]byte(`{"data":[{"broadcaster_id":"channel-1"}],"pagination":{"cursor":"next"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"broadcaster_id":"channel-2"}],"pagination":{}}`))
	}))
	defer twitch.Close()

	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.PutCredential(authCredential{
		ID: "credential-1", ClientID: "client-id", UserID: "user-1", Login: "viewer",
		Scopes: []string{"user:read:moderated_channels"}, AccessToken: "access-token", RefreshToken: "refresh-token",
		AccessExpiresAt: now.Add(time.Hour), LastValidatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	client := &twitchOAuthClient{
		cfg:   Config{TwitchClientID: "client-id", TwitchHelixBaseURL: twitch.URL},
		store: store,
		http:  twitch.Client(),
	}
	ids, err := client.moderatedChannelIDs(context.Background(), "credential-1")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || !reflect.DeepEqual(ids, []string{"channel-1", "channel-2"}) {
		t.Fatalf("requests=%d ids=%v", requests, ids)
	}
}

func TestTwitchOAuthLeaseRefreshesBeforeOutageReserve(t *testing.T) {
	var refreshRequests atomic.Int32
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			refreshRequests.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "access-reserved",
				"refresh_token": "refresh-reserved",
				"expires_in":    14_400,
				"scope":         []string{"user:read:chat", "user:write:chat"},
				"token_type":    "bearer",
			})
		case "/oauth2/validate":
			writeJSON(w, http.StatusOK, map[string]any{
				"client_id":  "client",
				"user_id":    "user",
				"login":      "tester",
				"scopes":     []string{"user:read:chat", "user:write:chat"},
				"expires_in": 14_300,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer twitch.Close()

	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.PutCredential(authCredential{
		ID:              "credential-reserve",
		ClientID:        "client",
		UserID:          "user",
		Login:           "tester",
		Scopes:          []string{"user:read:chat", "user:write:chat"},
		AccessToken:     "access-with-90m-left",
		RefreshToken:    "refresh-old",
		AccessExpiresAt: now.Add(90 * time.Minute),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutHandoff("handoff-reserve", authHandoffRecord{
		CredentialID:   "credential-reserve",
		InstallationID: "installation",
		DeviceHash:     hashSecret("device-secret-that-is-long-enough-000000"),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		StateHash:      hashSecret("state"),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	client := newTwitchOAuthClient(Config{
		TwitchClientID:         "client",
		TwitchClientSecret:     "secret",
		TwitchIDBaseURL:        twitch.URL,
		AuthScopes:             []string{"user:read:chat", "user:write:chat"},
		AuthEncryptionKey:      testAuthKey(),
		TwitchRedirectURL:      "https://auth.example.test/v1/auth/twitch/callback",
		PublicBaseURL:          "https://auth.example.test",
		AuthAccessRefreshAhead: 2 * time.Hour,
	}, store)

	credential, err := client.lease(context.Background(), "credential-reserve", false)
	if err != nil {
		t.Fatal(err)
	}
	if refreshRequests.Load() != 1 {
		t.Fatalf("expected proactive refresh inside outage reserve, requests=%d", refreshRequests.Load())
	}
	if credential.AccessToken != "access-reserved" || credential.RefreshToken != "refresh-reserved" {
		t.Fatalf("unexpected refreshed credential: %+v", credential)
	}
}
