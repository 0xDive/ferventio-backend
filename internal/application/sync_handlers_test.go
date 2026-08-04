package application

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsSyncHandlersRevisionConflictAndRestore(t *testing.T) {
	tempDir := t.TempDir()
	authStore, err := OpenAuthStore(filepath.Join(tempDir, "auth.json"), testAuthKey())
	if err != nil {
		t.Fatal(err)
	}
	credential := authCredential{
		ID:              "credential-1",
		ClientID:        "client-1",
		UserID:          "user-1",
		Login:           "tester",
		Scopes:          []string{"user:read:chat"},
		AccessToken:     "access",
		RefreshToken:    "refresh",
		AccessExpiresAt: time.Now().UTC().Add(time.Hour),
		LastValidatedAt: time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	if err := authStore.PutCredential(credential); err != nil {
		t.Fatal(err)
	}
	const installationID = "installation-1"
	const deviceSecret = "device-secret-that-is-long-enough"
	sessionToken, _, err := authStore.CreateSession(credential.ID, installationID, deviceSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	syncStore, err := OpenSettingsSyncStore(filepath.Join(tempDir, "settings-sync.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithStores(
		Config{AuthSessionTTL: time.Hour},
		nil,
		authStore,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
		syncStore,
	)
	handler := server.Handler()

	do := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+sessionToken)
		request.Header.Set("X-Installation-ID", installationID)
		request.Header.Set("X-Device-Secret", deviceSecret)
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	if response := do(http.MethodGet, "/v1/sync/settings", nil); response.Code != http.StatusNoContent {
		t.Fatalf("initial GET status=%d body=%s", response.Code, response.Body.String())
	}

	payload1 := validSettingsBackupPayload("0.9.7", strings.Repeat("a", 64), "DARK")
	put1 := settingsSyncPutBody(t, 0, false, payload1)
	response := do(http.MethodPut, "/v1/sync/settings", put1)
	if response.Code != http.StatusOK {
		t.Fatalf("first PUT status=%d body=%s", response.Code, response.Body.String())
	}
	var snapshot1 SettingsSyncSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot1); err != nil {
		t.Fatal(err)
	}
	if snapshot1.Revision != 1 || snapshot1.ContentHash != strings.Repeat("a", 64) {
		t.Fatalf("unexpected first snapshot: %+v", snapshot1)
	}

	payload2 := validSettingsBackupPayload("0.9.7", strings.Repeat("b", 64), "AMOLED")
	stale := settingsSyncPutBody(t, 0, false, payload2)
	response = do(http.MethodPut, "/v1/sync/settings", stale)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale PUT status=%d body=%s", response.Code, response.Body.String())
	}
	var conflict struct {
		Snapshot SettingsSyncSnapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &conflict); err != nil {
		t.Fatal(err)
	}
	if conflict.Snapshot.Revision != 1 {
		t.Fatalf("conflict did not return current snapshot: %+v", conflict.Snapshot)
	}

	response = do(http.MethodPut, "/v1/sync/settings", settingsSyncPutBody(t, 1, false, payload2))
	if response.Code != http.StatusOK {
		t.Fatalf("second PUT status=%d body=%s", response.Code, response.Body.String())
	}
	var snapshot2 SettingsSyncSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot2); err != nil {
		t.Fatal(err)
	}
	if snapshot2.Revision != 2 {
		t.Fatalf("second revision=%d want=2", snapshot2.Revision)
	}

	response = do(http.MethodGet, "/v1/sync/settings/history", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", response.Code, response.Body.String())
	}
	var history struct {
		Data []struct {
			Revision int64 `json:"revision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if len(history.Data) != 2 || history.Data[0].Revision != 2 || history.Data[1].Revision != 1 {
		t.Fatalf("unexpected history: %+v", history.Data)
	}

	response = do(http.MethodPost, "/v1/sync/settings/restore/1", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", response.Code, response.Body.String())
	}
	var restored SettingsSyncSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Revision != 3 || restored.ContentHash != snapshot1.ContentHash {
		t.Fatalf("unexpected restored snapshot: %+v", restored)
	}
}

func settingsSyncPutBody(t *testing.T, baseRevision int64, force bool, payload json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"baseRevision": baseRevision,
		"force":        force,
		"payload":      json.RawMessage(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func validSettingsBackupPayload(appVersion, hash, theme string) json.RawMessage {
	return json.RawMessage(`{"format":"ferventio-settings-backup","formatVersion":1,"createdAt":"2026-07-25T00:00:00Z","appVersion":"` + appVersion + `","contentHash":"` + hash + `","content":{"settings":{"themeMode":"` + theme + `"}}}`)
}
