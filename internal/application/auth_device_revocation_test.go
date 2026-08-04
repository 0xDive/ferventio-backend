package application

import (
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

func TestRevokeMobileDeviceRemovesOnlyTargetInstallation(t *testing.T) {
	temporary := t.TempDir()
	cfg := revocationTestConfig("")
	cfg.AuthSessionTTL = 365 * 24 * time.Hour
	cfg.AuthLeaseTTL = time.Minute
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
	credential := authCredential{
		ID:              "credential-shared",
		ClientID:        "client",
		UserID:          "user-1",
		Login:           "user",
		AccessToken:     "access",
		RefreshToken:    "refresh",
		AccessExpiresAt: now.Add(time.Hour),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	if err := authStore.PutCredential(credential); err != nil {
		t.Fatal(err)
	}
	targetInstallation := "installation-target"
	targetSecret := strings.Repeat("t", 48)
	otherInstallation := "installation-other"
	otherSecret := strings.Repeat("o", 48)
	targetToken, _, err := authStore.CreateSession(credential.ID, targetInstallation, targetSecret, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := authStore.CreateSession(credential.ID, otherInstallation, otherSecret, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := authStore.PutPending("pending-target", pendingAuthRecord{
		InstallationID: targetInstallation,
		DeviceHash:     hashSecret(targetSecret),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	handoffCredential := credential
	handoffCredential.ID = "credential-handoff"
	if err := authStore.PutCredentialAndHandoff(handoffCredential, "handoff-target", authHandoffRecord{
		CredentialID:   handoffCredential.ID,
		InstallationID: targetInstallation,
		DeviceHash:     hashSecret(targetSecret),
		AppCallbackURI: "io.ferventio.app://oauth/callback",
		StateHash:      hashSecret("state-target"),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	for _, registration := range []Registration{
		{InstallationID: targetInstallation, DeviceSecret: targetSecret, Provider: "socket"},
		{InstallationID: otherInstallation, DeviceSecret: otherSecret, Provider: "socket"},
	} {
		if err := registrationStore.Upsert(registration); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range []DeliveryRecord{
		{ID: "delivery-target", EventID: "event-target", InstallationID: targetInstallation},
		{ID: "delivery-other", EventID: "event-other", InstallationID: otherInstallation},
	} {
		if _, _, err := deliveryStore.Enqueue(record); err != nil {
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
	request := httptest.NewRequest(http.MethodDelete, "/v1/auth/device", nil)
	request.Header.Set("Authorization", "Bearer "+targetToken)
	request.Header.Set("X-Installation-ID", targetInstallation)
	request.Header.Set("X-Device-Secret", targetSecret)
	response := httptest.NewRecorder()
	server.revokeMobileDevice(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	// A retry with the now-revoked bearer is idempotent, covering a lost 204 response.
	retryResponse := httptest.NewRecorder()
	server.revokeMobileDevice(retryResponse, request)
	if retryResponse.Code != http.StatusNoContent {
		t.Fatalf("retry status=%d body=%s", retryResponse.Code, retryResponse.Body.String())
	}

	if _, err := authStore.ResolveSession(targetToken, targetInstallation, targetSecret, 0); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("target session must be revoked, got %v", err)
	}
	if _, err := authStore.ResolveSession(otherToken, otherInstallation, otherSecret, 0); err != nil {
		t.Fatalf("other device session must remain valid: %v", err)
	}
	if _, err := authStore.GetCredential(credential.ID); err != nil {
		t.Fatalf("credential used by another device must remain: %v", err)
	}
	if _, err := authStore.GetPending("pending-target"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("pending auth must be removed, got %v", err)
	}
	if _, err := authStore.ConsumeHandoff("handoff-target", targetInstallation, targetSecret, "state-target"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("handoff must be removed, got %v", err)
	}
	if _, err := authStore.GetCredential(handoffCredential.ID); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("orphaned handoff credential must be removed, got %v", err)
	}
	if _, err := registrationStore.Get(targetInstallation); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target push registration must be removed, got %v", err)
	}
	if _, err := registrationStore.Get(otherInstallation); err != nil {
		t.Fatalf("other registration must remain: %v", err)
	}
	deliveryCheckAt := time.Now().UTC().Add(time.Second)
	if pending := deliveryStore.PendingForInstallation(targetInstallation, 10, deliveryCheckAt); len(pending) != 0 {
		t.Fatalf("target deliveries must be removed: %+v", pending)
	}
	if pending := deliveryStore.PendingForInstallation(otherInstallation, 10, deliveryCheckAt); len(pending) != 1 {
		t.Fatalf("other deliveries must remain: %+v", pending)
	}
	records := auditStore.List(10)
	if len(records) != 1 || records[0].Action != "auth.device.revoke" || records[0].InstallationID != targetInstallation {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestRevokeMobileDeviceRejectsWrongDeviceSecretWithoutMutation(t *testing.T) {
	cfg := revocationTestConfig("")
	cfg.AuthSessionTTL = 24 * time.Hour
	cfg.AuthLeaseTTL = time.Minute
	authStore, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), cfg.AuthEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credential := authCredential{
		ID:              "credential",
		AccessToken:     "access",
		RefreshToken:    "refresh",
		AccessExpiresAt: now.Add(time.Hour),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}
	if err := authStore.PutCredential(credential); err != nil {
		t.Fatal(err)
	}
	installationID := "installation"
	deviceSecret := strings.Repeat("s", 48)
	token, _, err := authStore.CreateSession(credential.ID, installationID, deviceSecret, cfg.AuthSessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(cfg, nil, authStore, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	wrongBearerRequest := httptest.NewRequest(http.MethodDelete, "/v1/auth/device", nil)
	wrongBearerRequest.Header.Set("Authorization", "Bearer wrong-token")
	wrongBearerRequest.Header.Set("X-Installation-ID", installationID)
	wrongBearerRequest.Header.Set("X-Device-Secret", deviceSecret)
	wrongBearerResponse := httptest.NewRecorder()
	server.revokeMobileDevice(wrongBearerResponse, wrongBearerRequest)
	if wrongBearerResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status=%d body=%s", wrongBearerResponse.Code, wrongBearerResponse.Body.String())
	}
	if _, err := authStore.ResolveSession(token, installationID, deviceSecret, 0); err != nil {
		t.Fatalf("session must remain valid after wrong bearer: %v", err)
	}

	request := httptest.NewRequest(http.MethodDelete, "/v1/auth/device", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Installation-ID", installationID)
	request.Header.Set("X-Device-Secret", strings.Repeat("x", 48))
	response := httptest.NewRecorder()
	server.revokeMobileDevice(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := authStore.ResolveSession(token, installationID, deviceSecret, 0); err != nil {
		t.Fatalf("session must remain valid after rejected request: %v", err)
	}
}
