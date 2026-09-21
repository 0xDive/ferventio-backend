package memory

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestStoreRejectsSecretReplacement(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}

	registration := Registration{
		InstallationID:       "installation-1",
		DeviceSecret:         "secret-1",
		Provider:             "fcm",
		FirebaseInstallation: "fid-1",
		AppVersion:           "test",
		Platform:             "android",
	}
	if err := store.Upsert(registration); err != nil {
		t.Fatal(err)
	}

	registration.DeviceSecret = "secret-2"
	if err := store.Upsert(registration); !errors.Is(err, ErrSecretMismatch) {
		t.Fatalf("expected ErrSecretMismatch, got %v", err)
	}
}

func TestStoreHashesDeviceSecrets(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		InstallationID: "installation", DeviceSecret: "plain-secret",
		Provider: "embedded_socket", AppVersion: "test", Platform: "android",
	}
	if err := store.Upsert(registration); err != nil {
		t.Fatal(err)
	}
	stored := store.registrations[registration.InstallationID]
	if stored.DeviceSecret != "" || stored.DeviceSecretHash == "" || stored.DeviceSecretHash == registration.DeviceSecret {
		t.Fatalf("device secret was not reduced to a hash: %+v", stored)
	}
	if _, err := store.Authenticate(registration.InstallationID, "plain-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(registration.InstallationID, "wrong-secret"); !errors.Is(err, ErrSecretMismatch) {
		t.Fatalf("wrong secret = %v", err)
	}
}

func TestStoreCopiesNotificationChannelRules(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		InstallationID: "installation-rules",
		DeviceSecret:   "plain-secret",
		Provider:       "embedded_socket",
		AppVersion:     "test",
		Platform:       "android",
		NotificationChannelRules: map[string][]string{
			"channel-1": {"reply"},
		},
		NotificationChannelMutedUntilEpochMillis: map[string]int64{
			"channel-1": 12345,
		},
	}
	if err := store.Upsert(registration); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Authenticate(registration.InstallationID, registration.DeviceSecret)
	if err != nil {
		t.Fatal(err)
	}
	loaded.NotificationChannelRules["channel-1"][0] = "mutated"
	loaded.NotificationChannelMutedUntilEpochMillis["channel-1"] = 99999
	reloaded, err := store.Get(registration.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.NotificationChannelRules["channel-1"][0]; got != "reply" {
		t.Fatalf("stored notification rules were aliased: %q", got)
	}
	if got := reloaded.NotificationChannelMutedUntilEpochMillis["channel-1"]; got != 12345 {
		t.Fatalf("stored notification mute was aliased: %d", got)
	}
}
