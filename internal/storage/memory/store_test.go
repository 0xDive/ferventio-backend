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
