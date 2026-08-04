package config

import (
	"strings"
	"testing"
)

func TestFirebaseMessagingIsDisabledByDefault(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FIREBASE_PROJECT_ID", "configured-project")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FirebaseMessagingEnabled() {
		t.Fatal("Firebase Messaging must remain disabled until FIREBASE_ENABLED=true")
	}
}

func TestFirebaseMessagingRequiresProjectIDWhenEnabled(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FIREBASE_ENABLED", "true")

	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "FIREBASE_PROJECT_ID") {
		t.Fatalf("expected Firebase project validation error, got %v", err)
	}
}

func TestFirebaseMessagingCanBeEnabledExplicitly(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FIREBASE_ENABLED", "true")
	t.Setenv("FIREBASE_PROJECT_ID", "configured-project")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.FirebaseMessagingEnabled() {
		t.Fatal("Firebase Messaging should be enabled")
	}
}
