package push

import (
	"context"
	"testing"

	"github.com/0xDive/ferventio-backend/internal/config"
)

func TestNewSenderDoesNotResolveCredentialsWhenFirebaseDisabled(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", t.TempDir()+"/missing.json")

	sender, err := NewSender(context.Background(), config.Config{
		FirebaseEnabled:   false,
		FirebaseProjectID: "configured-project",
	})
	if err != nil {
		t.Fatalf("disabled Firebase must not resolve ADC: %v", err)
	}
	if sender.firebaseClient != nil {
		t.Fatal("disabled Firebase unexpectedly created a messaging client")
	}
}
