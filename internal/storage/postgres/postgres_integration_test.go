//go:build integration

package postgres

import (
	"context"
	"errors"
	. "github.com/0xDive/ferventio-backend/internal/domain"
	"os"
	"testing"
	"time"
)

func TestPostgresStorageRegistrationRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	storage, err := OpenPostgresStorage(ctx, Config{
		DatabaseURL:             databaseURL,
		DatabaseMaxConns:        4,
		DatabaseMinConns:        1,
		DatabaseMaxConnLifetime: 10 * time.Minute,
		DatabaseMaxConnIdleTime: time.Minute,
		DatabaseConnectTimeout:  10 * time.Second,
		DatabaseMigrate:         true,
	})
	if err != nil {
		t.Fatalf("open PostgreSQL storage: %v", err)
	}
	defer storage.Close()

	installationID := "integration-" + time.Now().UTC().Format("20060102150405.000000000")
	secret := "integration-device-secret"
	registration := Registration{
		InstallationID: installationID,
		DeviceSecret:   secret,
		Provider:       "embedded_socket",
		AppVersion:     "integration-test",
		Platform:       "android",
		ChannelIDs:     []string{"123"},
		UpdatedAt:      time.Now().UTC(),
	}
	if err := storage.Upsert(registration); err != nil {
		t.Fatalf("upsert registration: %v", err)
	}
	t.Cleanup(func() {
		if err := storage.Delete(installationID, secret); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("clean registration: %v", err)
		}
	})

	loaded, err := storage.Authenticate(installationID, secret)
	if err != nil {
		t.Fatalf("authenticate registration: %v", err)
	}
	if loaded.InstallationID != installationID || loaded.DeviceSecret != "" || loaded.DeviceSecretHash != "" {
		t.Fatalf("unexpected public registration: %#v", loaded)
	}
	if len(loaded.ChannelIDs) != 1 || loaded.ChannelIDs[0] != "123" {
		t.Fatalf("unexpected channels: %#v", loaded.ChannelIDs)
	}
	if _, err := storage.Authenticate(installationID, "wrong-secret"); !errors.Is(err, ErrSecretMismatch) {
		t.Fatalf("wrong secret error = %v, want ErrSecretMismatch", err)
	}
	if err := storage.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}
}

func TestPostgresSettingsFirstWriteSerializes(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	storage, err := OpenPostgresStorage(ctx, Config{
		DatabaseURL:             databaseURL,
		DatabaseMaxConns:        4,
		DatabaseMinConns:        1,
		DatabaseMaxConnLifetime: 10 * time.Minute,
		DatabaseMaxConnIdleTime: time.Minute,
		DatabaseConnectTimeout:  10 * time.Second,
		DatabaseMigrate:         true,
	})
	if err != nil {
		t.Fatalf("open PostgreSQL storage: %v", err)
	}
	defer storage.Close()

	userID := "settings-concurrency-" + time.Now().UTC().Format("20060102150405.000000000")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := storage.pool.Exec(cleanupCtx, "DELETE FROM settings_sync_snapshots WHERE user_id = $1", userID); err != nil {
			t.Errorf("clean settings snapshots: %v", err)
		}
	})

	start := make(chan struct{})
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			_, err := storage.Put(
				userID,
				"installation-"+string(rune('a'+index)),
				0,
				false,
				"integration-test",
				"hash-"+string(rune('a'+index)),
				[]byte(`{"theme":"dark"}`),
			)
			results <- err
		}()
	}
	close(start)

	successes := 0
	conflicts := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrSettingsSyncConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent write error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want one of each", successes, conflicts)
	}
}
