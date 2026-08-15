package config

import (
	"encoding/base64"
	"testing"
)

func TestLoadAPNsConfigDisabledByDefault(t *testing.T) {
	clearAPNsEnvironment(t)

	cfg, err := LoadAPNsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("APNs must be disabled by default")
	}
	if cfg.BundleID != "io.ferventio.ios" {
		t.Fatalf("BundleID = %q, want io.ferventio.ios", cfg.BundleID)
	}
	if cfg.Environment != APNsEnvironmentProduction {
		t.Fatalf("Environment = %q, want production", cfg.Environment)
	}
}

func TestLoadAPNsConfigRequiresCompleteEnabledConfiguration(t *testing.T) {
	clearAPNsEnvironment(t)
	t.Setenv("APNS_ENABLED", "true")

	if _, err := LoadAPNsConfig(); err == nil {
		t.Fatal("expected incomplete enabled APNs configuration to fail")
	}
}

func TestLoadAPNsConfigAcceptsSandboxConfiguration(t *testing.T) {
	clearAPNsEnvironment(t)
	t.Setenv("APNS_ENABLED", "true")
	t.Setenv("APNS_TEAM_ID", "TEAM123456")
	t.Setenv("APNS_KEY_ID", "KEY1234567")
	t.Setenv("APNS_PRIVATE_KEY_BASE64", base64.StdEncoding.EncodeToString([]byte("private-key")))
	t.Setenv("APNS_BUNDLE_ID", "io.ferventio.ios.debug")
	t.Setenv("APNS_ENVIRONMENT", "SANDBOX")

	cfg, err := LoadAPNsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.Environment != APNsEnvironmentSandbox {
		t.Fatalf("unexpected APNs config: %+v", cfg)
	}
	if cfg.BundleID != "io.ferventio.ios.debug" {
		t.Fatalf("BundleID = %q", cfg.BundleID)
	}
}

func TestLoadAPNsConfigRejectsInvalidEnvironment(t *testing.T) {
	clearAPNsEnvironment(t)
	t.Setenv("APNS_ENABLED", "true")
	t.Setenv("APNS_TEAM_ID", "TEAM123456")
	t.Setenv("APNS_KEY_ID", "KEY1234567")
	t.Setenv("APNS_PRIVATE_KEY_BASE64", base64.StdEncoding.EncodeToString([]byte("private-key")))
	t.Setenv("APNS_ENVIRONMENT", "staging")

	if _, err := LoadAPNsConfig(); err == nil {
		t.Fatal("expected invalid APNS_ENVIRONMENT to fail")
	}
}

func clearAPNsEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"APNS_ENABLED",
		"APNS_TEAM_ID",
		"APNS_KEY_ID",
		"APNS_PRIVATE_KEY_BASE64",
		"APNS_BUNDLE_ID",
		"APNS_ENVIRONMENT",
	} {
		t.Setenv(name, "")
	}
}
