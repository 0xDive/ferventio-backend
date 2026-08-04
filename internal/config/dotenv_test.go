package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigReadsServerDotEnvAutomatically(t *testing.T) {
	projectRoot := t.TempDir()
	serverDirectory := filepath.Join(projectRoot, "server")
	if err := os.MkdirAll(serverDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(serverDirectory, ".env")
	contents := strings.Join([]string{
		"TWITCH_CLIENT_ID=dotenv-client",
		"TWITCH_CLIENT_SECRET='dotenv-secret'",
		"PUBLIC_BASE_URL=https://ferventio.example.test",
		"AUTH_ENCRYPTION_KEY=\"" + testAuthKey() + "\"",
		"AUTH_ALLOWED_APP_SCHEMES=io.ferventio.app,io.ferventio.app.debug",
		"AUTH_LEASE_TTL=60s",
		"AUTH_ACCESS_REFRESH_AHEAD=2h",
		"AUTH_STATE_TTL=10m",
		"AUTH_HANDOFF_TTL=2m",
		"LISTEN_ADDRESS=:9191 # inline comment",
	}, "\n") + "\n"
	if err := os.WriteFile(envPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	clearConfigEnvironment(t)
	t.Setenv(explicitEnvFileVariable, "")
	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AuthEnabled() {
		t.Fatal("OAuth broker should be enabled from .env without shell exports")
	}
	expectedEnvInfo, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedEnvInfo, err := os.Stat(cfg.EnvFilePath)
	if err != nil {
		t.Fatalf("stat loaded dotenv path %q: %v", cfg.EnvFilePath, err)
	}
	if !os.SameFile(expectedEnvInfo, loadedEnvInfo) {
		t.Fatalf("unexpected dotenv path: got %q, want file %q", cfg.EnvFilePath, envPath)
	}
	if cfg.TwitchClientID != "dotenv-client" || cfg.TwitchClientSecret != "dotenv-secret" {
		t.Fatal("Twitch credentials were not loaded from .env")
	}
	if cfg.TwitchRedirectURL != "https://ferventio.example.test/v1/auth/twitch/callback" {
		t.Fatalf("redirect was not derived from PUBLIC_BASE_URL: %q", cfg.TwitchRedirectURL)
	}
	if cfg.ListenAddress != ":9191" {
		t.Fatalf("inline comment was not removed: %q", cfg.ListenAddress)
	}
}

func TestProcessEnvironmentOverridesDotEnv(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("LISTEN_ADDRESS=:9191\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(explicitEnvFileVariable, envPath)
	t.Setenv("LISTEN_ADDRESS", ":9292")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != ":9292" {
		t.Fatalf("process environment must override .env, got %q", cfg.ListenAddress)
	}
}

func TestExplicitDotEnvPathFailsFastWhenMissing(t *testing.T) {
	t.Setenv(explicitEnvFileVariable, filepath.Join(t.TempDir(), "missing.env"))
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), explicitEnvFileVariable) {
		t.Fatalf("expected explicit dotenv path error, got %v", err)
	}
}

func TestParseDotEnvSupportsExportAndQuotes(t *testing.T) {
	values, err := parseDotEnv(strings.NewReader(strings.Join([]string{
		"# comment",
		"export FIRST=one",
		"SECOND='two # literal'",
		`THIRD="line\nvalue"`,
		"FOURTH=value # comment",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if values["FIRST"] != "one" || values["SECOND"] != "two # literal" || values["FOURTH"] != "value" {
		t.Fatalf("unexpected dotenv values: %#v", values)
	}
	if values["THIRD"] != "line\nvalue" {
		t.Fatalf("double-quoted escape was not decoded: %q", values["THIRD"])
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"TWITCH_CLIENT_ID",
		"TWITCH_CLIENT_SECRET",
		"PUBLIC_BASE_URL",
		"TWITCH_REDIRECT_URL",
		"AUTH_ENCRYPTION_KEY",
		"AUTH_ALLOWED_APP_SCHEMES",
		"AUTH_LEASE_TTL",
		"AUTH_ACCESS_REFRESH_AHEAD",
		"AUTH_STATE_TTL",
		"AUTH_HANDOFF_TTL",
		"LISTEN_ADDRESS",
		"FIREBASE_ENABLED",
		"FIREBASE_PROJECT_ID",
		"RATE_LIMIT_DISABLED",
		"RATE_LIMIT_TRUSTED_PROXY_CIDRS",
		"RATE_LIMIT_GENERAL_PER_MINUTE",
		"RATE_LIMIT_GENERAL_BURST",
		"RATE_LIMIT_AUTH_PER_MINUTE",
		"RATE_LIMIT_AUTH_BURST",
		"RATE_LIMIT_INSTALLATION_PER_MINUTE",
		"RATE_LIMIT_INSTALLATION_BURST",
		"RATE_LIMIT_ADMIN_PER_MINUTE",
		"RATE_LIMIT_ADMIN_BURST",
		"RATE_LIMIT_MAX_KEYS",
		"RATE_LIMIT_IDLE_TTL",
	} {
		t.Setenv(name, "")
	}
}
