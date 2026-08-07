package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRejectsInsecureOAuthEndpoints(t *testing.T) {
	setValidAuthEnvironment(t)
	t.Setenv("TWITCH_ID_BASE_URL", "http://id.example.test")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "TWITCH_ID_BASE_URL must use HTTPS") {
		t.Fatalf("expected insecure Twitch ID endpoint rejection, got %v", err)
	}
}

func TestLoadConfigRejectsOverlongClientLease(t *testing.T) {
	setValidAuthEnvironment(t)
	t.Setenv("AUTH_LEASE_TTL", "6m")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "AUTH_LEASE_TTL") {
		t.Fatalf("expected overlong lease rejection, got %v", err)
	}
}

func TestLoadConfigUsesTwoHourOutageReserve(t *testing.T) {
	setValidAuthEnvironment(t)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthAccessRefreshAhead != 2*time.Hour {
		t.Fatalf("unexpected refresh-ahead reserve: %v", cfg.AuthAccessRefreshAhead)
	}
}

func TestLoadConfigRejectsInvalidOutageReserve(t *testing.T) {
	setValidAuthEnvironment(t)
	t.Setenv("AUTH_ACCESS_REFRESH_AHEAD", "25h")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "AUTH_ACCESS_REFRESH_AHEAD") {
		t.Fatalf("expected invalid outage reserve rejection, got %v", err)
	}
}

func TestLoadConfigAllowsLocalOAuthTestEndpoint(t *testing.T) {
	setValidAuthEnvironment(t)
	t.Setenv("TWITCH_ID_BASE_URL", "http://127.0.0.1:18080")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AuthEnabled() {
		t.Fatal("OAuth broker should be enabled")
	}
}

func setValidAuthEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("TWITCH_CLIENT_ID", "client")
	t.Setenv("TWITCH_CLIENT_SECRET", "secret")
	t.Setenv("PUBLIC_BASE_URL", "https://auth.example.test")
	t.Setenv("TWITCH_REDIRECT_URL", "https://auth.example.test/v1/auth/twitch/callback")
	t.Setenv("TWITCH_ID_BASE_URL", "https://id.twitch.tv")
	t.Setenv("AUTH_ENCRYPTION_KEY", testAuthKey())
	t.Setenv("AUTH_LEASE_TTL", "60s")
	t.Setenv("AUTH_ACCESS_REFRESH_AHEAD", "2h")
	t.Setenv("AUTH_STATE_TTL", "10m")
	t.Setenv("AUTH_HANDOFF_TTL", "2m")
}

func TestConfiguredScopesCannotDropRequiredApplicationScopes(t *testing.T) {
	setValidAuthEnvironment(t)
	t.Setenv("TWITCH_AUTH_SCOPES", "user:read:chat")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"user:bot",
		"user:read:chat",
		"user:write:chat",
		"moderator:manage:chat_messages",
		"channel:manage:polls",
		"channel:manage:predictions",
	} {
		found := false
		for _, scope := range cfg.AuthScopes {
			if scope == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("required scope %q was removed by TWITCH_AUTH_SCOPES", required)
		}
	}
}

func TestLoadConfigRejectsInvalidEventSubSecret(t *testing.T) {
	setValidAuthEnvironment(t)
	t.Setenv("EVENTSUB_CALLBACK_URL", "https://auth.example.test/v1/eventsub/webhook")
	t.Setenv("EVENTSUB_SECRET", strings.Repeat("x", 101))
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "EVENTSUB_SECRET") {
		t.Fatalf("expected invalid EventSub secret rejection, got %v", err)
	}
}

func TestLoadConfigRateLimitDefaultsAndTrustedProxyCIDRs(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("RATE_LIMIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 2001:db8::/32")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimitGeneralPerMinute != DefaultRateLimitGeneralPerMinute ||
		cfg.RateLimitAuthBurst != DefaultRateLimitAuthBurst ||
		cfg.RateLimitInstallationPerMinute != DefaultRateLimitInstallationPerMinute {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if len(cfg.RateLimitTrustedProxyCIDRs) != 2 {
		t.Fatalf("unexpected trusted proxy CIDRs: %v", cfg.RateLimitTrustedProxyCIDRs)
	}
}

func TestLoadConfigRejectsInvalidRateLimitConfiguration(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("RATE_LIMIT_AUTH_BURST", "zero")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "RATE_LIMIT_AUTH_BURST") {
		t.Fatalf("expected invalid rate-limit rejection, got %v", err)
	}

	clearConfigEnvironment(t)
	t.Setenv("RATE_LIMIT_TRUSTED_PROXY_CIDRS", "not-a-cidr")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "RATE_LIMIT_TRUSTED_PROXY_CIDRS") {
		t.Fatalf("expected invalid proxy CIDR rejection, got %v", err)
	}
}
