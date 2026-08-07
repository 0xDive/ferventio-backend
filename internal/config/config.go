package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	EnvFilePath                    string
	ListenAddress                  string
	DatabaseURL                    string
	DatabaseMaxConns               int32
	DatabaseMinConns               int32
	DatabaseMaxConnLifetime        time.Duration
	DatabaseMaxConnIdleTime        time.Duration
	DatabaseConnectTimeout         time.Duration
	DatabaseMigrate                bool
	FirebaseEnabled                bool
	FirebaseProjectID              string
	TwitchClientID                 string
	TwitchClientSecret             string
	TwitchRedirectURL              string
	TwitchIDBaseURL                string
	TwitchHelixBaseURL             string
	PublicBaseURL                  string
	EventSubSecret                 string
	EventSubCallbackURL            string
	AuthEncryptionKey              string
	AuthAllowedAppSchemes          []string
	AuthScopes                     []string
	AuthSessionTTL                 time.Duration
	AuthStateTTL                   time.Duration
	AuthHandoffTTL                 time.Duration
	AuthLeaseTTL                   time.Duration
	AuthAccessRefreshAhead         time.Duration
	VAPIDPublicKey                 string
	VAPIDPrivateKey                string
	VAPIDSubscriber                string
	AdminToken                     string
	ReadHeaderTimeout              time.Duration
	RequestBodyMaxBytes            int64
	RateLimitDisabled              bool
	RateLimitTrustedProxyCIDRs     []netip.Prefix
	RateLimitGeneralPerMinute      int
	RateLimitGeneralBurst          int
	RateLimitAuthPerMinute         int
	RateLimitAuthBurst             int
	RateLimitInstallationPerMinute int
	RateLimitInstallationBurst     int
	RateLimitAdminPerMinute        int
	RateLimitAdminBurst            int
	RateLimitMaxKeys               int
	RateLimitIdleTTL               time.Duration
}

func LoadConfig() (Config, error) {
	source, err := loadConfigSource()
	if err != nil {
		return Config{}, err
	}
	rateLimits, err := loadRateLimitConfig(source)
	if err != nil {
		return Config{}, err
	}
	databaseMaxConns, err := source.positiveInt("DATABASE_MAX_CONNS", 20)
	if err != nil {
		return Config{}, err
	}
	databaseMinConns, err := source.nonNegativeInt("DATABASE_MIN_CONNS", 2)
	if err != nil {
		return Config{}, err
	}
	databaseMigrate, err := source.boolean("DATABASE_MIGRATE", true)
	if err != nil {
		return Config{}, err
	}
	firebaseEnabled, err := source.boolean("FIREBASE_ENABLED", false)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		EnvFilePath:                    source.envFilePath,
		ListenAddress:                  source.valueOr("LISTEN_ADDRESS", ":8080"),
		DatabaseURL:                    source.valueOr("DATABASE_URL", "postgres://ferventio:ferventio@localhost:5432/ferventio?sslmode=disable"),
		DatabaseMaxConns:               int32(databaseMaxConns),
		DatabaseMinConns:               int32(databaseMinConns),
		DatabaseMaxConnLifetime:        source.duration("DATABASE_MAX_CONN_LIFETIME", 30*time.Minute),
		DatabaseMaxConnIdleTime:        source.duration("DATABASE_MAX_CONN_IDLE_TIME", 5*time.Minute),
		DatabaseConnectTimeout:         source.duration("DATABASE_CONNECT_TIMEOUT", 10*time.Second),
		DatabaseMigrate:                databaseMigrate,
		FirebaseEnabled:                firebaseEnabled,
		FirebaseProjectID:              strings.TrimSpace(source.value("FIREBASE_PROJECT_ID")),
		TwitchClientID:                 strings.TrimSpace(source.value("TWITCH_CLIENT_ID")),
		TwitchClientSecret:             strings.TrimSpace(source.value("TWITCH_CLIENT_SECRET")),
		TwitchRedirectURL:              strings.TrimSpace(source.value("TWITCH_REDIRECT_URL")),
		TwitchIDBaseURL:                source.valueOr("TWITCH_ID_BASE_URL", "https://id.twitch.tv"),
		TwitchHelixBaseURL:             source.valueOr("TWITCH_HELIX_BASE_URL", "https://api.twitch.tv/helix"),
		PublicBaseURL:                  strings.TrimSuffix(strings.TrimSpace(source.value("PUBLIC_BASE_URL")), "/"),
		EventSubSecret:                 strings.TrimSpace(source.value("EVENTSUB_SECRET")),
		EventSubCallbackURL:            strings.TrimSpace(source.value("EVENTSUB_CALLBACK_URL")),
		AuthEncryptionKey:              strings.TrimSpace(source.value("AUTH_ENCRYPTION_KEY")),
		AuthAllowedAppSchemes:          splitCSV(source.valueOr("AUTH_ALLOWED_APP_SCHEMES", "io.ferventio.app,io.ferventio.app.debug")),
		AuthScopes:                     mergeAuthScopes(splitFields(source.valueOr("TWITCH_AUTH_SCOPES", ""))),
		AuthSessionTTL:                 source.duration("AUTH_SESSION_TTL", 365*24*time.Hour),
		AuthStateTTL:                   source.duration("AUTH_STATE_TTL", 10*time.Minute),
		AuthHandoffTTL:                 source.duration("AUTH_HANDOFF_TTL", 2*time.Minute),
		AuthLeaseTTL:                   source.duration("AUTH_LEASE_TTL", 60*time.Second),
		AuthAccessRefreshAhead:         source.duration("AUTH_ACCESS_REFRESH_AHEAD", 2*time.Hour),
		VAPIDPublicKey:                 strings.TrimSpace(source.value("VAPID_PUBLIC_KEY")),
		VAPIDPrivateKey:                strings.TrimSpace(source.value("VAPID_PRIVATE_KEY")),
		VAPIDSubscriber:                source.valueOr("VAPID_SUBSCRIBER", "mailto:admin@example.com"),
		AdminToken:                     strings.TrimSpace(source.value("ADMIN_TOKEN")),
		ReadHeaderTimeout:              10 * time.Second,
		RequestBodyMaxBytes:            64 << 10,
		RateLimitDisabled:              rateLimits.disabled,
		RateLimitTrustedProxyCIDRs:     rateLimits.trustedProxyCIDRs,
		RateLimitGeneralPerMinute:      rateLimits.generalPerMinute,
		RateLimitGeneralBurst:          rateLimits.generalBurst,
		RateLimitAuthPerMinute:         rateLimits.authPerMinute,
		RateLimitAuthBurst:             rateLimits.authBurst,
		RateLimitInstallationPerMinute: rateLimits.installationPerMinute,
		RateLimitInstallationBurst:     rateLimits.installationBurst,
		RateLimitAdminPerMinute:        rateLimits.adminPerMinute,
		RateLimitAdminBurst:            rateLimits.adminBurst,
		RateLimitMaxKeys:               rateLimits.maxKeys,
		RateLimitIdleTTL:               rateLimits.idleTTL,
	}

	if cfg.DatabaseMaxConns < 1 || cfg.DatabaseMaxConns > 500 {
		return Config{}, fmt.Errorf("DATABASE_MAX_CONNS must be between 1 and 500")
	}
	if cfg.DatabaseMinConns < 0 || cfg.DatabaseMinConns > cfg.DatabaseMaxConns {
		return Config{}, fmt.Errorf("DATABASE_MIN_CONNS must be between 0 and DATABASE_MAX_CONNS")
	}
	if cfg.DatabaseConnectTimeout <= 0 || cfg.DatabaseConnectTimeout > time.Minute {
		return Config{}, fmt.Errorf("DATABASE_CONNECT_TIMEOUT must be greater than zero and not exceed 1m")
	}
	parsedDatabaseURL, err := url.Parse(cfg.DatabaseURL)
	if err != nil || (parsedDatabaseURL.Scheme != "postgres" && parsedDatabaseURL.Scheme != "postgresql") || parsedDatabaseURL.Host == "" {
		return Config{}, fmt.Errorf("DATABASE_URL must be an absolute postgres:// or postgresql:// URL")
	}

	if cfg.FirebaseEnabled && cfg.FirebaseProjectID == "" {
		return Config{}, fmt.Errorf("FIREBASE_PROJECT_ID is required when FIREBASE_ENABLED=true")
	}
	if cfg.VAPIDPublicKey == "" != (cfg.VAPIDPrivateKey == "") {
		return Config{}, fmt.Errorf("VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY must be configured together")
	}
	if cfg.TwitchClientID == "" != (cfg.TwitchClientSecret == "") {
		return Config{}, fmt.Errorf("TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET must be configured together")
	}
	if cfg.TwitchRedirectURL == "" && cfg.PublicBaseURL != "" {
		cfg.TwitchRedirectURL = cfg.PublicBaseURL + "/v1/auth/twitch/callback"
	}
	if cfg.PublicBaseURL == "" && cfg.TwitchRedirectURL != "" {
		if parsed, err := url.Parse(cfg.TwitchRedirectURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			cfg.PublicBaseURL = parsed.Scheme + "://" + parsed.Host
		}
	}
	if cfg.EventSubCallbackURL == "" && cfg.PublicBaseURL != "" {
		cfg.EventSubCallbackURL = cfg.PublicBaseURL + "/v1/eventsub/webhook"
	}
	if cfg.EventSubSecret != "" {
		if len(cfg.EventSubSecret) < 16 || len(cfg.EventSubSecret) > 100 {
			return Config{}, fmt.Errorf("EVENTSUB_SECRET must contain 16 to 100 ASCII characters")
		}
		for _, character := range cfg.EventSubSecret {
			if character < 0x20 || character > 0x7e {
				return Config{}, fmt.Errorf("EVENTSUB_SECRET must contain 16 to 100 ASCII characters")
			}
		}
		if cfg.EventSubCallbackURL == "" {
			return Config{}, fmt.Errorf("EVENTSUB_CALLBACK_URL or PUBLIC_BASE_URL is required when EVENTSUB_SECRET is configured")
		}
		if err := validateSecureHTTPURL(cfg.EventSubCallbackURL, "EVENTSUB_CALLBACK_URL", true); err != nil {
			return Config{}, err
		}
		if err := validateSecureHTTPURL(cfg.TwitchHelixBaseURL, "TWITCH_HELIX_BASE_URL", true); err != nil {
			return Config{}, err
		}
	}
	if cfg.AuthEncryptionKey != "" {
		if cfg.TwitchClientID == "" || cfg.TwitchClientSecret == "" {
			return Config{}, fmt.Errorf("server OAuth requires TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET")
		}
		if cfg.TwitchRedirectURL == "" || cfg.PublicBaseURL == "" {
			return Config{}, fmt.Errorf("server OAuth requires PUBLIC_BASE_URL or TWITCH_REDIRECT_URL")
		}
		if _, err := DecodeAuthKey(cfg.AuthEncryptionKey); err != nil {
			return Config{}, err
		}
		if err := validateSecureHTTPURL(cfg.TwitchRedirectURL, "TWITCH_REDIRECT_URL", true); err != nil {
			return Config{}, err
		}
		if err := validateSecureHTTPURL(cfg.TwitchIDBaseURL, "TWITCH_ID_BASE_URL", false); err != nil {
			return Config{}, err
		}
		if err := validatePublicBaseURL(cfg.PublicBaseURL); err != nil {
			return Config{}, err
		}
		if len(cfg.AuthAllowedAppSchemes) == 0 {
			return Config{}, fmt.Errorf("AUTH_ALLOWED_APP_SCHEMES must not be empty")
		}
		if len(cfg.AuthScopes) == 0 {
			return Config{}, fmt.Errorf("TWITCH_AUTH_SCOPES must not be empty")
		}
		if cfg.AuthLeaseTTL <= 0 || cfg.AuthLeaseTTL > 5*time.Minute {
			return Config{}, fmt.Errorf("AUTH_LEASE_TTL must be greater than zero and not exceed 5m")
		}
		if cfg.AuthAccessRefreshAhead < 5*time.Minute || cfg.AuthAccessRefreshAhead > 24*time.Hour {
			return Config{}, fmt.Errorf("AUTH_ACCESS_REFRESH_AHEAD must be between 5m and 24h")
		}
		if cfg.AuthStateTTL > 30*time.Minute || cfg.AuthHandoffTTL > 10*time.Minute {
			return Config{}, fmt.Errorf("OAuth state/handoff TTL is too long")
		}
	}
	return cfg, nil
}

func (c Config) FirebaseMessagingEnabled() bool {
	return c.FirebaseEnabled && c.FirebaseProjectID != ""
}

func (c Config) AuthEnabled() bool {
	return c.AuthEncryptionKey != "" && c.TwitchClientID != "" && c.TwitchClientSecret != "" && c.TwitchRedirectURL != "" && c.PublicBaseURL != ""
}

func validateSecureHTTPURL(raw, name string, allowPath bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials, query, or fragment", name)
	}
	host := strings.ToLower(parsed.Hostname())
	local := host == "localhost" || host == "127.0.0.1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return fmt.Errorf("%s must use HTTPS outside localhost", name)
	}
	if !allowPath && strings.Trim(parsed.EscapedPath(), "/") != "" {
		return fmt.Errorf("%s must not contain a path", name)
	}
	return nil
}

func validatePublicBaseURL(raw string) error {
	return validateSecureHTTPURL(raw, "PUBLIC_BASE_URL", true)
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func splitFields(value string) []string {
	return strings.Fields(value)
}

func mergeAuthScopes(configured []string) []string {
	seen := make(map[string]struct{}, len(defaultTwitchAuthScopes)+len(configured))
	result := make([]string, 0, len(defaultTwitchAuthScopes)+len(configured))
	appendScope := func(scope string) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return
		}
		if _, ok := seen[scope]; ok {
			return
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	for _, scope := range defaultTwitchAuthScopes {
		appendScope(scope)
	}
	for _, scope := range configured {
		appendScope(scope)
	}
	return result
}

var defaultTwitchAuthScopes = []string{
	"user:bot",
	"user:read:chat",
	"user:write:chat",
	"moderator:manage:chat_messages",
	"moderator:manage:banned_users",
	"user:read:moderated_channels",
	"moderator:read:followers",
	"moderator:manage:chat_settings",
	"moderator:read:chatters",
	"clips:edit",
	"channel:manage:broadcast",
	"channel:moderate",
	"moderator:manage:warnings",
	"user:manage:blocked_users",
	"moderator:manage:automod",
	"moderator:read:blocked_terms",
	"moderator:read:unban_requests",
	"moderation:read",
	"moderator:read:banned_users",
	"moderator:read:moderators",
	"moderator:read:vips",
	"channel:read:vips",
	"channel:read:subscriptions",
	"channel:read:redemptions",
	"channel:manage:polls",
	"channel:manage:predictions",
	"user:read:emotes",
}
