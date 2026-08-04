package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	DefaultRateLimitGeneralPerMinute      = 300
	DefaultRateLimitGeneralBurst          = 60
	DefaultRateLimitAuthPerMinute         = 60
	DefaultRateLimitAuthBurst             = 15
	DefaultRateLimitInstallationPerMinute = 120
	DefaultRateLimitInstallationBurst     = 30
	DefaultRateLimitAdminPerMinute        = 120
	DefaultRateLimitAdminBurst            = 30
	DefaultRateLimitMaxKeys               = 50_000
	DefaultRateLimitIdleTTL               = 30 * time.Minute
)

type loadedRateLimitConfig struct {
	disabled              bool
	trustedProxyCIDRs     []netip.Prefix
	generalPerMinute      int
	generalBurst          int
	authPerMinute         int
	authBurst             int
	installationPerMinute int
	installationBurst     int
	adminPerMinute        int
	adminBurst            int
	maxKeys               int
	idleTTL               time.Duration
}

func loadRateLimitConfig(source configSource) (loadedRateLimitConfig, error) {
	var result loadedRateLimitConfig
	var err error
	if result.disabled, err = source.boolean("RATE_LIMIT_DISABLED", false); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.generalPerMinute, err = source.positiveInt("RATE_LIMIT_GENERAL_PER_MINUTE", DefaultRateLimitGeneralPerMinute); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.generalBurst, err = source.positiveInt("RATE_LIMIT_GENERAL_BURST", DefaultRateLimitGeneralBurst); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.authPerMinute, err = source.positiveInt("RATE_LIMIT_AUTH_PER_MINUTE", DefaultRateLimitAuthPerMinute); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.authBurst, err = source.positiveInt("RATE_LIMIT_AUTH_BURST", DefaultRateLimitAuthBurst); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.installationPerMinute, err = source.positiveInt("RATE_LIMIT_INSTALLATION_PER_MINUTE", DefaultRateLimitInstallationPerMinute); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.installationBurst, err = source.positiveInt("RATE_LIMIT_INSTALLATION_BURST", DefaultRateLimitInstallationBurst); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.adminPerMinute, err = source.positiveInt("RATE_LIMIT_ADMIN_PER_MINUTE", DefaultRateLimitAdminPerMinute); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.adminBurst, err = source.positiveInt("RATE_LIMIT_ADMIN_BURST", DefaultRateLimitAdminBurst); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.maxKeys, err = source.positiveInt("RATE_LIMIT_MAX_KEYS", DefaultRateLimitMaxKeys); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.idleTTL, err = source.positiveDuration("RATE_LIMIT_IDLE_TTL", DefaultRateLimitIdleTTL); err != nil {
		return loadedRateLimitConfig{}, err
	}
	if result.generalPerMinute > 100_000 || result.authPerMinute > 100_000 || result.installationPerMinute > 100_000 || result.adminPerMinute > 100_000 {
		return loadedRateLimitConfig{}, fmt.Errorf("rate limits per minute must not exceed 100000")
	}
	if result.generalBurst > 10_000 || result.authBurst > 10_000 || result.installationBurst > 10_000 || result.adminBurst > 10_000 {
		return loadedRateLimitConfig{}, fmt.Errorf("rate limit bursts must not exceed 10000")
	}
	if result.maxKeys < 100 || result.maxKeys > 1_000_000 {
		return loadedRateLimitConfig{}, fmt.Errorf("RATE_LIMIT_MAX_KEYS must be between 100 and 1000000")
	}
	if result.idleTTL < time.Minute || result.idleTTL > 24*time.Hour {
		return loadedRateLimitConfig{}, fmt.Errorf("RATE_LIMIT_IDLE_TTL must be between 1m and 24h")
	}
	result.trustedProxyCIDRs, err = parseTrustedProxyCIDRs(source.value("RATE_LIMIT_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return loadedRateLimitConfig{}, err
	}
	return result, nil
}

func parseTrustedProxyCIDRs(raw string) ([]netip.Prefix, error) {
	values := strings.FieldsFunc(raw, func(character rune) bool {
		return character == ',' || character == ';' || character == ' ' || character == '\t' || character == '\n'
	})
	result := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("RATE_LIMIT_TRUSTED_PROXY_CIDRS contains invalid CIDR %q", value)
		}
		prefix = prefix.Masked()
		key := prefix.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, prefix)
	}
	return result, nil
}
