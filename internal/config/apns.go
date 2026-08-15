package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	APNsEnvironmentProduction = "production"
	APNsEnvironmentSandbox    = "sandbox"
)

// APNsConfig contains the token-authentication settings required by the push
// adapter. The private key is supplied as base64-encoded .p8 PEM so multiline
// secret material never needs to be embedded directly in a dotenv file.
type APNsConfig struct {
	Enabled          bool
	TeamID           string
	KeyID            string
	PrivateKeyBase64 string
	BundleID         string
	Environment      string
}

func LoadAPNsConfig() (APNsConfig, error) {
	source, err := loadConfigSource()
	if err != nil {
		return APNsConfig{}, err
	}
	enabled, err := source.boolean("APNS_ENABLED", false)
	if err != nil {
		return APNsConfig{}, err
	}
	cfg := APNsConfig{
		Enabled:          enabled,
		TeamID:           strings.TrimSpace(source.value("APNS_TEAM_ID")),
		KeyID:            strings.TrimSpace(source.value("APNS_KEY_ID")),
		PrivateKeyBase64: strings.TrimSpace(source.value("APNS_PRIVATE_KEY_BASE64")),
		BundleID:         strings.TrimSpace(source.valueOr("APNS_BUNDLE_ID", "io.ferventio.ios")),
		Environment:      strings.ToLower(strings.TrimSpace(source.valueOr("APNS_ENVIRONMENT", APNsEnvironmentProduction))),
	}
	if !cfg.Enabled {
		return cfg, nil
	}

	if cfg.TeamID == "" || cfg.KeyID == "" || cfg.PrivateKeyBase64 == "" || cfg.BundleID == "" {
		return APNsConfig{}, errors.New("APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY_BASE64, and APNS_BUNDLE_ID are required when APNS_ENABLED=true")
	}
	if cfg.Environment != APNsEnvironmentProduction && cfg.Environment != APNsEnvironmentSandbox {
		return APNsConfig{}, fmt.Errorf("APNS_ENVIRONMENT must be %q or %q", APNsEnvironmentProduction, APNsEnvironmentSandbox)
	}
	if _, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyBase64); err != nil {
		return APNsConfig{}, fmt.Errorf("APNS_PRIVATE_KEY_BASE64 must contain valid base64: %w", err)
	}
	return cfg, nil
}
