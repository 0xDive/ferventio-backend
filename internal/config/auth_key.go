package config

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// DecodeAuthKey validates and decodes the 256-bit key used to encrypt OAuth tokens.
func DecodeAuthKey(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("AUTH_ENCRYPTION_KEY is required")
	}
	for _, decoder := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if decoded, err := decoder.DecodeString(value); err == nil {
			if len(decoded) != 32 {
				return nil, fmt.Errorf("AUTH_ENCRYPTION_KEY must decode to 32 bytes, got %d", len(decoded))
			}
			return decoded, nil
		}
	}
	return nil, errors.New("AUTH_ENCRYPTION_KEY must be base64 or base64url")
}
