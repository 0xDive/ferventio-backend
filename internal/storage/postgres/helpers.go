package postgres

import (
	"crypto/cipher"
	"encoding/json"
	"time"

	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/domain"
	securitypkg "github.com/0xDive/ferventio-backend/internal/security"
)

var (
	ErrNotFound       = domain.ErrRegistrationNotFound
	ErrSecretMismatch = domain.ErrDeviceSecretMismatch
)

type Config = config.Config

func DecodeAuthKey(value string) ([]byte, error) { return config.DecodeAuthKey(value) }
func HashSecret(value string) string             { return securitypkg.HashSecret(value) }
func SecureHashEqual(left, right string) bool    { return securitypkg.EqualHash(left, right) }
func RandomToken(prefix string, size int) (string, error) {
	return securitypkg.RandomToken(prefix, size)
}
func SealAuthValue(aead cipher.AEAD, purpose, value string) (domain.EncryptedValue, error) {
	return securitypkg.Seal(aead, purpose, value)
}
func OpenAuthValue(aead cipher.AEAD, purpose string, value domain.EncryptedValue) (string, error) {
	return securitypkg.Open(aead, purpose, value)
}
func RetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return time.Duration(1<<MinInt(attempt-1, 6)) * time.Second
}
func MinInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func CloneSettingsSyncSnapshot(value domain.SettingsSyncSnapshot) domain.SettingsSyncSnapshot {
	value.Payload = append(json.RawMessage(nil), value.Payload...)
	return value
}
func NonNilJSON(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}
