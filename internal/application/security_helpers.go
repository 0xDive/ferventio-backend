package application

import (
	"encoding/json"
	"time"

	"github.com/0xDive/ferventio-backend/internal/domain"
	securitypkg "github.com/0xDive/ferventio-backend/internal/security"
)

func randomToken(prefix string, size int) (string, error) {
	return securitypkg.RandomToken(prefix, size)
}
func hashSecret(value string) string { return securitypkg.HashSecret(value) }
func secureHashEqual(left, right string) bool {
	return securitypkg.EqualHash(left, right)
}
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return time.Duration(1<<minInt(attempt-1, 6)) * time.Second
}
func cloneSettingsSyncSnapshot(snapshot domain.SettingsSyncSnapshot) domain.SettingsSyncSnapshot {
	snapshot.Payload = append(json.RawMessage(nil), snapshot.Payload...)
	return snapshot
}
