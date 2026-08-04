package security

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/0xDive/ferventio-backend/internal/domain"
)

// HashSecret returns a URL-safe SHA-256 digest suitable for storing bearer
// secrets without retaining their plaintext value.
func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// EqualHash compares two encoded hashes in constant time.
func EqualHash(left, right string) bool {
	if len(left) != len(right) || left == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// EqualSecret compares plaintext secrets in constant time.
func EqualSecret(left, right string) bool {
	if len(left) != len(right) || left == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// RandomToken returns a cryptographically secure URL-safe token with a stable
// prefix that identifies its purpose in logs and database records.
func RandomToken(prefix string, size int) (string, error) {
	if size <= 0 {
		return "", errors.New("token size must be positive")
	}
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}

// Seal encrypts one OAuth value with AES-GCM and purpose-bound associated data.
func Seal(aead cipher.AEAD, purpose, plaintext string) (domain.EncryptedValue, error) {
	if aead == nil {
		return domain.EncryptedValue{}, errors.New("auth encryption is not configured")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return domain.EncryptedValue{}, fmt.Errorf("generate auth nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), []byte(purpose))
	return domain.EncryptedValue{
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

// Open decrypts one purpose-bound OAuth value.
func Open(aead cipher.AEAD, purpose string, value domain.EncryptedValue) (string, error) {
	if aead == nil {
		return "", errors.New("auth encryption is not configured")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(value.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode auth nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(value.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode auth ciphertext: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(purpose))
	if err != nil {
		return "", fmt.Errorf("decrypt auth value: %w", err)
	}
	return string(plaintext), nil
}
