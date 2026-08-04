package domain

import (
	"errors"
	"time"
)

var (
	ErrAuthNotFound       = errors.New("authentication record not found")
	ErrAuthExpired        = errors.New("authentication record expired")
	ErrAuthDeviceMismatch = errors.New("authentication device mismatch")
	ErrAuthStateMismatch  = errors.New("authentication state mismatch")
	ErrAuthCapacity       = errors.New("authentication store capacity exceeded")
)

const (
	MaxPendingAuthRecords = 10_000
	MaxAuthHandoffs       = 10_000
	MaxAuthSessions       = 100_000
)

type EncryptedValue struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type AuthCredentialRecord struct {
	ID              string         `json:"id"`
	ClientID        string         `json:"clientId"`
	UserID          string         `json:"userId"`
	Login           string         `json:"login"`
	Scopes          []string       `json:"scopes"`
	AccessToken     EncryptedValue `json:"accessToken"`
	RefreshToken    EncryptedValue `json:"refreshToken"`
	AccessExpiresAt time.Time      `json:"accessExpiresAt"`
	LastValidatedAt time.Time      `json:"lastValidatedAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
}

type AuthCredential struct {
	ID              string
	ClientID        string
	UserID          string
	Login           string
	Scopes          []string
	AccessToken     string
	RefreshToken    string
	AccessExpiresAt time.Time
	LastValidatedAt time.Time
	UpdatedAt       time.Time
}

type AuthSessionRecord struct {
	CredentialID   string    `json:"credentialId"`
	InstallationID string    `json:"installationId"`
	DeviceHash     string    `json:"deviceHash"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type PendingAuthRecord struct {
	InstallationID string    `json:"installationId"`
	DeviceHash     string    `json:"deviceHash"`
	AppCallbackURI string    `json:"appCallbackUri"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type AuthHandoffRecord struct {
	CredentialID   string    `json:"credentialId"`
	InstallationID string    `json:"installationId"`
	DeviceHash     string    `json:"deviceHash"`
	AppCallbackURI string    `json:"appCallbackUri"`
	StateHash      string    `json:"stateHash"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type AuthDiskState struct {
	Version     int                             `json:"version"`
	Credentials map[string]AuthCredentialRecord `json:"credentials"`
	Sessions    map[string]AuthSessionRecord    `json:"sessions"`
	Pending     map[string]PendingAuthRecord    `json:"pending"`
	Handoffs    map[string]AuthHandoffRecord    `json:"handoffs"`
}

type AccountRevocationTargets struct {
	InstallationIDs []string
	Credentials     []AuthCredential
}

type AccountRevocationResult struct {
	RemovedSessions    int
	RemovedCredentials int
}
