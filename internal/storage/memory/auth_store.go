package memory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type AuthStore struct {
	mu    sync.RWMutex
	aead  cipher.AEAD
	state authDiskState
}

func OpenAuthStore(_ string, base64Key string) (*AuthStore, error) {
	key, err := decodeAuthKey(base64Key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create auth cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create auth AEAD: %w", err)
	}
	return &AuthStore{
		aead: aead,
		state: authDiskState{
			Version:     1,
			Credentials: map[string]authCredentialRecord{},
			Sessions:    map[string]authSessionRecord{},
			Pending:     map[string]pendingAuthRecord{},
			Handoffs:    map[string]authHandoffRecord{},
		},
	}, nil
}
func (s *AuthStore) PutPending(state string, record pendingAuthRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now().UTC())
	for key, existing := range s.state.Pending {
		if existing.InstallationID == record.InstallationID && secureHashEqual(existing.DeviceHash, record.DeviceHash) {
			delete(s.state.Pending, key)
		}
	}
	if len(s.state.Pending) >= maxPendingAuthRecords {
		return ErrAuthCapacity
	}
	s.state.Pending[hashSecret(state)] = record
	return s.persistLocked()
}

func (s *AuthStore) GetPending(state string) (pendingAuthRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.state.Pending[hashSecret(state)]
	if !ok {
		return pendingAuthRecord{}, ErrAuthNotFound
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return pendingAuthRecord{}, ErrAuthExpired
	}
	return record, nil
}

func (s *AuthStore) ConsumePending(state string) (pendingAuthRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashSecret(state)
	record, ok := s.state.Pending[key]
	if !ok {
		return pendingAuthRecord{}, ErrAuthNotFound
	}
	delete(s.state.Pending, key)
	if err := s.persistLocked(); err != nil {
		return pendingAuthRecord{}, err
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return pendingAuthRecord{}, ErrAuthExpired
	}
	return record, nil
}

func (s *AuthStore) PutHandoff(code string, record authHandoffRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, existing := range s.state.Handoffs {
		if existing.InstallationID == record.InstallationID && secureHashEqual(existing.DeviceHash, record.DeviceHash) {
			delete(s.state.Handoffs, key)
		}
	}
	s.state.Handoffs[hashSecret(code)] = record
	s.cleanupExpiredLocked(time.Now().UTC())
	if len(s.state.Handoffs) > maxAuthHandoffs {
		delete(s.state.Handoffs, hashSecret(code))
		s.cleanupExpiredLocked(time.Now().UTC())
		if err := s.persistLocked(); err != nil {
			return err
		}
		return ErrAuthCapacity
	}
	return s.persistLocked()
}

func (s *AuthStore) ConsumeHandoff(code, installationID, deviceSecret, state string) (authHandoffRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashSecret(code)
	record, ok := s.state.Handoffs[key]
	if !ok {
		return authHandoffRecord{}, ErrAuthNotFound
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		delete(s.state.Handoffs, key)
		_ = s.persistLocked()
		return authHandoffRecord{}, ErrAuthExpired
	}
	if record.InstallationID != installationID || !secureHashEqual(record.DeviceHash, hashSecret(deviceSecret)) {
		return authHandoffRecord{}, ErrAuthDeviceMismatch
	}
	if !secureHashEqual(record.StateHash, hashSecret(state)) {
		return authHandoffRecord{}, ErrAuthStateMismatch
	}
	delete(s.state.Handoffs, key)
	if err := s.persistLocked(); err != nil {
		return authHandoffRecord{}, err
	}
	return record, nil
}

func (s *AuthStore) PutCredential(credential authCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.setCredentialLocked(credential); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *AuthStore) PutCredentialAndHandoff(
	credential authCredential,
	code string,
	record authHandoffRecord,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if credential.ID == "" || record.CredentialID != credential.ID {
		return errors.New("credential and handoff do not match")
	}
	if err := s.setCredentialLocked(credential); err != nil {
		return err
	}
	for key, existing := range s.state.Handoffs {
		if existing.InstallationID == record.InstallationID && secureHashEqual(existing.DeviceHash, record.DeviceHash) {
			delete(s.state.Handoffs, key)
		}
	}
	handoffKey := hashSecret(code)
	s.state.Handoffs[handoffKey] = record
	s.cleanupExpiredLocked(time.Now().UTC())
	if len(s.state.Handoffs) > maxAuthHandoffs {
		delete(s.state.Handoffs, handoffKey)
		s.cleanupExpiredLocked(time.Now().UTC())
		if err := s.persistLocked(); err != nil {
			return err
		}
		return ErrAuthCapacity
	}
	return s.persistLocked()
}

func (s *AuthStore) setCredentialLocked(credential authCredential) error {
	access, err := s.seal(credential.ID+":access", credential.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := s.seal(credential.ID+":refresh", credential.RefreshToken)
	if err != nil {
		return err
	}
	s.state.Credentials[credential.ID] = authCredentialRecord{
		ID:              credential.ID,
		ClientID:        credential.ClientID,
		UserID:          credential.UserID,
		Login:           credential.Login,
		Scopes:          append([]string(nil), credential.Scopes...),
		AccessToken:     access,
		RefreshToken:    refresh,
		AccessExpiresAt: credential.AccessExpiresAt,
		LastValidatedAt: credential.LastValidatedAt,
		UpdatedAt:       credential.UpdatedAt,
	}
	return nil
}

func (s *AuthStore) GetCredential(id string) (authCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.state.Credentials[id]
	if !ok {
		return authCredential{}, ErrAuthNotFound
	}
	access, err := s.open(id+":access", record.AccessToken)
	if err != nil {
		return authCredential{}, err
	}
	refresh, err := s.open(id+":refresh", record.RefreshToken)
	if err != nil {
		return authCredential{}, err
	}
	return authCredential{
		ID:              record.ID,
		ClientID:        record.ClientID,
		UserID:          record.UserID,
		Login:           record.Login,
		Scopes:          append([]string(nil), record.Scopes...),
		AccessToken:     access,
		RefreshToken:    refresh,
		AccessExpiresAt: record.AccessExpiresAt,
		LastValidatedAt: record.LastValidatedAt,
		UpdatedAt:       record.UpdatedAt,
	}, nil
}

func (s *AuthStore) CredentialForInstallation(installationID, deviceSecret string) (authCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	deviceHash := hashSecret(deviceSecret)
	for _, session := range s.state.Sessions {
		if session.InstallationID != installationID || now.After(session.ExpiresAt) ||
			!secureHashEqual(session.DeviceHash, deviceHash) {
			continue
		}
		record, ok := s.state.Credentials[session.CredentialID]
		if !ok {
			return authCredential{}, ErrAuthNotFound
		}
		access, err := s.open(record.ID+":access", record.AccessToken)
		if err != nil {
			return authCredential{}, err
		}
		refresh, err := s.open(record.ID+":refresh", record.RefreshToken)
		if err != nil {
			return authCredential{}, err
		}
		return authCredential{
			ID:              record.ID,
			ClientID:        record.ClientID,
			UserID:          record.UserID,
			Login:           record.Login,
			Scopes:          append([]string(nil), record.Scopes...),
			AccessToken:     access,
			RefreshToken:    refresh,
			AccessExpiresAt: record.AccessExpiresAt,
			LastValidatedAt: record.LastValidatedAt,
			UpdatedAt:       record.UpdatedAt,
		}, nil
	}
	return authCredential{}, ErrAuthNotFound
}

func (s *AuthStore) CreateSession(credentialID, installationID, deviceSecret string, ttl time.Duration) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Credentials[credentialID]; !ok {
		return "", time.Time{}, ErrAuthNotFound
	}
	now := time.Now().UTC()
	for key, existing := range s.state.Sessions {
		if now.After(existing.ExpiresAt) || existing.InstallationID == installationID {
			delete(s.state.Sessions, key)
		}
	}
	if len(s.state.Sessions) >= maxAuthSessions {
		return "", time.Time{}, ErrAuthCapacity
	}
	token, err := randomToken("fsv1_", 32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(ttl)
	s.state.Sessions[hashSecret(token)] = authSessionRecord{
		CredentialID:   credentialID,
		InstallationID: installationID,
		DeviceHash:     hashSecret(deviceSecret),
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
	}
	s.cleanupExpiredLocked(now)
	if err := s.persistLocked(); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *AuthStore) ResolveSession(token, installationID, deviceSecret string, renewTTL time.Duration) (authSessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashSecret(token)
	record, ok := s.state.Sessions[key]
	if !ok {
		return authSessionRecord{}, ErrAuthNotFound
	}
	now := time.Now().UTC()
	if now.After(record.ExpiresAt) {
		delete(s.state.Sessions, key)
		if !s.credentialInUseLocked(record.CredentialID) {
			delete(s.state.Credentials, record.CredentialID)
		}
		_ = s.persistLocked()
		return authSessionRecord{}, ErrAuthExpired
	}
	if record.InstallationID != installationID || !secureHashEqual(record.DeviceHash, hashSecret(deviceSecret)) {
		return authSessionRecord{}, ErrAuthDeviceMismatch
	}
	if renewTTL > 0 && record.ExpiresAt.Before(now.Add(renewTTL/2)) {
		record.ExpiresAt = now.Add(renewTTL)
		s.state.Sessions[key] = record
		if err := s.persistLocked(); err != nil {
			return authSessionRecord{}, err
		}
	}
	return record, nil
}

// SessionAccount resolves the Twitch user bound to a backend session without renewing or
// deleting an expired record. Destructive account revocation may therefore still be
// authorized by a genuine stale token, while wrong tokens remain indistinguishable from
// missing records.
func (s *AuthStore) SessionAccount(token, installationID, deviceSecret string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.state.Sessions[hashSecret(token)]
	if !ok {
		return "", false, ErrAuthNotFound
	}
	if record.InstallationID != installationID || !secureHashEqual(record.DeviceHash, hashSecret(deviceSecret)) {
		return "", false, ErrAuthDeviceMismatch
	}
	credential, ok := s.state.Credentials[record.CredentialID]
	if !ok || strings.TrimSpace(credential.UserID) == "" {
		return "", false, ErrAuthNotFound
	}
	return credential.UserID, time.Now().UTC().After(record.ExpiresAt), nil
}

func (s *AuthStore) DeleteSession(token, installationID, deviceSecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashSecret(token)
	record, ok := s.state.Sessions[key]
	if !ok {
		return ErrAuthNotFound
	}
	if record.InstallationID != installationID || !secureHashEqual(record.DeviceHash, hashSecret(deviceSecret)) {
		return ErrAuthDeviceMismatch
	}
	delete(s.state.Sessions, key)
	if !s.credentialInUseLocked(record.CredentialID) {
		delete(s.state.Credentials, record.CredentialID)
	}
	return s.persistLocked()
}

// InstallationBinding reports whether any auth artifact belongs to this installation and
// device secret. A record for the installation with another secret is rejected explicitly.
func (s *AuthStore) InstallationBinding(installationID, deviceSecret string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	deviceHash := hashSecret(deviceSecret)
	foundInstallation := false
	for _, session := range s.state.Sessions {
		if session.InstallationID != installationID {
			continue
		}
		foundInstallation = true
		if secureHashEqual(session.DeviceHash, deviceHash) {
			return true, nil
		}
	}
	for _, pending := range s.state.Pending {
		if pending.InstallationID != installationID {
			continue
		}
		foundInstallation = true
		if secureHashEqual(pending.DeviceHash, deviceHash) {
			return true, nil
		}
	}
	for _, handoff := range s.state.Handoffs {
		if handoff.InstallationID != installationID {
			continue
		}
		foundInstallation = true
		if secureHashEqual(handoff.DeviceHash, deviceHash) {
			return true, nil
		}
	}
	if foundInstallation {
		return false, ErrAuthDeviceMismatch
	}
	return false, ErrAuthNotFound
}

// RevokeInstallation removes every authentication artifact bound to one app installation.
// Sessions and OAuth handoffs on other installations remain valid. The operation is
// idempotent after the caller has authenticated the device binding.
func (s *AuthStore) RevokeInstallation(installationID, deviceSecret string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deviceHash := hashSecret(deviceSecret)
	removedSessions := 0
	mutated := false
	for key, session := range s.state.Sessions {
		if session.InstallationID != installationID {
			continue
		}
		if !secureHashEqual(session.DeviceHash, deviceHash) {
			return 0, ErrAuthDeviceMismatch
		}
		removedSessions++
		mutated = true
		delete(s.state.Sessions, key)
	}
	for key, pending := range s.state.Pending {
		if pending.InstallationID != installationID {
			continue
		}
		if !secureHashEqual(pending.DeviceHash, deviceHash) {
			return 0, ErrAuthDeviceMismatch
		}
		mutated = true
		delete(s.state.Pending, key)
	}
	for key, handoff := range s.state.Handoffs {
		if handoff.InstallationID != installationID {
			continue
		}
		if !secureHashEqual(handoff.DeviceHash, deviceHash) {
			return 0, ErrAuthDeviceMismatch
		}
		mutated = true
		delete(s.state.Handoffs, key)
	}
	for id := range s.state.Credentials {
		if !s.credentialInUseLocked(id) {
			mutated = true
			delete(s.state.Credentials, id)
		}
	}
	if !mutated {
		return 0, nil
	}
	return removedSessions, s.persistLocked()
}

// AccountRevocationTargets returns active-session installations and decrypted Twitch
// credentials currently associated with one Twitch user. The snapshot is used to remove external
// delivery surfaces and best-effort revoke access tokens before deleting the auth records.
func (s *AuthStore) AccountRevocationTargets(userID string) (accountRevocationTargets, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return accountRevocationTargets{}, ErrAuthNotFound
	}
	credentialIDs := make(map[string]struct{})
	credentials := make([]authCredential, 0)
	for id, record := range s.state.Credentials {
		if record.UserID != userID {
			continue
		}
		access, err := s.open(id+":access", record.AccessToken)
		if err != nil {
			return accountRevocationTargets{}, err
		}
		refresh, err := s.open(id+":refresh", record.RefreshToken)
		if err != nil {
			return accountRevocationTargets{}, err
		}
		credentialIDs[id] = struct{}{}
		credentials = append(credentials, authCredential{
			ID:              record.ID,
			ClientID:        record.ClientID,
			UserID:          record.UserID,
			Login:           record.Login,
			Scopes:          append([]string(nil), record.Scopes...),
			AccessToken:     access,
			RefreshToken:    refresh,
			AccessExpiresAt: record.AccessExpiresAt,
			LastValidatedAt: record.LastValidatedAt,
			UpdatedAt:       record.UpdatedAt,
		})
	}
	installations := make(map[string]struct{})
	for _, session := range s.state.Sessions {
		if _, ok := credentialIDs[session.CredentialID]; ok {
			installations[session.InstallationID] = struct{}{}
		}
	}
	installationIDs := make([]string, 0, len(installations))
	for installationID := range installations {
		installationIDs = append(installationIDs, installationID)
	}
	sort.Strings(installationIDs)
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].ID < credentials[j].ID })
	return accountRevocationTargets{
		InstallationIDs: installationIDs,
		Credentials:     credentials,
	}, nil
}

// RevokeAccount removes every Ferventio auth session and OAuth artifact associated with
// one Twitch user. Extra installation IDs come from the push-registration store so stale
// pending OAuth records on already signed-out devices are also cleared.
func (s *AuthStore) RevokeAccount(userID string, extraInstallationIDs []string) (accountRevocationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return accountRevocationResult{}, ErrAuthNotFound
	}
	credentialIDs := make(map[string]struct{})
	for id, credential := range s.state.Credentials {
		if credential.UserID == userID {
			credentialIDs[id] = struct{}{}
		}
	}
	installations := make(map[string]struct{}, len(extraInstallationIDs))
	for _, installationID := range extraInstallationIDs {
		if installationID = strings.TrimSpace(installationID); installationID != "" {
			installations[installationID] = struct{}{}
		}
	}
	result := accountRevocationResult{}
	mutated := false
	for key, session := range s.state.Sessions {
		if _, ok := credentialIDs[session.CredentialID]; !ok {
			continue
		}
		installations[session.InstallationID] = struct{}{}
		delete(s.state.Sessions, key)
		result.RemovedSessions++
		mutated = true
	}
	for key, handoff := range s.state.Handoffs {
		_, credentialMatches := credentialIDs[handoff.CredentialID]
		_, installationMatches := installations[handoff.InstallationID]
		if !credentialMatches && !installationMatches {
			continue
		}
		installations[handoff.InstallationID] = struct{}{}
		delete(s.state.Handoffs, key)
		mutated = true
	}
	for key, pending := range s.state.Pending {
		if _, ok := installations[pending.InstallationID]; ok {
			delete(s.state.Pending, key)
			mutated = true
		}
	}
	for credentialID := range credentialIDs {
		if _, ok := s.state.Credentials[credentialID]; ok {
			delete(s.state.Credentials, credentialID)
			result.RemovedCredentials++
			mutated = true
		}
	}
	for credentialID := range s.state.Credentials {
		if !s.credentialInUseLocked(credentialID) {
			delete(s.state.Credentials, credentialID)
			mutated = true
		}
	}
	if !mutated {
		return result, nil
	}
	return result, s.persistLocked()
}

// DeleteCredentialIfUnused removes an OAuth credential left behind by a consumed handoff
// when mobile-session completion fails. Credentials referenced by another session or handoff
// are deliberately preserved.
func (s *AuthStore) DeleteCredentialIfUnused(credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credentialInUseLocked(credentialID) {
		return nil
	}
	if _, ok := s.state.Credentials[credentialID]; !ok {
		return nil
	}
	delete(s.state.Credentials, credentialID)
	return s.persistLocked()
}

func (s *AuthStore) credentialInUseLocked(credentialID string) bool {
	for _, session := range s.state.Sessions {
		if session.CredentialID == credentialID {
			return true
		}
	}
	for _, handoff := range s.state.Handoffs {
		if handoff.CredentialID == credentialID {
			return true
		}
	}
	return false
}

func (s *AuthStore) seal(aad, plaintext string) (encryptedValue, error) {
	return sealAuthValue(s.aead, aad, plaintext)
}

func (s *AuthStore) open(aad string, value encryptedValue) (string, error) {
	return openAuthValue(s.aead, aad, value)
}

func sealAuthValue(aead cipher.AEAD, aad, plaintext string) (encryptedValue, error) {
	if aead == nil {
		return encryptedValue{}, errors.New("auth encryption is not configured")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedValue{}, fmt.Errorf("generate auth nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	return encryptedValue{
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

func openAuthValue(aead cipher.AEAD, aad string, value encryptedValue) (string, error) {
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
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt auth value: %w", err)
	}
	return string(plaintext), nil
}

func (s *AuthStore) cleanupExpiredLocked(now time.Time) {
	for key, pending := range s.state.Pending {
		if now.After(pending.ExpiresAt) {
			delete(s.state.Pending, key)
		}
	}
	for key, handoff := range s.state.Handoffs {
		if now.After(handoff.ExpiresAt) {
			delete(s.state.Handoffs, key)
		}
	}
	for key, session := range s.state.Sessions {
		if now.After(session.ExpiresAt) {
			delete(s.state.Sessions, key)
		}
	}
	for id := range s.state.Credentials {
		if !s.credentialInUseLocked(id) {
			delete(s.state.Credentials, id)
		}
	}
}

func (s *AuthStore) ensureMapsLocked() {
	if s.state.Credentials == nil {
		s.state.Credentials = map[string]authCredentialRecord{}
	}
	if s.state.Sessions == nil {
		s.state.Sessions = map[string]authSessionRecord{}
	}
	if s.state.Pending == nil {
		s.state.Pending = map[string]pendingAuthRecord{}
	}
	if s.state.Handoffs == nil {
		s.state.Handoffs = map[string]authHandoffRecord{}
	}
}

func (s *AuthStore) persistLocked() error {
	s.ensureMapsLocked()
	return nil
}
func randomToken(prefix string, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func hashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func secureHashEqual(left, right string) bool {
	if len(left) != len(right) || left == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
