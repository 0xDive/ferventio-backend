package memory

import (
	"sort"
	"strings"
	"sync"
)

type Store struct {
	mu            sync.RWMutex
	registrations map[string]Registration
}

// OpenStore returns an isolated in-memory repository. Production uses PostgresStorage.
// The path argument is retained for source compatibility with the unit-test suite.
func OpenStore(_ string) (*Store, error) {
	return &Store{registrations: make(map[string]Registration)}, nil
}

func (s *Store) Upsert(registration Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	providedSecret := registration.DeviceSecret
	if providedSecret == "" {
		return ErrSecretMismatch
	}
	if existing, ok := s.registrations[registration.InstallationID]; ok &&
		!registrationSecretMatches(existing, providedSecret) {
		return ErrSecretMismatch
	}
	registration.DeviceSecretHash = hashSecret(providedSecret)
	registration.DeviceSecret = ""
	s.registrations[registration.InstallationID] = registration
	return s.persistLocked()
}

func (s *Store) List() []Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Registration, 0, len(s.registrations))
	for _, registration := range s.registrations {
		registration.DeviceSecret = ""
		registration.DeviceSecretHash = ""
		registration.ChannelIDs = append([]string(nil), registration.ChannelIDs...)
		registration.ModeratorChannelIDs = append([]string(nil), registration.ModeratorChannelIDs...)
		registration.NotificationRules = append([]string(nil), registration.NotificationRules...)
		registration.HighlightPhrases = append([]string(nil), registration.HighlightPhrases...)
		registration.SelectedUserLogins = append([]string(nil), registration.SelectedUserLogins...)
		result = append(result, registration)
	}
	return result
}

func (s *Store) Get(installationID string) (Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	registration, ok := s.registrations[installationID]
	if !ok {
		return Registration{}, ErrNotFound
	}
	registration.DeviceSecret = ""
	registration.DeviceSecretHash = ""
	return registration, nil
}

func (s *Store) Authenticate(installationID, deviceSecret string) (Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	registration, ok := s.registrations[installationID]
	if !ok {
		return Registration{}, ErrNotFound
	}
	if !registrationSecretMatches(registration, deviceSecret) {
		return Registration{}, ErrSecretMismatch
	}
	registration.DeviceSecret = ""
	registration.DeviceSecretHash = ""
	return registration, nil
}

func (s *Store) Delete(installationID, deviceSecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registration, ok := s.registrations[installationID]
	if !ok {
		return ErrNotFound
	}
	if !registrationSecretMatches(registration, deviceSecret) {
		return ErrSecretMismatch
	}
	delete(s.registrations, installationID)
	return s.persistLocked()
}

// DeleteForAccount removes push registrations bound to one Twitch user or explicitly
// identified by the account auth store. It is an internal destructive operation and
// therefore does not accept device secrets.
func (s *Store) DeleteForAccount(userID string, installationIDs []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID = strings.TrimSpace(userID)
	targets := make(map[string]struct{}, len(installationIDs))
	for _, installationID := range installationIDs {
		if installationID = strings.TrimSpace(installationID); installationID != "" {
			targets[installationID] = struct{}{}
		}
	}
	removed := make([]string, 0)
	for installationID, registration := range s.registrations {
		_, explicitTarget := targets[installationID]
		if !explicitTarget && (userID == "" || registration.UserID != userID) {
			continue
		}
		removed = append(removed, installationID)
		delete(s.registrations, installationID)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	sort.Strings(removed)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return removed, nil
}

func registrationSecretMatches(registration Registration, provided string) bool {
	if provided == "" {
		return false
	}
	if registration.DeviceSecretHash != "" {
		return secureHashEqual(registration.DeviceSecretHash, hashSecret(provided))
	}
	return secureEqual(registration.DeviceSecret, provided)
}

func (s *Store) persistLocked() error {
	return nil
}
