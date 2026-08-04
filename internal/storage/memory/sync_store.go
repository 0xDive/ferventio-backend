package memory

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

type SettingsSyncStore struct {
	mu    sync.RWMutex
	state settingsSyncDiskState
}

func OpenSettingsSyncStore(_ string) (*SettingsSyncStore, error) {
	return newMemorySettingsSyncStore(), nil
}
func newMemorySettingsSyncStore() *SettingsSyncStore {
	return &SettingsSyncStore{
		state: settingsSyncDiskState{
			Version: 1,
			Users:   map[string]settingsSyncUserState{},
		},
	}
}

func (s *SettingsSyncStore) Current(userID string) (SettingsSyncSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.state.Users[userID]
	if !ok || state.Current == nil {
		return SettingsSyncSnapshot{}, false
	}
	return cloneSettingsSyncSnapshot(*state.Current), true
}

func (s *SettingsSyncStore) Put(
	userID string,
	installationID string,
	baseRevision int64,
	force bool,
	appVersion string,
	contentHash string,
	payload json.RawMessage,
) (SettingsSyncSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(userID, installationID, baseRevision, force, appVersion, contentHash, payload)
}

func (s *SettingsSyncStore) putLocked(
	userID string,
	installationID string,
	baseRevision int64,
	force bool,
	appVersion string,
	contentHash string,
	payload json.RawMessage,
) (SettingsSyncSnapshot, error) {
	userState, hadUserState := s.state.Users[userID]
	previousUserState := userState
	currentRevision := int64(0)
	if userState.Current != nil {
		currentRevision = userState.Current.Revision
	}
	if !force && baseRevision != currentRevision {
		if userState.Current == nil {
			return SettingsSyncSnapshot{}, ErrSettingsSyncConflict
		}
		return cloneSettingsSyncSnapshot(*userState.Current), ErrSettingsSyncConflict
	}
	if userState.Current != nil && userState.Current.ContentHash == contentHash {
		return cloneSettingsSyncSnapshot(*userState.Current), nil
	}

	now := time.Now().UTC()
	next := SettingsSyncSnapshot{
		Revision:                currentRevision + 1,
		UpdatedAt:               now,
		UpdatedByInstallationID: installationID,
		AppVersion:              appVersion,
		ContentHash:             contentHash,
		Payload:                 append(json.RawMessage(nil), payload...),
	}
	if userState.Current != nil {
		userState.History = append([]SettingsSyncSnapshot{cloneSettingsSyncSnapshot(*userState.Current)}, userState.History...)
		if len(userState.History) > maxSettingsSyncHistory {
			userState.History = userState.History[:maxSettingsSyncHistory]
		}
	}
	userState.Current = &next
	s.state.Users[userID] = userState
	if err := s.persistLocked(); err != nil {
		if hadUserState {
			s.state.Users[userID] = previousUserState
		} else {
			delete(s.state.Users, userID)
		}
		return SettingsSyncSnapshot{}, err
	}
	return cloneSettingsSyncSnapshot(next), nil
}

func (s *SettingsSyncStore) History(userID string) []SettingsSyncSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userState, ok := s.state.Users[userID]
	if !ok {
		return nil
	}
	result := make([]SettingsSyncSnapshot, 0, len(userState.History)+1)
	if userState.Current != nil {
		result = append(result, cloneSettingsSyncSnapshot(*userState.Current))
	}
	for _, snapshot := range userState.History {
		result = append(result, cloneSettingsSyncSnapshot(snapshot))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Revision > result[j].Revision })
	return result
}

func (s *SettingsSyncStore) Restore(
	userID string,
	installationID string,
	revision int64,
) (SettingsSyncSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userState, ok := s.state.Users[userID]
	if !ok {
		return SettingsSyncSnapshot{}, ErrSettingsSyncRevisionNotFound
	}
	var source *SettingsSyncSnapshot
	if userState.Current != nil && userState.Current.Revision == revision {
		copy := cloneSettingsSyncSnapshot(*userState.Current)
		source = &copy
	} else {
		for _, candidate := range userState.History {
			if candidate.Revision == revision {
				copy := cloneSettingsSyncSnapshot(candidate)
				source = &copy
				break
			}
		}
	}
	if source == nil {
		return SettingsSyncSnapshot{}, ErrSettingsSyncRevisionNotFound
	}
	currentRevision := int64(0)
	if userState.Current != nil {
		currentRevision = userState.Current.Revision
	}
	return s.putLocked(
		userID,
		installationID,
		currentRevision,
		true,
		source.AppVersion,
		source.ContentHash,
		source.Payload,
	)
}

func (s *SettingsSyncStore) persistLocked() error {
	return nil
}
func cloneSettingsSyncSnapshot(snapshot SettingsSyncSnapshot) SettingsSyncSnapshot {
	snapshot.Payload = append(json.RawMessage(nil), snapshot.Payload...)
	return snapshot
}

// NewSettingsSyncStore creates an isolated in-memory settings repository.
func NewSettingsSyncStore() *SettingsSyncStore { return newMemorySettingsSyncStore() }
