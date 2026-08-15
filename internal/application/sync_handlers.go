package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type settingsSyncPutRequest struct {
	BaseRevision int64           `json:"baseRevision"`
	Force        bool            `json:"force,omitempty"`
	Payload      json.RawMessage `json:"payload"`
}

type settingsBackupHeader struct {
	Format        string `json:"format"`
	FormatVersion int    `json:"formatVersion"`
	AppVersion    string `json:"appVersion"`
	ContentHash   string `json:"contentHash"`
}

func (s *Server) getSettingsSync(w http.ResponseWriter, r *http.Request) {
	credential, _, ok := s.authorizeSettingsSync(w, r)
	if !ok {
		return
	}
	snapshot, exists := s.settingsSync.Current(credential.UserID)
	if !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) putSettingsSync(w http.ResponseWriter, r *http.Request) {
	credential, session, ok := s.authorizeSettingsSync(w, r)
	if !ok {
		return
	}
	var request settingsSyncPutRequest
	if err := s.decodeSettingsSyncJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	header, err := validateSettingsSyncPayload(request.Payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshot, err := s.settingsSync.Put(
		credential.UserID,
		session.InstallationID,
		request.BaseRevision,
		request.Force,
		header.AppVersion,
		header.ContentHash,
		request.Payload,
	)
	if errors.Is(err, ErrSettingsSyncConflict) {
		noStore(w)
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    "settings revision conflict",
			"snapshot": snapshot,
		})
		return
	}
	if err != nil {
		s.log.Error("save settings sync snapshot", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to save settings snapshot")
		return
	}
	s.auditRecord(AuditRecord{
		Action:         "settings.sync.put",
		Status:         "ok",
		InstallationID: session.InstallationID,
		UserID:         credential.UserID,
		Detail:         fmt.Sprintf("revision=%d force=%t", snapshot.Revision, request.Force),
	})
	noStore(w)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) getSettingsSyncHistory(w http.ResponseWriter, r *http.Request) {
	credential, _, ok := s.authorizeSettingsSync(w, r)
	if !ok {
		return
	}
	type historyEntry struct {
		Revision                int64     `json:"revision"`
		UpdatedAt               time.Time `json:"updatedAt"`
		UpdatedByInstallationID string    `json:"updatedByInstallationId"`
		AppVersion              string    `json:"appVersion,omitempty"`
		ContentHash             string    `json:"contentHash"`
	}
	history := s.settingsSync.History(credential.UserID)
	result := make([]historyEntry, 0, len(history))
	for _, snapshot := range history {
		result = append(result, historyEntry{
			Revision:                snapshot.Revision,
			UpdatedAt:               snapshot.UpdatedAt,
			UpdatedByInstallationID: snapshot.UpdatedByInstallationID,
			AppVersion:              snapshot.AppVersion,
			ContentHash:             snapshot.ContentHash,
		})
	}
	noStore(w)
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

func (s *Server) restoreSettingsSyncRevision(w http.ResponseWriter, r *http.Request) {
	credential, session, ok := s.authorizeSettingsSync(w, r)
	if !ok {
		return
	}
	revision, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("revision")), 10, 64)
	if err != nil || revision <= 0 {
		writeError(w, http.StatusBadRequest, "invalid settings revision")
		return
	}
	snapshot, err := s.settingsSync.Restore(credential.UserID, session.InstallationID, revision)
	switch {
	case errors.Is(err, ErrSettingsSyncRevisionNotFound):
		writeError(w, http.StatusNotFound, "settings revision not found")
		return
	case err != nil:
		s.log.Error("restore settings sync revision", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to restore settings revision")
		return
	}
	s.auditRecord(AuditRecord{
		Action:         "settings.sync.restore",
		Status:         "ok",
		InstallationID: session.InstallationID,
		UserID:         credential.UserID,
		Detail:         fmt.Sprintf("source_revision=%d new_revision=%d", revision, snapshot.Revision),
	})
	noStore(w)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) authorizeSettingsSync(
	w http.ResponseWriter,
	r *http.Request,
) (authCredential, authSessionRecord, bool) {
	if s.authStore == nil || s.settingsSync == nil {
		writeError(w, http.StatusServiceUnavailable, "settings sync is not configured")
		return authCredential{}, authSessionRecord{}, false
	}
	session, ok := s.authorizeMobileSession(w, r)
	if !ok {
		return authCredential{}, authSessionRecord{}, false
	}
	credential, err := s.authStore.GetCredential(session.CredentialID)
	if err != nil || credential.UserID == "" {
		writeError(w, http.StatusUnauthorized, "Twitch authorization is missing")
		return authCredential{}, authSessionRecord{}, false
	}
	return credential, session, true
}

func (s *Server) decodeSettingsSyncJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSettingsSyncRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON: multiple values are not allowed")
	}
	return nil
}

func validateSettingsSyncPayload(payload json.RawMessage) (settingsBackupHeader, error) {
	if len(payload) == 0 || len(payload) > maxSettingsSyncPayloadBytes || !json.Valid(payload) {
		return settingsBackupHeader{}, errors.New("invalid settings payload")
	}
	var header settingsBackupHeader
	if err := json.Unmarshal(payload, &header); err != nil {
		return settingsBackupHeader{}, errors.New("invalid settings backup envelope")
	}
	if header.Format != settingsBackupFormat || !isSupportedSettingsBackupVersion(header.FormatVersion) {
		return settingsBackupHeader{}, errors.New("unsupported settings backup format")
	}
	if len(header.AppVersion) == 0 || len(header.AppVersion) > 40 {
		return settingsBackupHeader{}, errors.New("invalid settings app version")
	}
	if len(header.ContentHash) != 64 {
		return settingsBackupHeader{}, errors.New("invalid settings content hash")
	}
	for _, character := range header.ContentHash {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return settingsBackupHeader{}, errors.New("invalid settings content hash")
		}
	}
	return header, nil
}

func isSupportedSettingsBackupVersion(version int) bool {
	return version >= minimumSettingsBackupVersion && version <= maximumSettingsBackupVersion
}

const settingsBackupFormat = "ferventio-settings-backup"
const minimumSettingsBackupVersion = 1
const maximumSettingsBackupVersion = 2
const maxSettingsSyncPayloadBytes = 1 << 20
const maxSettingsSyncRequestBytes = maxSettingsSyncPayloadBytes + 32_768
