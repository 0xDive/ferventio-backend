package domain

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrSettingsSyncConflict         = errors.New("settings sync revision conflict")
	ErrSettingsSyncRevisionNotFound = errors.New("settings sync revision not found")
)

const MaxSettingsSyncHistory = 20

type SettingsSyncSnapshot struct {
	Revision                int64           `json:"revision"`
	UpdatedAt               time.Time       `json:"updatedAt"`
	UpdatedByInstallationID string          `json:"updatedByInstallationId"`
	AppVersion              string          `json:"appVersion,omitempty"`
	ContentHash             string          `json:"contentHash"`
	Payload                 json.RawMessage `json:"payload"`
}

type SettingsSyncUserState struct {
	Current *SettingsSyncSnapshot  `json:"current,omitempty"`
	History []SettingsSyncSnapshot `json:"history,omitempty"`
}

type SettingsSyncDiskState struct {
	Version int                              `json:"version"`
	Users   map[string]SettingsSyncUserState `json:"users"`
}
