package domain

import "time"

const MaxAuditRecords = 20_000

type AuditRecord struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Action         string    `json:"action"`
	Status         string    `json:"status,omitempty"`
	InstallationID string    `json:"installationId,omitempty"`
	UserID         string    `json:"userId,omitempty"`
	ChannelID      string    `json:"channelId,omitempty"`
	EventID        string    `json:"eventId,omitempty"`
	Detail         string    `json:"detail,omitempty"`
}

type AuditDiskState struct {
	Version int           `json:"version"`
	Records []AuditRecord `json:"records"`
}
