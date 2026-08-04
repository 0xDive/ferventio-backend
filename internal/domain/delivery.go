package domain

import "time"

const (
	DeliveryStatusPending      = "pending"
	DeliveryStatusSent         = "sent"
	DeliveryStatusAcked        = "acked"
	DeliveryStatusDead         = "dead"
	EventSubInboxStatusPending = "pending"
	EventSubInboxStatusDead    = "dead"
	MaxDeliveryRecords         = 50_000
	MaxSeenEventRecords        = 100_000
	MaxEventSubInboxRecords    = 100_000
)

type DeliveryRecord struct {
	ID             string       `json:"id"`
	EventID        string       `json:"eventId"`
	InstallationID string       `json:"installationId"`
	Notification   Notification `json:"notification"`
	Status         string       `json:"status"`
	AttemptCount   int          `json:"attemptCount"`
	AvailableAt    time.Time    `json:"availableAt"`
	ExpiresAt      time.Time    `json:"expiresAt"`
	CreatedAt      time.Time    `json:"createdAt"`
	SentAt         time.Time    `json:"sentAt,omitempty"`
	AckedAt        time.Time    `json:"ackedAt,omitempty"`
	LastError      string       `json:"lastError,omitempty"`
}

type ChannelNotificationState struct {
	Title        string    `json:"title,omitempty"`
	CategoryName string    `json:"categoryName,omitempty"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type EventSubInboxRecord struct {
	MessageID     string           `json:"messageId"`
	Envelope      EventSubEnvelope `json:"envelope"`
	Status        string           `json:"status"`
	AttemptCount  int              `json:"attemptCount"`
	AvailableAt   time.Time        `json:"availableAt"`
	ExpiresAt     time.Time        `json:"expiresAt"`
	ReceivedAt    time.Time        `json:"receivedAt"`
	LastAttemptAt time.Time        `json:"lastAttemptAt,omitempty"`
	LastError     string           `json:"lastError,omitempty"`
}

type DeliveryDiskState struct {
	Version       int                                 `json:"version"`
	Records       map[string]DeliveryRecord           `json:"records"`
	Seen          map[string]time.Time                `json:"seenEventSubMessages"`
	EventSubInbox map[string]EventSubInboxRecord      `json:"eventSubInbox,omitempty"`
	ChannelStates map[string]ChannelNotificationState `json:"channelStates,omitempty"`
}
