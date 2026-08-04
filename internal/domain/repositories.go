package domain

import (
	"context"
	"encoding/json"
	"time"
)

type RegistrationRepository interface {
	Upsert(Registration) error
	List() []Registration
	Get(installationID string) (Registration, error)
	Authenticate(installationID, deviceSecret string) (Registration, error)
	Delete(installationID, deviceSecret string) error
	DeleteForAccount(userID string, installationIDs []string) ([]string, error)
}

type AuthRepository interface {
	PutPending(state string, record PendingAuthRecord) error
	GetPending(state string) (PendingAuthRecord, error)
	ConsumePending(state string) (PendingAuthRecord, error)
	PutHandoff(code string, record AuthHandoffRecord) error
	ConsumeHandoff(code, installationID, deviceSecret, state string) (AuthHandoffRecord, error)
	PutCredential(credential AuthCredential) error
	PutCredentialAndHandoff(credential AuthCredential, code string, record AuthHandoffRecord) error
	GetCredential(id string) (AuthCredential, error)
	CredentialForInstallation(installationID, deviceSecret string) (AuthCredential, error)
	CreateSession(credentialID, installationID, deviceSecret string, ttl time.Duration) (string, time.Time, error)
	ResolveSession(token, installationID, deviceSecret string, renewTTL time.Duration) (AuthSessionRecord, error)
	SessionAccount(token, installationID, deviceSecret string) (string, bool, error)
	DeleteSession(token, installationID, deviceSecret string) error
	InstallationBinding(installationID, deviceSecret string) (bool, error)
	RevokeInstallation(installationID, deviceSecret string) (int, error)
	AccountRevocationTargets(userID string) (AccountRevocationTargets, error)
	RevokeAccount(userID string, extraInstallationIDs []string) (AccountRevocationResult, error)
	DeleteCredentialIfUnused(credentialID string) error
}

type DeliveryRepository interface {
	Enqueue(record DeliveryRecord) (DeliveryRecord, bool, error)
	ListDeliveries(limit int) []DeliveryRecord
	PendingForInstallation(installationID string, limit int, now time.Time) []DeliveryRecord
	MarkSent(id string, sentAt time.Time) error
	MarkFailed(id string, failure error, failedAt time.Time) error
	AckThrough(installationID, eventID string, ackedAt time.Time) error
	Ack(installationID, eventID string, ackedAt time.Time) error
	DeleteForInstallation(installationID string) (int, error)
	EnqueueEventSub(messageID string, envelope EventSubEnvelope, now time.Time) (EventSubInboxRecord, bool, error)
	PendingEventSub(limit int, now time.Time) []EventSubInboxRecord
	ListEventSubInbox(limit int) []EventSubInboxRecord
	CompleteEventSub(messageID string, completedAt time.Time) error
	MarkEventSubFailed(messageID string, failure error, failedAt time.Time) error
	RetryEventSub(messageID string, now time.Time) error
	HasSeenEventSub(messageID string, now time.Time, ttl time.Duration) bool
	SeenEventSub(messageID string, now time.Time, ttl time.Duration) (bool, error)
	ForgetEventSub(messageID string) error
	ChannelStateChanges(channelID, title, categoryName string) (titleChanged, gameChanged, initialized bool, err error)
	SaveChannelState(channelID, title, categoryName string, now time.Time) error
	UpdateChannelState(channelID, title, categoryName string, now time.Time) (titleChanged, gameChanged, initialized bool, err error)
	Cleanup(now time.Time) error
}

type AuditRepository interface {
	Append(AuditRecord) error
	ListAudit(limit int) []AuditRecord
}

type SettingsSyncRepository interface {
	Current(userID string) (SettingsSyncSnapshot, bool)
	Put(userID, installationID string, baseRevision int64, force bool, appVersion, contentHash string, payload json.RawMessage) (SettingsSyncSnapshot, error)
	History(userID string) []SettingsSyncSnapshot
	Restore(userID, installationID string, revision int64) (SettingsSyncSnapshot, error)
}

type ReadinessChecker interface {
	Ping(context.Context) error
}
