package memory

import (
	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/domain"
)

type Registration = domain.Registration
type Notification = domain.Notification

type encryptedValue = domain.EncryptedValue
type authCredentialRecord = domain.AuthCredentialRecord
type authCredential = domain.AuthCredential
type authSessionRecord = domain.AuthSessionRecord
type pendingAuthRecord = domain.PendingAuthRecord
type authHandoffRecord = domain.AuthHandoffRecord
type authDiskState = domain.AuthDiskState
type accountRevocationTargets = domain.AccountRevocationTargets
type accountRevocationResult = domain.AccountRevocationResult

type eventSubEnvelope = domain.EventSubEnvelope
type DeliveryRecord = domain.DeliveryRecord
type ChannelNotificationState = domain.ChannelNotificationState
type EventSubInboxRecord = domain.EventSubInboxRecord
type deliveryDiskState = domain.DeliveryDiskState

type AuditRecord = domain.AuditRecord
type auditDiskState = domain.AuditDiskState

type SettingsSyncSnapshot = domain.SettingsSyncSnapshot
type settingsSyncUserState = domain.SettingsSyncUserState
type settingsSyncDiskState = domain.SettingsSyncDiskState

var (
	ErrNotFound                     = domain.ErrRegistrationNotFound
	ErrSecretMismatch               = domain.ErrDeviceSecretMismatch
	ErrAuthNotFound                 = domain.ErrAuthNotFound
	ErrAuthExpired                  = domain.ErrAuthExpired
	ErrAuthDeviceMismatch           = domain.ErrAuthDeviceMismatch
	ErrAuthStateMismatch            = domain.ErrAuthStateMismatch
	ErrAuthCapacity                 = domain.ErrAuthCapacity
	ErrSettingsSyncConflict         = domain.ErrSettingsSyncConflict
	ErrSettingsSyncRevisionNotFound = domain.ErrSettingsSyncRevisionNotFound
)

const (
	maxPendingAuthRecords = domain.MaxPendingAuthRecords
	maxAuthHandoffs       = domain.MaxAuthHandoffs
	maxAuthSessions       = domain.MaxAuthSessions

	deliveryStatusPending      = domain.DeliveryStatusPending
	deliveryStatusSent         = domain.DeliveryStatusSent
	deliveryStatusAcked        = domain.DeliveryStatusAcked
	deliveryStatusDead         = domain.DeliveryStatusDead
	eventSubInboxStatusPending = domain.EventSubInboxStatusPending
	eventSubInboxStatusDead    = domain.EventSubInboxStatusDead
	maxDeliveryRecords         = domain.MaxDeliveryRecords
	maxSeenEventRecords        = domain.MaxSeenEventRecords
	maxEventSubInboxRecords    = domain.MaxEventSubInboxRecords
	maxAuditRecords            = domain.MaxAuditRecords
	maxSettingsSyncHistory     = domain.MaxSettingsSyncHistory
)

func decodeAuthKey(value string) ([]byte, error) { return config.DecodeAuthKey(value) }

func secureEqual(left, right string) bool {
	return len(left) == len(right) && left != "" && secureHashEqual(hashSecret(left), hashSecret(right))
}
