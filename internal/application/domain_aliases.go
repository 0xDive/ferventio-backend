package application

import "github.com/0xDive/ferventio-backend/internal/domain"

type Registration = domain.Registration
type Notification = domain.Notification
type VAPIDResponse = domain.VAPIDResponse

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

type AuditRecord = domain.AuditRecord
type SettingsSyncSnapshot = domain.SettingsSyncSnapshot

type RegistrationRepository = domain.RegistrationRepository
type AuthRepository = domain.AuthRepository
type DeliveryRepository = domain.DeliveryRepository
type AuditRepository = domain.AuditRepository
type SettingsSyncRepository = domain.SettingsSyncRepository
type ReadinessChecker = domain.ReadinessChecker

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
	deliveryStatusPending      = domain.DeliveryStatusPending
	deliveryStatusSent         = domain.DeliveryStatusSent
	deliveryStatusAcked        = domain.DeliveryStatusAcked
	deliveryStatusDead         = domain.DeliveryStatusDead
	eventSubInboxStatusPending = domain.EventSubInboxStatusPending
	eventSubInboxStatusDead    = domain.EventSubInboxStatusDead
)
