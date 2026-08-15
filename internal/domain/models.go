package domain

import "time"

type Registration struct {
	InstallationID       string    `json:"installationId"`
	DeviceSecret         string    `json:"deviceSecret,omitempty"`
	DeviceSecretHash     string    `json:"deviceSecretHash,omitempty"`
	Provider             string    `json:"provider"`
	FirebaseInstallation string    `json:"firebaseInstallationId,omitempty"`
	APNsDeviceToken      string    `json:"apnsDeviceToken,omitempty"`
	Endpoint             string    `json:"endpoint,omitempty"`
	P256DH               string    `json:"p256dh,omitempty"`
	Auth                 string    `json:"auth,omitempty"`
	AppVersion           string    `json:"appVersion"`
	Platform             string    `json:"platform"`
	UserID               string    `json:"userId,omitempty"`
	UserLogin            string    `json:"userLogin,omitempty"`
	ChannelIDs           []string  `json:"channelIds,omitempty"`
	ModeratorChannelIDs  []string  `json:"moderatorChannelIds,omitempty"`
	NotificationRules    []string  `json:"notificationRules,omitempty"`
	HighlightPhrases     []string  `json:"highlightPhrases,omitempty"`
	SelectedUserLogins   []string  `json:"selectedUserLogins,omitempty"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

type Notification struct {
	EventID              string `json:"eventId,omitempty"`
	Type                 string `json:"type,omitempty"`
	Title                string `json:"title"`
	Body                 string `json:"body"`
	ChannelID            string `json:"channelId,omitempty"`
	ChannelLogin         string `json:"channelLogin,omitempty"`
	MessageID            string `json:"messageId,omitempty"`
	ActorID              string `json:"actorId,omitempty"`
	ActorLogin           string `json:"actorLogin,omitempty"`
	ActorDisplayName     string `json:"actorDisplayName,omitempty"`
	Destination          string `json:"destination,omitempty"`
	Silent               bool   `json:"silent,omitempty"`
	CreatedAtEpochMillis int64  `json:"createdAtEpochMillis,omitempty"`
}

type VAPIDResponse struct {
	PublicKey string `json:"publicKey"`
}
