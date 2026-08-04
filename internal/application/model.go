package application

type socketClientMessage struct {
	Type            string `json:"type"`
	ProtocolVersion int    `json:"protocolVersion,omitempty"`
	InstallationID  string `json:"installationId,omitempty"`
	DeviceSecret    string `json:"deviceSecret,omitempty"`
	LastEventID     string `json:"lastEventId,omitempty"`
	EventID         string `json:"eventId,omitempty"`
}

type socketServerMessage struct {
	Type                  string        `json:"type"`
	ConnectionID          string        `json:"connectionId,omitempty"`
	HeartbeatSeconds      int           `json:"heartbeatSeconds,omitempty"`
	EventID               string        `json:"eventId,omitempty"`
	Payload               *Notification `json:"payload,omitempty"`
	Message               string        `json:"message,omitempty"`
	ServerTimeEpochMillis int64         `json:"serverTimeEpochMillis,omitempty"`
}
