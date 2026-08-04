package domain

type EventSubEnvelope struct {
	Challenge    string `json:"challenge,omitempty"`
	Subscription struct {
		ID        string            `json:"id"`
		Type      string            `json:"type"`
		Version   string            `json:"version"`
		Status    string            `json:"status"`
		Condition map[string]string `json:"condition"`
	} `json:"subscription"`
	Event map[string]any `json:"event,omitempty"`
}
