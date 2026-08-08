package application

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"context"
)

func TestVerifyEventSubMessage(t *testing.T) {
	now := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	timestamp := now.Format(time.RFC3339Nano)
	body := []byte(`{"subscription":{"type":"stream.online"},"event":{}}`)
	signature := signEventSub("secret-value-1234", "message-1", timestamp, body)
	if err := verifyEventSubMessage("secret-value-1234", "message-1", timestamp, signature, body, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := verifyEventSubMessage("secret-value-1234", "message-1", timestamp, signature, append(body, 'x'), now); err == nil {
		t.Fatal("modified body was accepted")
	}
	oldTimestamp := now.Add(-eventSubReplayWindow - time.Second).Format(time.RFC3339Nano)
	oldSignature := signEventSub("secret-value-1234", "message-2", oldTimestamp, body)
	if err := verifyEventSubMessage("secret-value-1234", "message-2", oldTimestamp, oldSignature, body, now); err == nil {
		t.Fatal("replayed timestamp was accepted")
	}
}

func TestEventSubWebhookChallengeResponse(t *testing.T) {
	secret := "eventsub-secret-value"
	now := time.Now().UTC()
	body := `{"challenge":"raw-challenge-value","subscription":{"id":"sub-challenge","type":"stream.online","version":"1","status":"webhook_callback_verification_pending","condition":{"broadcaster_user_id":"channel-1"}}}`
	messageID := "message-challenge"
	timestamp := now.Format(time.RFC3339Nano)
	server := &Server{
		cfg:        Config{EventSubSecret: secret, RequestBodyMaxBytes: 64 << 10},
		deliveries: newMemoryDeliveryStore(),
		audit:      newMemoryAuditStore(),
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/eventsub/webhook", strings.NewReader(body))
	request.Header.Set("Twitch-Eventsub-Message-Id", messageID)
	request.Header.Set("Twitch-Eventsub-Message-Timestamp", timestamp)
	request.Header.Set("Twitch-Eventsub-Message-Signature", signEventSub(secret, messageID, timestamp, []byte(body)))
	request.Header.Set("Twitch-Eventsub-Message-Type", "webhook_callback_verification")
	response := httptest.NewRecorder()

	server.eventSubWebhook(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body=%q", response.Code, response.Body.String())
	}
	if response.Body.String() != "raw-challenge-value" {
		t.Fatalf("challenge body = %q", response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("challenge Content-Type = %q", got)
	}
	if got := response.Header().Get("Content-Length"); got != "19" {
		t.Fatalf("challenge Content-Length = %q", got)
	}
}

func TestEventSubWebhookPersistsBeforeAcknowledgement(t *testing.T) {
	secret := "eventsub-secret-value"
	now := time.Now().UTC()
	body := `{"subscription":{"id":"sub-1","type":"stream.online","version":"1","status":"enabled","condition":{"broadcaster_user_id":"channel-1"}},"event":{"broadcaster_user_id":"channel-1","broadcaster_user_login":"channel"}}`
	messageID := "message-persisted"
	timestamp := now.Format(time.RFC3339Nano)
	server := &Server{
		cfg:           Config{EventSubSecret: secret, RequestBodyMaxBytes: 64 << 10},
		deliveries:    newMemoryDeliveryStore(),
		audit:         newMemoryAuditStore(),
		eventQueue:    make(chan queuedEventSub, 1),
		eventInFlight: map[string]struct{}{},
		eventMu:       sync.Mutex{},
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/eventsub/webhook", strings.NewReader(body))
	request.Header.Set("Twitch-Eventsub-Message-Id", messageID)
	request.Header.Set("Twitch-Eventsub-Message-Timestamp", timestamp)
	request.Header.Set("Twitch-Eventsub-Message-Signature", signEventSub(secret, messageID, timestamp, []byte(body)))
	request.Header.Set("Twitch-Eventsub-Message-Type", "notification")
	response := httptest.NewRecorder()
	server.eventSubWebhook(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("webhook status = %d, body=%s", response.Code, response.Body.String())
	}
	items := server.deliveries.ListEventSubInbox(10)
	if len(items) != 1 || items[0].MessageID != messageID {
		t.Fatalf("durable inbox = %#v", items)
	}
}

func TestChatNotificationRouting(t *testing.T) {
	registration := Registration{
		UserID: "viewer-1", UserLogin: "viewer",
		ChannelIDs:         []string{"channel-1"},
		NotificationRules:  []string{"mention", "reply", "highlight", "selected_user"},
		HighlightPhrases:   []string{"important phrase"},
		SelectedUserLogins: []string{"chosen"},
	}
	baseEvent := map[string]any{
		"broadcaster_user_id":    "channel-1",
		"broadcaster_user_login": "channel",
		"chatter_user_id":        "author-1",
		"chatter_user_login":     "author",
		"chatter_user_name":      "Author",
		"message_id":             "message-1",
		"message":                map[string]any{"text": "hello @viewer"},
	}
	notification, ok := eventNotificationForRegistration("event-1", "channel.chat.message", baseEvent, registration)
	if !ok || notification.Type != "mention" || notification.Destination != "mentions" {
		t.Fatalf("mention notification = %#v, ok=%v", notification, ok)
	}
	if notification.ActorID != "author-1" || notification.ActorLogin != "author" || notification.ActorDisplayName != "Author" {
		t.Fatalf("mention actor metadata = %#v", notification)
	}

	replyEvent := cloneEvent(baseEvent)
	replyEvent["message"] = map[string]any{"text": "reply text"}
	replyEvent["reply"] = map[string]any{"parent_user_id": "viewer-1", "parent_user_login": "viewer"}
	notification, ok = eventNotificationForRegistration("event-2", "channel.chat.message", replyEvent, registration)
	if !ok || notification.Type != "reply" {
		t.Fatalf("reply notification = %#v, ok=%v", notification, ok)
	}

	wrongChannel := cloneEvent(baseEvent)
	wrongChannel["broadcaster_user_id"] = "other-channel"
	if _, ok := eventNotificationForRegistration("event-3", "channel.chat.message", wrongChannel, registration); ok {
		t.Fatal("message from an unregistered channel was routed")
	}
}

func TestDesiredEventSubSubscriptions(t *testing.T) {
	cfg := Config{EventSubCallbackURL: "https://example.com/v1/eventsub/webhook", EventSubSecret: "secret-value-1234"}
	registrations := []Registration{
		{
			UserID: "viewer-1", ChannelIDs: []string{"channel-1"}, ModeratorChannelIDs: []string{"channel-1"},
			NotificationRules: []string{"mention", "automod_hold", "moderation_action", "stream_online"},
		},
		{
			UserID: "channel-2", ChannelIDs: []string{"channel-2"},
			NotificationRules: []string{"reward", "subscription"},
		},
	}
	registrations = append(registrations, Registration{
		UserID: "viewer-3", ChannelIDs: []string{"channel-3"},
		NotificationRules: []string{"mention", "reply", "highlight"},
	})
	subscriptions := desiredEventSubSubscriptions(cfg, registrations)
	keys := make(map[string]bool, len(subscriptions))
	for _, subscription := range subscriptions {
		if subscription.Type == "channel.chat.message" {
			t.Fatalf("chat must use user-token WebSocket transport, got webhook %#v", subscription)
		}
		keys[eventSubSpecKey(subscription.Type, subscription.Version, subscription.Condition)] = true
	}
	expected := []string{
		eventSubSpecKey("automod.message.hold", "2", map[string]string{"broadcaster_user_id": "channel-1", "moderator_user_id": "viewer-1"}),
		eventSubSpecKey("channel.moderate", "2", map[string]string{"broadcaster_user_id": "channel-1", "moderator_user_id": "viewer-1"}),
		eventSubSpecKey("stream.online", "1", map[string]string{"broadcaster_user_id": "channel-1"}),
		eventSubSpecKey("channel.channel_points_custom_reward_redemption.add", "1", map[string]string{"broadcaster_user_id": "channel-2"}),
	}
	for _, key := range expected {
		if !keys[key] {
			t.Fatalf("missing desired subscription %s", key)
		}
	}
}

func signEventSub(secret, messageID, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(messageID))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func cloneEvent(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestEventSubAppTokenKeepsClientSecretOutOfURL(t *testing.T) {
	var sawFormSecret bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("client_secret") != "" {
			t.Fatal("client secret leaked into URL query")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		sawFormSecret = r.Form.Get("client_secret") == "secret-value"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"app-token","expires_in":3600}`))
	}))
	defer server.Close()

	manager := newEventSubManager(Config{
		TwitchIDBaseURL:    server.URL,
		TwitchClientID:     "client-id",
		TwitchClientSecret: "secret-value",
	})
	token, err := manager.token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "app-token" || !sawFormSecret {
		t.Fatalf("token=%q sawFormSecret=%v", token, sawFormSecret)
	}
}

func TestContainsMentionRequiresLoginBoundary(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		login string
		want  bool
	}{
		{name: "exact", text: "hello @Dive", login: "dive", want: true},
		{name: "punctuation", text: "@dive, check this", login: "dive", want: true},
		{name: "case insensitive", text: "ping @DIVE!", login: "dive", want: true},
		{name: "prefix of another login", text: "hello @diver", login: "dive", want: false},
		{name: "underscore continuation", text: "hello @dive_test", login: "dive", want: false},
		{name: "digit continuation", text: "hello @dive2", login: "dive", want: false},
		{name: "empty", text: "hello @dive", login: "", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := containsMention(test.text, test.login); got != test.want {
				t.Fatalf("containsMention(%q, %q) = %v, want %v", test.text, test.login, got, test.want)
			}
		})
	}
}
