package application

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestAssignUserChatChannelsSharesOneSubscriptionPerChannel(t *testing.T) {
	registrations := []Registration{
		{
			UserID:              "user-a",
			ChannelIDs:          []string{"channel-1", "channel-2"},
			ModeratorChannelIDs: []string{"channel-2"},
			NotificationRules:   []string{"mention"},
		},
		{
			UserID:            "user-b",
			ChannelIDs:        []string{"channel-1", "channel-3"},
			NotificationRules: []string{"reply"},
		},
	}

	assigned := assignUserChatChannels(registrations, true)
	want := map[string][]string{
		"user-a": {"channel-1"},
		"user-b": {"channel-3"},
	}
	if !reflect.DeepEqual(assigned, want) {
		t.Fatalf("assigned = %#v, want %#v", assigned, want)
	}
}

func TestAssignUserChatChannelsKeepsViewerChannelsWithoutWebhook(t *testing.T) {
	registrations := []Registration{
		{
			UserID:            "viewer",
			ChannelIDs:        []string{"channel-2", "channel-1"},
			NotificationRules: []string{"highlight"},
		},
	}
	assigned := assignUserChatChannels(registrations, false)
	want := map[string][]string{"viewer": {"channel-1", "channel-2"}}
	if !reflect.DeepEqual(assigned, want) {
		t.Fatalf("assigned = %#v, want %#v", assigned, want)
	}
}

func TestEnqueueUserChatEventDeduplicatesAcrossUserSessions(t *testing.T) {
	deliveries := newMemoryDeliveryStore()
	server := &Server{
		deliveries:    deliveries,
		audit:         newMemoryAuditStore(),
		eventQueue:    make(chan queuedEventSub, 4),
		eventInFlight: map[string]struct{}{},
		eventMu:       sync.Mutex{},
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	message := userChatWebSocketMessage{}
	message.Metadata.MessageID = "transport-message-a"
	message.Metadata.SubscriptionType = "channel.chat.message"
	message.Metadata.SubscriptionVersion = "1"
	message.Payload.Subscription.ID = "subscription-a"
	message.Payload.Subscription.Type = "channel.chat.message"
	message.Payload.Subscription.Version = "1"
	message.Payload.Subscription.Status = "enabled"
	message.Payload.Event = map[string]any{
		"message_id":             "chat-message-1",
		"broadcaster_user_id":    "channel-1",
		"broadcaster_user_login": "channel",
		"message":                map[string]any{"text": "hello"},
	}
	if err := server.enqueueUserChatEvent(message); err != nil {
		t.Fatal(err)
	}
	message.Metadata.MessageID = "transport-message-b"
	message.Payload.Subscription.ID = "subscription-b"
	if err := server.enqueueUserChatEvent(message); err != nil {
		t.Fatal(err)
	}

	items := deliveries.ListEventSubInbox(10)
	if len(items) != 1 {
		t.Fatalf("inbox length = %d, want 1", len(items))
	}
	if items[0].MessageID != "chat:chat-message-1" {
		t.Fatalf("message ID = %q", items[0].MessageID)
	}
}

func TestCreateUserChatSubscriptionUsesUserTokenAndWebSocketTransport(t *testing.T) {
	var received userChatSubscriptionRequest
	var authorization string
	var clientID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/eventsub/subscriptions" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		authorization = r.Header.Get("Authorization")
		clientID = r.Header.Get("Client-Id")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	application := &Server{cfg: Config{
		TwitchClientID:     "client-id",
		TwitchHelixBaseURL: server.URL,
	}}
	manager := newUserChatEventSubManager(application)
	if err := manager.createChatSubscription(
		t.Context(),
		"user-token",
		"viewer-id",
		"session-id",
		"channel-id",
	); err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer user-token" || clientID != "client-id" {
		t.Fatalf("authorization=%q clientID=%q", authorization, clientID)
	}
	if received.Type != "channel.chat.message" || received.Version != "1" {
		t.Fatalf("subscription = %#v", received)
	}
	if received.Condition["user_id"] != "viewer-id" ||
		received.Condition["broadcaster_user_id"] != "channel-id" {
		t.Fatalf("condition = %#v", received.Condition)
	}
	if received.Transport.Method != "websocket" || received.Transport.SessionID != "session-id" {
		t.Fatalf("transport = %#v", received.Transport)
	}
}

func TestValidateUserChatReconnectURL(t *testing.T) {
	if err := validateUserChatReconnectURL("wss://eventsub.wss.twitch.tv/ws?reconnect=token"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"https://eventsub.wss.twitch.tv/ws",
		"wss://example.com/ws",
		"wss://eventsub.wss.twitch.tv.evil.example/ws",
		"not a URL",
	} {
		if err := validateUserChatReconnectURL(raw); err == nil {
			t.Fatalf("accepted reconnect URL %q", raw)
		}
	}
}

func TestUserChatSessionSignatureIsStable(t *testing.T) {
	left := []string{"a", "b"}
	right := []string{"a", "b"}
	if userChatSessionSignature(left) != userChatSessionSignature(right) {
		t.Fatal("equal channel sets produced different signatures")
	}
	if strings.TrimSpace(userChatSessionSignature(left)) == "" {
		t.Fatal("empty signature")
	}
}
