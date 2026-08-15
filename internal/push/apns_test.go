package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/domain"
)

func TestAPNsSenderBuildsAlertRequest(t *testing.T) {
	var receivedPath string
	var receivedAuthorization string
	var receivedTopic string
	var receivedPushType string
	var receivedPriority string
	var receivedPayload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuthorization = r.Header.Get("Authorization")
		receivedTopic = r.Header.Get("apns-topic")
		receivedPushType = r.Header.Get("apns-push-type")
		receivedPriority = r.Header.Get("apns-priority")
		receivedPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := newTestAPNsSender(t)
	sender.endpoint = server.URL
	sender.client = server.Client()

	notification := domain.Notification{
		EventID:      "event-1",
		Type:         "mention",
		Title:        "Ferventio",
		Body:         "hello from chat",
		ChannelID:    "channel-1",
		ChannelLogin: "channel",
	}
	if err := sender.Send(context.Background(), "abc123", notification); err != nil {
		t.Fatal(err)
	}

	if receivedPath != "/3/device/abc123" {
		t.Fatalf("path = %q", receivedPath)
	}
	if !strings.HasPrefix(receivedAuthorization, "bearer ") {
		t.Fatalf("authorization = %q", receivedAuthorization)
	}
	if receivedTopic != "io.ferventio.ios" {
		t.Fatalf("apns-topic = %q", receivedTopic)
	}
	if receivedPushType != "alert" || receivedPriority != "10" {
		t.Fatalf("push type/priority = %q/%q", receivedPushType, receivedPriority)
	}
	var payload struct {
		APS struct {
			Alert struct {
				Title string `json:"title"`
				Body  string `json:"body"`
			} `json:"alert"`
			Sound string `json:"sound"`
		} `json:"aps"`
		Ferventio domain.Notification `json:"ferventio"`
	}
	if err := json.Unmarshal(receivedPayload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.APS.Alert.Title != "Ferventio" || payload.APS.Alert.Body != "hello from chat" {
		t.Fatalf("unexpected alert: %+v", payload.APS.Alert)
	}
	if payload.APS.Sound != "default" || payload.Ferventio.EventID != "event-1" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestAPNsSenderBuildsBackgroundRequest(t *testing.T) {
	var pushType string
	var priority string
	var payload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushType = r.Header.Get("apns-push-type")
		priority = r.Header.Get("apns-priority")
		payload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := newTestAPNsSender(t)
	sender.endpoint = server.URL
	sender.client = server.Client()
	if err := sender.Send(context.Background(), "token", domain.Notification{
		Type:   "sync",
		Silent: true,
		Body:   "background",
	}); err != nil {
		t.Fatal(err)
	}

	if pushType != "background" || priority != "5" {
		t.Fatalf("push type/priority = %q/%q", pushType, priority)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	aps := decoded["aps"].(map[string]any)
	if aps["content-available"] != float64(1) {
		t.Fatalf("aps = %+v", aps)
	}
	if _, exists := aps["alert"]; exists {
		t.Fatalf("background push unexpectedly contains alert: %+v", aps)
	}
}

func TestAPNsSenderRefreshesExpiredProviderTokenOnce(t *testing.T) {
	var attempts int
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		if attempts == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"reason":"ExpiredProviderToken"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := newTestAPNsSender(t)
	sender.endpoint = server.URL
	sender.client = server.Client()
	if err := sender.Send(context.Background(), "token", domain.Notification{Title: "F", Body: "B"}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if authorizations[0] == authorizations[1] {
		t.Fatal("expired provider token was not regenerated")
	}
}

func TestMakeAPNsPayloadRejectsOversizedNotification(t *testing.T) {
	_, _, _, err := makeAPNsPayload(domain.Notification{
		Title: "Ferventio",
		Body:  strings.Repeat("x", apnsMaximumPayloadSize),
	})
	if err == nil {
		t.Fatal("expected oversized APNs payload to fail")
	}
}

func TestAPNsProviderTokenUsesExpectedClaims(t *testing.T) {
	sender := newTestAPNsSender(t)
	token, err := sender.providerToken(false)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Issuer string `json:"iss"`
		Issued int64  `json:"iat"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "TEAM123456" || claims.Issued != 1_786_800_000 {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("ES256 signature length = %d, want 64", len(signature))
	}
}

func newTestAPNsSender(t *testing.T) *apnsSender {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}))
	sender, err := newAPNsSender(config.APNsConfig{
		Enabled:          true,
		TeamID:           "TEAM123456",
		KeyID:            "KEY1234567",
		PrivateKeyBase64: encoded,
		BundleID:         "io.ferventio.ios",
		Environment:      config.APNsEnvironmentProduction,
	})
	if err != nil {
		t.Fatal(err)
	}
	sender.now = func() time.Time { return time.Unix(1_786_800_000, 0).UTC() }
	return sender
}
