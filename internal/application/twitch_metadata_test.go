package application

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTwitchMetadataCachesTokenAndBadges(t *testing.T) {
	var tokenCalls atomic.Int32
	var badgeCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		if r.URL.RawQuery != "" {
			t.Fatalf("credentials must not be placed in URL query: %s", r.URL.RawQuery)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse token form: %v", err)
		}
		if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
			t.Fatalf("unexpected credentials form")
		}
		writeRawJSON(w, http.StatusOK, []byte(`{"access_token":"app-token","expires_in":3600,"token_type":"bearer"}`))
	})
	mux.HandleFunc("GET /helix/chat/badges/global", func(w http.ResponseWriter, r *http.Request) {
		badgeCalls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer app-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get("Client-Id"); got != "client" {
			t.Fatalf("unexpected Client-Id header: %q", got)
		}
		writeRawJSON(w, http.StatusOK, []byte(`{"data":[{"set_id":"staff","versions":[]}]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newTwitchMetadataClient(Config{TwitchClientID: "client", TwitchClientSecret: "secret"})
	client.httpClient = server.Client()
	client.identityURL = server.URL + "/oauth2/token"
	client.helixURL = server.URL + "/helix"

	first, err := client.globalChatBadges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.globalChatBadges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("cached response changed: %q != %q", first, second)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected one token call, got %d", tokenCalls.Load())
	}
	if badgeCalls.Load() != 1 {
		t.Fatalf("expected one badge call, got %d", badgeCalls.Load())
	}
}

func TestTwitchMetadataRefreshesRejectedToken(t *testing.T) {
	var tokenCalls atomic.Int32
	var badgeCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		call := tokenCalls.Add(1)
		writeRawJSON(w, http.StatusOK, []byte(`{"access_token":"token-`+strconv.Itoa(int(call))+`","expires_in":3600}`))
	})
	mux.HandleFunc("GET /helix/chat/badges", func(w http.ResponseWriter, r *http.Request) {
		call := badgeCalls.Add(1)
		if call == 1 {
			writeError(w, http.StatusUnauthorized, "expired")
			return
		}
		if r.URL.Query().Get("broadcaster_id") != "12345" {
			t.Fatalf("missing broadcaster_id: %s", r.URL.RawQuery)
		}
		writeRawJSON(w, http.StatusOK, []byte(`{"data":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newTwitchMetadataClient(Config{TwitchClientID: "client", TwitchClientSecret: "secret"})
	client.httpClient = server.Client()
	client.identityURL = server.URL + "/oauth2/token"
	client.helixURL = server.URL + "/helix"

	if _, err := client.channelChatBadges(context.Background(), "12345"); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("expected token refresh after 401, got %d token calls", tokenCalls.Load())
	}
	if badgeCalls.Load() != 2 {
		t.Fatalf("expected one retry after 401, got %d badge calls", badgeCalls.Load())
	}
}

func TestTwitchMetadataRejectsInvalidChannelID(t *testing.T) {
	client := newTwitchMetadataClient(Config{TwitchClientID: "client", TwitchClientSecret: "secret"})
	_, err := client.channelChatBadges(context.Background(), "not-a-number")
	if err == nil || !strings.Contains(err.Error(), "invalid broadcaster ID") {
		t.Fatalf("expected invalid broadcaster ID error, got %v", err)
	}
}

func TestTwitchMetadataHandlerDisabled(t *testing.T) {
	server := NewServer(Config{}, nil, nil, nil, newDiscardLogger())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/twitch/badges/global", nil)
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(recorder.Result().Body)
		t.Fatalf("expected 503, got %d: %s", recorder.Code, body)
	}
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
