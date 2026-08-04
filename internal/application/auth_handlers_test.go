package application

import (
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestServerOAuthMobileFlow(t *testing.T) {
	var tokenRequests int
	twitch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/authorize":
			w.WriteHeader(http.StatusNoContent)
		case "/oauth2/token":
			tokenRequests++
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("client_secret") != "server-secret" {
				t.Fatal("client secret was not used server-side")
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "twitch-access-1",
				"refresh_token": "twitch-refresh-1",
				"expires_in":    3600,
				"scope":         []string{"user:read:chat", "user:write:chat"},
				"token_type":    "bearer",
			})
		case "/oauth2/validate":
			if r.Header.Get("Authorization") != "Bearer twitch-access-1" {
				t.Fatalf("unexpected validation authorization: %q", r.Header.Get("Authorization"))
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"client_id":  "server-client",
				"user_id":    "42",
				"login":      "tester",
				"scopes":     []string{"user:read:chat", "user:write:chat"},
				"expires_in": 3500,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer twitch.Close()

	cfg := Config{
		TwitchClientID:        "server-client",
		TwitchClientSecret:    "server-secret",
		TwitchRedirectURL:     "https://auth.example.test/v1/auth/twitch/callback",
		TwitchIDBaseURL:       twitch.URL,
		PublicBaseURL:         "https://auth.example.test",
		AuthEncryptionKey:     testAuthKey(),
		AuthAllowedAppSchemes: []string{"io.ferventio.app"},
		AuthScopes:            []string{"user:read:chat", "user:write:chat"},
		AuthSessionTTL:        365 * 24 * time.Hour,
		AuthStateTTL:          10 * time.Minute,
		AuthHandoffTTL:        2 * time.Minute,
		AuthLeaseTTL:          time.Minute,
		RequestBodyMaxBytes:   64 << 10,
	}
	store, err := OpenAuthStore(filepath.Join(t.TempDir(), "auth.json"), cfg.AuthEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(cfg, nil, store, nil, logger)

	installationID := "installation-1"
	deviceSecret := strings.Repeat("z", 48)
	startBody := `{"installationId":"` + installationID + `","deviceSecret":"` + deviceSecret + `","appCallbackUri":"io.ferventio.app://oauth/callback"}`
	startRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/mobile/start", strings.NewReader(startBody))
	startResponse := httptest.NewRecorder()
	server.startMobileAuth(startResponse, startRequest)
	if startResponse.Code != http.StatusCreated {
		t.Fatalf("start status=%d body=%s", startResponse.Code, startResponse.Body.String())
	}
	var started mobileAuthStartResponse
	if err := json.Unmarshal(startResponse.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(started.AuthorizationURL, cfg.PublicBaseURL+"/v1/auth/mobile/browser") {
		t.Fatalf("app must open the Ferventio site first, got %q", started.AuthorizationURL)
	}
	if strings.Contains(startResponse.Body.String(), "server-secret") {
		t.Fatal("server secret leaked to mobile response")
	}

	browserURL, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	browserRequest := httptest.NewRequest(http.MethodGet, browserURL.RequestURI(), nil)
	browserResponse := httptest.NewRecorder()
	server.beginBrowserAuth(browserResponse, browserRequest)
	if browserResponse.Code != http.StatusFound {
		t.Fatalf("browser status=%d body=%s", browserResponse.Code, browserResponse.Body.String())
	}
	location, err := url.Parse(browserResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != strings.TrimPrefix(twitch.URL, "http://") || location.Query().Get("state") != started.State {
		t.Fatalf("unexpected Twitch redirect: %s", location)
	}

	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/v1/auth/twitch/callback?state="+url.QueryEscape(started.State)+"&code=authorization-code",
		nil,
	)
	callbackResponse := httptest.NewRecorder()
	server.twitchOAuthCallback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", callbackResponse.Code, callbackResponse.Body.String())
	}
	callbackHTML := html.UnescapeString(callbackResponse.Body.String())
	match := regexp.MustCompile(`io\.ferventio\.app://oauth/callback\?[^"<]+`).FindString(callbackHTML)
	if match == "" {
		t.Fatalf("app deep link missing: %s", callbackHTML)
	}
	deepLink, err := url.Parse(match)
	if err != nil {
		t.Fatal(err)
	}
	handoffCode := deepLink.Query().Get("code")
	if handoffCode == "" || deepLink.Query().Get("state") != started.State {
		t.Fatalf("invalid app handoff link: %s", deepLink)
	}
	if strings.Contains(callbackHTML, "twitch-access-1") || strings.Contains(callbackHTML, "twitch-refresh-1") {
		t.Fatal("Twitch token leaked through browser callback")
	}

	completeBody := `{"installationId":"` + installationID + `","deviceSecret":"` + deviceSecret + `","code":"` + handoffCode + `","state":"` + started.State + `"}`
	completeRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/mobile/complete", strings.NewReader(completeBody))
	completeResponse := httptest.NewRecorder()
	server.completeMobileAuth(completeResponse, completeRequest)
	if completeResponse.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", completeResponse.Code, completeResponse.Body.String())
	}
	var completed mobileAuthCompleteResponse
	if err := json.Unmarshal(completeResponse.Body.Bytes(), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.SessionToken == "" || completed.SessionToken == completed.Lease.AccessToken {
		t.Fatal("backend session must be opaque and distinct from Twitch access token")
	}
	if completed.Lease.AccessToken != "twitch-access-1" || completed.Lease.LeaseExpiresAt.After(time.Now().Add(70*time.Second)) {
		t.Fatalf("unexpected lease: %+v", completed.Lease)
	}
	if completed.Lease.TwitchValidatedAt.IsZero() || completed.Lease.TwitchValidatedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("unexpected Twitch validation timestamp: %v", completed.Lease.TwitchValidatedAt)
	}

	leaseRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	leaseRequest.Header.Set("Authorization", "Bearer "+completed.SessionToken)
	leaseRequest.Header.Set("X-Installation-ID", installationID)
	leaseRequest.Header.Set("X-Device-Secret", deviceSecret)
	leaseResponse := httptest.NewRecorder()
	server.leaseMobileToken(leaseResponse, leaseRequest)
	if leaseResponse.Code != http.StatusOK {
		t.Fatalf("lease status=%d body=%s", leaseResponse.Code, leaseResponse.Body.String())
	}
	if tokenRequests != 1 {
		t.Fatalf("valid Twitch token should be reused, token requests=%d", tokenRequests)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/auth/session", nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+completed.SessionToken)
	deleteRequest.Header.Set("X-Installation-ID", installationID)
	deleteRequest.Header.Set("X-Device-Secret", deviceSecret)
	deleteResponse := httptest.NewRecorder()
	server.deleteMobileSession(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
}
