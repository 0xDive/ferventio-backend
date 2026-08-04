package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultTwitchIdentityURL = "https://id.twitch.tv/oauth2/token"
	defaultTwitchHelixURL    = "https://api.twitch.tv/helix"
	maxTwitchMetadataBytes   = 4 << 20
)

var errTwitchMetadataDisabled = errors.New("Twitch metadata relay is not configured")

type twitchMetadataCacheEntry struct {
	body      []byte
	expiresAt time.Time
}

type twitchMetadataClient struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
	identityURL  string
	helixURL     string
	now          func() time.Time

	tokenMu        sync.Mutex
	accessToken    string
	tokenExpiresAt time.Time

	cacheMu      sync.Mutex
	globalBadges twitchMetadataCacheEntry
	channelBadge map[string]twitchMetadataCacheEntry
}

func newTwitchMetadataClient(cfg Config) *twitchMetadataClient {
	return &twitchMetadataClient{
		clientID:     cfg.TwitchClientID,
		clientSecret: cfg.TwitchClientSecret,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		identityURL:  defaultTwitchIdentityURL,
		helixURL:     defaultTwitchHelixURL,
		now:          time.Now,
		channelBadge: make(map[string]twitchMetadataCacheEntry),
	}
}

func (c *twitchMetadataClient) enabled() bool {
	return strings.TrimSpace(c.clientID) != "" && strings.TrimSpace(c.clientSecret) != ""
}

func (c *twitchMetadataClient) globalChatBadges(ctx context.Context) ([]byte, error) {
	if !c.enabled() {
		return nil, errTwitchMetadataDisabled
	}
	if body, ok := c.cachedGlobal(); ok {
		return body, nil
	}
	body, err := c.fetchHelix(ctx, "/chat/badges/global", nil)
	if err != nil {
		return nil, err
	}
	c.cacheMu.Lock()
	c.globalBadges = twitchMetadataCacheEntry{
		body:      cloneBytes(body),
		expiresAt: c.now().Add(6 * time.Hour),
	}
	c.cacheMu.Unlock()
	return cloneBytes(body), nil
}

func (c *twitchMetadataClient) channelChatBadges(ctx context.Context, broadcasterID string) ([]byte, error) {
	if !c.enabled() {
		return nil, errTwitchMetadataDisabled
	}
	if !validTwitchID(broadcasterID) {
		return nil, fmt.Errorf("invalid broadcaster ID")
	}
	if body, ok := c.cachedChannel(broadcasterID); ok {
		return body, nil
	}
	query := url.Values{"broadcaster_id": []string{broadcasterID}}
	body, err := c.fetchHelix(ctx, "/chat/badges", query)
	if err != nil {
		return nil, err
	}
	c.cacheMu.Lock()
	c.channelBadge[broadcasterID] = twitchMetadataCacheEntry{
		body:      cloneBytes(body),
		expiresAt: c.now().Add(30 * time.Minute),
	}
	c.cacheMu.Unlock()
	return cloneBytes(body), nil
}

func (c *twitchMetadataClient) cachedGlobal() ([]byte, bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if len(c.globalBadges.body) == 0 || !c.now().Before(c.globalBadges.expiresAt) {
		c.globalBadges = twitchMetadataCacheEntry{}
		return nil, false
	}
	return cloneBytes(c.globalBadges.body), true
}

func (c *twitchMetadataClient) cachedChannel(broadcasterID string) ([]byte, bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	entry, ok := c.channelBadge[broadcasterID]
	if !ok || len(entry.body) == 0 || !c.now().Before(entry.expiresAt) {
		delete(c.channelBadge, broadcasterID)
		return nil, false
	}
	return cloneBytes(entry.body), true
}

func (c *twitchMetadataClient) fetchHelix(
	ctx context.Context,
	path string,
	query url.Values,
) ([]byte, error) {
	body, status, err := c.fetchHelixOnce(ctx, path, query)
	if err == nil {
		return body, nil
	}
	if status != http.StatusUnauthorized {
		return nil, err
	}
	c.invalidateToken()
	body, _, retryErr := c.fetchHelixOnce(ctx, path, query)
	return body, retryErr
}

func (c *twitchMetadataClient) fetchHelixOnce(
	ctx context.Context,
	path string,
	query url.Values,
) ([]byte, int, error) {
	token, err := c.appAccessToken(ctx)
	if err != nil {
		return nil, 0, err
	}
	endpoint, err := url.Parse(strings.TrimRight(c.helixURL, "/") + path)
	if err != nil {
		return nil, 0, fmt.Errorf("build Twitch Helix URL: %w", err)
	}
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create Twitch Helix request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Client-Id", c.clientID)
	req.Header.Set("User-Agent", "Ferventio-Metadata-Relay/1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request Twitch Helix: %w", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTwitchMetadataBytes+1))
	if readErr != nil {
		return nil, resp.StatusCode, fmt.Errorf("read Twitch Helix response: %w", readErr)
	}
	if len(body) > maxTwitchMetadataBytes {
		return nil, resp.StatusCode, fmt.Errorf("Twitch Helix response is too large")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("Twitch Helix returned %d: %s", resp.StatusCode, compactError(body))
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Data) == 0 {
		return nil, resp.StatusCode, fmt.Errorf("Twitch Helix returned invalid badge metadata")
	}
	return body, resp.StatusCode, nil
}

func (c *twitchMetadataClient) appAccessToken(ctx context.Context) (string, error) {
	if !c.enabled() {
		return "", errTwitchMetadataDisabled
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" && c.now().Add(2*time.Minute).Before(c.tokenExpiresAt) {
		return c.accessToken, nil
	}

	endpoint, err := url.Parse(c.identityURL)
	if err != nil {
		return "", fmt.Errorf("build Twitch identity URL: %w", err)
	}
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create Twitch token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Ferventio-Metadata-Relay/1")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request Twitch app token: %w", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if readErr != nil {
		return "", fmt.Errorf("read Twitch token response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Twitch token endpoint returned %d: %s", resp.StatusCode, compactError(body))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode Twitch app token: %w", err)
	}
	if strings.TrimSpace(payload.AccessToken) == "" || payload.ExpiresIn <= 0 {
		return "", fmt.Errorf("Twitch token endpoint returned incomplete credentials")
	}
	c.accessToken = payload.AccessToken
	c.tokenExpiresAt = c.now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	return c.accessToken, nil
}

func (c *twitchMetadataClient) invalidateToken() {
	c.tokenMu.Lock()
	c.accessToken = ""
	c.tokenExpiresAt = time.Time{}
	c.tokenMu.Unlock()
}

func validTwitchID(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func compactError(body []byte) string {
	value := strings.TrimSpace(string(body))
	if len(value) > 300 {
		return value[:300]
	}
	return value
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
