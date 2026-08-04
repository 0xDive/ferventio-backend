package application

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	errOAuthDisabled = errors.New("Twitch OAuth broker is not configured")
	errOAuthRevoked  = errors.New("Twitch authorization is no longer valid")
)

type twitchTokenResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	Scopes       []string `json:"scope"`
	TokenType    string   `json:"token_type"`
}

type twitchValidationResponse struct {
	ClientID  string   `json:"client_id"`
	UserID    string   `json:"user_id"`
	Login     string   `json:"login"`
	Scopes    []string `json:"scopes"`
	ExpiresIn int64    `json:"expires_in"`
}

type moderatedChannelCacheEntry struct {
	IDs       []string
	ExpiresAt time.Time
}

type twitchOAuthClient struct {
	cfg            Config
	store          AuthRepository
	http           *http.Client
	locks          [64]sync.Mutex
	moderatedMu    sync.Mutex
	moderatedCache map[string]moderatedChannelCacheEntry
}

func newTwitchOAuthClient(cfg Config, store AuthRepository) *twitchOAuthClient {
	if store == nil || !cfg.AuthEnabled() {
		return nil
	}
	return &twitchOAuthClient{
		cfg:            cfg,
		store:          store,
		moderatedCache: map[string]moderatedChannelCacheEntry{},
		http: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

func (c *twitchOAuthClient) authorizationURL(state string) string {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", c.cfg.TwitchClientID)
	values.Set("redirect_uri", c.cfg.TwitchRedirectURL)
	values.Set("scope", strings.Join(c.cfg.AuthScopes, " "))
	values.Set("state", state)
	return strings.TrimSuffix(c.cfg.TwitchIDBaseURL, "/") + "/oauth2/authorize?" + values.Encode()
}

func (c *twitchOAuthClient) exchangeCode(ctx context.Context, code string) (authCredential, error) {
	values := url.Values{}
	values.Set("client_id", c.cfg.TwitchClientID)
	values.Set("client_secret", c.cfg.TwitchClientSecret)
	values.Set("code", code)
	values.Set("grant_type", "authorization_code")
	values.Set("redirect_uri", c.cfg.TwitchRedirectURL)
	token, err := c.requestToken(ctx, values)
	if err != nil {
		return authCredential{}, err
	}
	validation, err := c.validate(ctx, token.AccessToken)
	if err != nil {
		return authCredential{}, err
	}
	if validation.ClientID != c.cfg.TwitchClientID {
		return authCredential{}, errors.New("Twitch returned a token for another client ID")
	}
	if err := ensureScopes(validation.Scopes, c.cfg.AuthScopes); err != nil {
		return authCredential{}, err
	}
	id, err := randomToken("fc1_", 24)
	if err != nil {
		return authCredential{}, err
	}
	now := time.Now().UTC()
	return authCredential{
		ID:              id,
		ClientID:        validation.ClientID,
		UserID:          validation.UserID,
		Login:           validation.Login,
		Scopes:          normalizedScopes(validation.Scopes),
		AccessToken:     token.AccessToken,
		RefreshToken:    token.RefreshToken,
		AccessExpiresAt: now.Add(time.Duration(minPositiveInt64(token.ExpiresIn, validation.ExpiresIn)) * time.Second),
		LastValidatedAt: now,
		UpdatedAt:       now,
	}, nil
}

func (c *twitchOAuthClient) lease(ctx context.Context, credentialID string, forceRefresh bool) (authCredential, error) {
	lock := c.lockForCredential(credentialID)
	lock.Lock()
	defer lock.Unlock()

	credential, err := c.store.GetCredential(credentialID)
	if err != nil {
		return authCredential{}, err
	}
	now := time.Now().UTC()
	refreshAhead := c.cfg.AuthAccessRefreshAhead
	if refreshAhead <= 0 {
		refreshAhead = 5 * time.Minute
	}
	refreshNeeded := forceRefresh || credential.AccessExpiresAt.Before(now.Add(refreshAhead))
	if !refreshNeeded && now.Sub(credential.LastValidatedAt) >= 55*time.Minute {
		validation, validateErr := c.validate(ctx, credential.AccessToken)
		if validateErr != nil {
			if errors.Is(validateErr, errOAuthRevoked) {
				refreshNeeded = true
			} else {
				return authCredential{}, validateErr
			}
		} else {
			if validation.ClientID != c.cfg.TwitchClientID || validation.UserID != credential.UserID {
				return authCredential{}, errOAuthRevoked
			}
			if err := ensureScopes(validation.Scopes, c.cfg.AuthScopes); err != nil {
				return authCredential{}, errOAuthRevoked
			}
			credential.Login = validation.Login
			credential.Scopes = normalizedScopes(validation.Scopes)
			credential.AccessExpiresAt = now.Add(time.Duration(validation.ExpiresIn) * time.Second)
			credential.LastValidatedAt = now
			credential.UpdatedAt = now
			if err := c.store.PutCredential(credential); err != nil {
				return authCredential{}, err
			}
		}
	}
	if refreshNeeded {
		refreshed, refreshErr := c.refresh(ctx, credential.RefreshToken)
		if refreshErr != nil {
			return authCredential{}, refreshErr
		}
		validation, validateErr := c.validate(ctx, refreshed.AccessToken)
		if validateErr != nil {
			return authCredential{}, validateErr
		}
		if validation.ClientID != c.cfg.TwitchClientID || validation.UserID != credential.UserID {
			return authCredential{}, errOAuthRevoked
		}
		if err := ensureScopes(validation.Scopes, c.cfg.AuthScopes); err != nil {
			return authCredential{}, errOAuthRevoked
		}
		credential.AccessToken = refreshed.AccessToken
		credential.RefreshToken = refreshed.RefreshToken
		credential.Login = validation.Login
		credential.Scopes = normalizedScopes(validation.Scopes)
		credential.AccessExpiresAt = now.Add(time.Duration(minPositiveInt64(refreshed.ExpiresIn, validation.ExpiresIn)) * time.Second)
		credential.LastValidatedAt = now
		credential.UpdatedAt = now
		if err := c.store.PutCredential(credential); err != nil {
			return authCredential{}, err
		}
	}
	return credential, nil
}

func (c *twitchOAuthClient) lockForCredential(credentialID string) *sync.Mutex {
	sum := sha256.Sum256([]byte(credentialID))
	return &c.locks[int(sum[0])%len(c.locks)]
}

func (c *twitchOAuthClient) refresh(ctx context.Context, refreshToken string) (twitchTokenResponse, error) {
	values := url.Values{}
	values.Set("client_id", c.cfg.TwitchClientID)
	values.Set("client_secret", c.cfg.TwitchClientSecret)
	values.Set("grant_type", "refresh_token")
	values.Set("refresh_token", refreshToken)
	return c.requestToken(ctx, values)
}

func (c *twitchOAuthClient) requestToken(ctx context.Context, values url.Values) (twitchTokenResponse, error) {
	endpoint := strings.TrimSuffix(c.cfg.TwitchIDBaseURL, "/") + "/oauth2/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return twitchTokenResponse{}, fmt.Errorf("create Twitch token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return twitchTokenResponse{}, fmt.Errorf("Twitch token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return twitchTokenResponse{}, fmt.Errorf("read Twitch token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
			return twitchTokenResponse{}, errOAuthRevoked
		}
		return twitchTokenResponse{}, fmt.Errorf("Twitch token HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var token twitchTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return twitchTokenResponse{}, fmt.Errorf("decode Twitch token response: %w", err)
	}
	if token.AccessToken == "" || token.RefreshToken == "" || token.ExpiresIn <= 0 {
		return twitchTokenResponse{}, errors.New("Twitch returned incomplete OAuth tokens")
	}
	return token, nil
}

// revokeAccessToken asks Twitch to invalidate the current access token for a stored
// authorization. A 400 response means the token is already invalid and is treated as
// idempotent success. Local Ferventio revocation still removes the refresh token afterward.
func (c *twitchOAuthClient) revokeAccessToken(ctx context.Context, credential authCredential) error {
	lock := c.lockForCredential(credential.ID)
	lock.Lock()
	defer lock.Unlock()
	values := url.Values{}
	values.Set("client_id", c.cfg.TwitchClientID)
	values.Set("token", credential.AccessToken)
	endpoint := strings.TrimSuffix(c.cfg.TwitchIDBaseURL, "/") + "/oauth2/revoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("create Twitch revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Twitch revoke request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Twitch revoke response: %w", err)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
		return nil
	}
	return fmt.Errorf("Twitch revoke HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func (c *twitchOAuthClient) validate(ctx context.Context, accessToken string) (twitchValidationResponse, error) {
	endpoint := strings.TrimSuffix(c.cfg.TwitchIDBaseURL, "/") + "/oauth2/validate"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return twitchValidationResponse{}, fmt.Errorf("create Twitch validation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return twitchValidationResponse{}, fmt.Errorf("Twitch validation request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return twitchValidationResponse{}, fmt.Errorf("read Twitch validation response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return twitchValidationResponse{}, errOAuthRevoked
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return twitchValidationResponse{}, fmt.Errorf("Twitch validation HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var validation twitchValidationResponse
	if err := json.Unmarshal(body, &validation); err != nil {
		return twitchValidationResponse{}, fmt.Errorf("decode Twitch validation response: %w", err)
	}
	if validation.ClientID == "" || validation.UserID == "" || validation.Login == "" || validation.ExpiresIn <= 0 {
		return twitchValidationResponse{}, errors.New("Twitch returned incomplete validation data")
	}
	return validation, nil
}

func ensureScopes(actual, required []string) error {
	set := make(map[string]struct{}, len(actual))
	for _, scope := range actual {
		set[scope] = struct{}{}
	}
	var missing []string
	for _, scope := range required {
		if _, ok := set[scope]; !ok {
			missing = append(missing, scope)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("Twitch authorization is missing scopes: %s", strings.Join(missing, ", "))
	}
	return nil
}

func normalizedScopes(scopes []string) []string {
	unique := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope = strings.TrimSpace(scope); scope != "" {
			unique[scope] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for scope := range unique {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func minPositiveInt64(left, right int64) int64 {
	switch {
	case left <= 0:
		return right
	case right <= 0:
		return left
	case left < right:
		return left
	default:
		return right
	}
}

type twitchModeratedChannelsResponse struct {
	Data []struct {
		BroadcasterID string `json:"broadcaster_id"`
	} `json:"data"`
	Pagination struct {
		Cursor string `json:"cursor"`
	} `json:"pagination"`
}

func (c *twitchOAuthClient) moderatedChannelIDs(ctx context.Context, credentialID string) ([]string, error) {
	now := time.Now().UTC()
	c.moderatedMu.Lock()
	if cached, ok := c.moderatedCache[credentialID]; ok && now.Before(cached.ExpiresAt) {
		ids := append([]string(nil), cached.IDs...)
		c.moderatedMu.Unlock()
		return ids, nil
	}
	c.moderatedMu.Unlock()

	credential, err := c.lease(ctx, credentialID, false)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	cursor := ""
	for {
		query := url.Values{
			"user_id": []string{credential.UserID},
			"first":   []string{"100"},
		}
		if cursor != "" {
			query.Set("after", cursor)
		}
		endpoint := strings.TrimSuffix(c.cfg.TwitchHelixBaseURL, "/") + "/moderation/channels?" + query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("create moderated channels request: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+credential.AccessToken)
		request.Header.Set("Client-Id", c.cfg.TwitchClientID)
		request.Header.Set("Accept", "application/json")
		response, err := c.http.Do(request)
		if err != nil {
			return nil, fmt.Errorf("moderated channels request: %w", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read moderated channels response: %w", readErr)
		}
		if response.StatusCode == http.StatusUnauthorized {
			return nil, errOAuthRevoked
		}
		if response.StatusCode < 200 || response.StatusCode > 299 {
			return nil, fmt.Errorf(
				"moderated channels HTTP %d: %s",
				response.StatusCode,
				strings.TrimSpace(string(payload)),
			)
		}
		var page twitchModeratedChannelsResponse
		if err := json.Unmarshal(payload, &page); err != nil {
			return nil, fmt.Errorf("decode moderated channels response: %w", err)
		}
		for _, channel := range page.Data {
			if id := strings.TrimSpace(channel.BroadcasterID); id != "" {
				result = append(result, id)
			}
		}
		cursor = strings.TrimSpace(page.Pagination.Cursor)
		if cursor == "" {
			result = normalizeLimitedStrings(result, 1_000, 64)
			c.moderatedMu.Lock()
			if c.moderatedCache == nil {
				c.moderatedCache = map[string]moderatedChannelCacheEntry{}
			}
			c.moderatedCache[credentialID] = moderatedChannelCacheEntry{
				IDs:       append([]string(nil), result...),
				ExpiresAt: now.Add(5 * time.Minute),
			}
			c.moderatedMu.Unlock()
			return result, nil
		}
	}
}
