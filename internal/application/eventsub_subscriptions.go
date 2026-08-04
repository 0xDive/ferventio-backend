package application

import (
	"bytes"
	"context"
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

type eventSubSubscriptionSpec struct {
	Type      string            `json:"type"`
	Version   string            `json:"version"`
	Condition map[string]string `json:"condition"`
	Transport struct {
		Method   string `json:"method"`
		Callback string `json:"callback"`
		Secret   string `json:"secret"`
	} `json:"transport"`
}

type eventSubSubscription struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Type      string            `json:"type"`
	Version   string            `json:"version"`
	Condition map[string]string `json:"condition"`
	Transport struct {
		Method   string `json:"method"`
		Callback string `json:"callback"`
	} `json:"transport"`
}

type eventSubListResponse struct {
	Data       []eventSubSubscription `json:"data"`
	Pagination struct {
		Cursor string `json:"cursor"`
	} `json:"pagination"`
}

type appTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type eventSubManager struct {
	cfg        Config
	http       *http.Client
	mu         sync.Mutex
	appToken   string
	tokenUntil time.Time
}

func newEventSubManager(cfg Config) *eventSubManager {
	return &eventSubManager{
		cfg: cfg,
		http: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (m *eventSubManager) enabled() bool {
	return m.cfg.EventSubSecret != "" && m.cfg.EventSubCallbackURL != "" &&
		m.cfg.TwitchClientID != "" && m.cfg.TwitchClientSecret != ""
}

func (m *eventSubManager) reconcile(ctx context.Context, registrations []Registration) (created, deleted int, err error) {
	if !m.enabled() {
		return 0, 0, errors.New("EventSub subscription manager is not configured")
	}
	desired := desiredEventSubSubscriptions(m.cfg, registrations)
	existing, err := m.list(ctx)
	if err != nil {
		return 0, 0, err
	}
	desiredByKey := make(map[string]eventSubSubscriptionSpec, len(desired))
	for _, spec := range desired {
		desiredByKey[eventSubSpecKey(spec.Type, spec.Version, spec.Condition)] = spec
	}
	kept := map[string]bool{}
	blocked := map[string]bool{}
	var failures []error
	for _, subscription := range existing {
		if subscription.Transport.Callback != m.cfg.EventSubCallbackURL {
			continue
		}
		key := eventSubSpecKey(subscription.Type, subscription.Version, subscription.Condition)
		_, wanted := desiredByKey[key]
		usable := subscription.Status == "enabled" || subscription.Status == "webhook_callback_verification_pending"
		if wanted && !kept[key] && usable {
			kept[key] = true
			continue
		}
		if err := m.delete(ctx, subscription.ID); err != nil {
			failures = append(failures, fmt.Errorf("delete %s: %w", key, err))
			blocked[key] = true
			continue
		}
		deleted++
	}
	for key, spec := range desiredByKey {
		if kept[key] || blocked[key] {
			continue
		}
		if err := m.create(ctx, spec); err != nil {
			failures = append(failures, fmt.Errorf("create %s: %w", key, err))
			continue
		}
		created++
	}
	return created, deleted, errors.Join(failures...)
}

func desiredEventSubSubscriptions(cfg Config, registrations []Registration) []eventSubSubscriptionSpec {
	unique := map[string]eventSubSubscriptionSpec{}
	appendSpec := func(eventType, version string, condition map[string]string) {
		for key, value := range condition {
			if strings.TrimSpace(value) == "" {
				return
			}
			condition[key] = strings.TrimSpace(value)
		}
		spec := eventSubSubscriptionSpec{Type: eventType, Version: version, Condition: condition}
		spec.Transport.Method = "webhook"
		spec.Transport.Callback = cfg.EventSubCallbackURL
		spec.Transport.Secret = cfg.EventSubSecret
		unique[eventSubSpecKey(eventType, version, condition)] = spec
	}

	for _, registration := range registrations {
		for _, broadcasterID := range registration.ChannelIDs {
			if broadcasterID = strings.TrimSpace(broadcasterID); broadcasterID == "" {
				continue
			}
			isModerator := containsString(registration.ModeratorChannelIDs, broadcasterID)
			isBroadcaster := registration.UserID != "" && registration.UserID == broadcasterID
			// App-token chat webhooks require user:bot and either moderator status
			// or a broadcaster-granted channel:bot authorization. Ferventio can
			// prove the former today; broadcaster bot grants can be added later.
			if registration.UserID != "" && (isModerator || isBroadcaster) && anyRule(registration, "mention", "reply", "highlight", "selected_user") {
				appendSpec("channel.chat.message", "1", map[string]string{
					"broadcaster_user_id": broadcasterID,
					"user_id":             registration.UserID,
				})
			}
			if registration.UserID != "" && isModerator && ruleEnabled(registration, "automod_hold") {
				appendSpec("automod.message.hold", "2", map[string]string{
					"broadcaster_user_id": broadcasterID,
					"moderator_user_id":   registration.UserID,
				})
			}
			if registration.UserID != "" && isModerator && ruleEnabled(registration, "moderation_action") {
				appendSpec("channel.moderate", "2", map[string]string{
					"broadcaster_user_id": broadcasterID,
					"moderator_user_id":   registration.UserID,
				})
			}
			if isModerator && anyRule(registration, "ban", "timeout") {
				appendSpec("channel.ban", "1", map[string]string{"broadcaster_user_id": broadcasterID})
			}
			if ruleEnabled(registration, "stream_online") {
				appendSpec("stream.online", "1", map[string]string{"broadcaster_user_id": broadcasterID})
			}
			if anyRule(registration, "title_change", "game_change") {
				appendSpec("channel.update", "2", map[string]string{"broadcaster_user_id": broadcasterID})
			}
			if ruleEnabled(registration, "raid") {
				appendSpec("channel.raid", "1", map[string]string{"to_broadcaster_user_id": broadcasterID})
			}
			if isBroadcaster && ruleEnabled(registration, "reward") {
				appendSpec(
					"channel.channel_points_custom_reward_redemption.add",
					"1",
					map[string]string{"broadcaster_user_id": broadcasterID},
				)
			}
			if isBroadcaster && ruleEnabled(registration, "subscription") {
				appendSpec("channel.subscribe", "1", map[string]string{"broadcaster_user_id": broadcasterID})
				appendSpec("channel.subscription.message", "1", map[string]string{"broadcaster_user_id": broadcasterID})
				appendSpec("channel.subscription.gift", "1", map[string]string{"broadcaster_user_id": broadcasterID})
			}
		}
	}
	result := make([]eventSubSubscriptionSpec, 0, len(unique))
	for _, spec := range unique {
		result = append(result, spec)
	}
	sort.Slice(result, func(i, j int) bool {
		return eventSubSpecKey(result[i].Type, result[i].Version, result[i].Condition) <
			eventSubSpecKey(result[j].Type, result[j].Version, result[j].Condition)
	})
	return result
}

func anyRule(registration Registration, rules ...string) bool {
	for _, rule := range rules {
		if ruleEnabled(registration, rule) {
			return true
		}
	}
	return false
}

func eventSubSpecKey(eventType, version string, condition map[string]string) string {
	keys := make([]string, 0, len(condition))
	for key := range condition {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteString(eventType)
	builder.WriteByte('|')
	builder.WriteString(version)
	for _, key := range keys {
		builder.WriteByte('|')
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(condition[key])
	}
	return builder.String()
}

func (m *eventSubManager) create(ctx context.Context, spec eventSubSubscriptionSpec) error {
	body, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	response, err := m.do(ctx, http.MethodPost, "/eventsub/subscriptions", nil, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("create EventSub subscription HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	return nil
}

func (m *eventSubManager) list(ctx context.Context) ([]eventSubSubscription, error) {
	var result []eventSubSubscription
	cursor := ""
	for {
		query := url.Values{}
		if cursor != "" {
			query.Set("after", cursor)
		}
		response, err := m.do(ctx, http.MethodGet, "/eventsub/subscriptions", query, nil)
		if err != nil {
			return nil, err
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if response.StatusCode < 200 || response.StatusCode > 299 {
			return nil, fmt.Errorf("list EventSub subscriptions HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
		}
		var page eventSubListResponse
		if err := json.Unmarshal(payload, &page); err != nil {
			return nil, err
		}
		result = append(result, page.Data...)
		cursor = page.Pagination.Cursor
		if cursor == "" {
			return result, nil
		}
	}
}

func (m *eventSubManager) delete(ctx context.Context, id string) error {
	query := url.Values{"id": []string{id}}
	response, err := m.do(ctx, http.MethodDelete, "/eventsub/subscriptions", query, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("delete EventSub subscription HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	return nil
}

func (m *eventSubManager) deleteAllForCallback(ctx context.Context) (int, error) {
	existing, err := m.list(ctx)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, subscription := range existing {
		if subscription.Transport.Callback != m.cfg.EventSubCallbackURL {
			continue
		}
		if err := m.delete(ctx, subscription.ID); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func (m *eventSubManager) do(
	ctx context.Context,
	method, path string,
	query url.Values,
	body []byte,
) (*http.Response, error) {
	token, err := m.token(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimSuffix(m.cfg.TwitchHelixBaseURL, "/") + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Client-Id", m.cfg.TwitchClientID)
	request.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := m.http.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		response.Body.Close()
		m.invalidateToken()
		token, err = m.token(ctx)
		if err != nil {
			return nil, err
		}
		request, err = http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Client-Id", m.cfg.TwitchClientID)
		request.Header.Set("Accept", "application/json")
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		return m.http.Do(request)
	}
	return response, nil
}

func (m *eventSubManager) token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.appToken != "" && time.Now().UTC().Add(time.Minute).Before(m.tokenUntil) {
		return m.appToken, nil
	}
	endpoint := strings.TrimSuffix(m.cfg.TwitchIDBaseURL, "/") + "/oauth2/token"
	form := url.Values{
		"client_id":     []string{m.cfg.TwitchClientID},
		"client_secret": []string{m.cfg.TwitchClientSecret},
		"grant_type":    []string{"client_credentials"},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := m.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("Twitch app token HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	var token appTokenResponse
	if err := json.Unmarshal(payload, &token); err != nil {
		return "", err
	}
	if token.AccessToken == "" || token.ExpiresIn <= 0 {
		return "", errors.New("Twitch returned incomplete app token")
	}
	m.appToken = token.AccessToken
	m.tokenUntil = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	return m.appToken, nil
}

func (m *eventSubManager) invalidateToken() {
	m.mu.Lock()
	m.appToken = ""
	m.tokenUntil = time.Time{}
	m.mu.Unlock()
}

func (s *Server) adminReconcileEventSub(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	created, deleted, err := s.eventSub.reconcile(r.Context(), s.store.List())
	if err != nil {
		s.auditRecord(AuditRecord{Action: "eventsub.reconcile", Status: "failed", Detail: err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.auditRecord(AuditRecord{
		Action: "eventsub.reconcile",
		Status: "ok",
		Detail: fmt.Sprintf("created=%d deleted=%d", created, deleted),
	})
	writeJSON(w, http.StatusOK, map[string]int{"created": created, "deleted": deleted})
}

func (s *Server) adminListEventSubSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	subscriptions, err := s.eventSub.list(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	filtered := make([]eventSubSubscription, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		if subscription.Transport.Callback == s.cfg.EventSubCallbackURL {
			filtered = append(filtered, subscription)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": filtered})
}

func (s *Server) adminDeleteEventSubSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	deleted, err := s.eventSub.deleteAllForCallback(r.Context())
	if err != nil {
		s.auditRecord(AuditRecord{Action: "eventsub.delete_all", Status: "failed", Detail: err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.auditRecord(AuditRecord{Action: "eventsub.delete_all", Status: "ok", Detail: fmt.Sprintf("deleted=%d", deleted)})
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

func (s *Server) requestEventSubReconcile() {
	if !s.eventSub.enabled() {
		return
	}
	select {
	case s.eventSubReconcile <- struct{}{}:
	default:
	}
}

func (s *Server) runEventSubReconciler(ctx context.Context) {
	if !s.eventSub.enabled() {
		return
	}
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	reconcile := func() {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		created, deleted, err := s.eventSub.reconcile(runCtx, s.store.List())
		if err != nil {
			s.log.Warn("EventSub reconcile failed", "error", err)
			s.auditRecord(AuditRecord{Action: "eventsub.reconcile", Status: "failed", Detail: err.Error()})
			return
		}
		s.log.Info("EventSub reconciled", "created", created, "deleted", deleted)
		s.auditRecord(AuditRecord{
			Action: "eventsub.reconcile",
			Status: "ok",
			Detail: fmt.Sprintf("created=%d deleted=%d", created, deleted),
		})
	}
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		case <-s.eventSubReconcile:
			// Coalesce bursts of registration updates before hitting Twitch.
			timer := time.NewTimer(750 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			for {
				select {
				case <-s.eventSubReconcile:
				default:
					reconcile()
					goto reconciled
				}
			}
		reconciled:
		}
	}
}
