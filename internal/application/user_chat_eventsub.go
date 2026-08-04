package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

const (
	defaultUserChatEventSubURL = "wss://eventsub.wss.twitch.tv/ws"
	maxUserChatChannels        = 100
	maxUserChatMessageBytes    = 1 << 20
)

var errUserChatUnauthorized = errors.New("Twitch user chat authorization rejected")

type userChatCredentialProvider interface {
	CredentialForUser(userID string) (authCredential, error)
}

type userChatEventSubManager struct {
	server *Server
	wsURL  string
	http   *http.Client

	mu       sync.Mutex
	sessions map[string]*userChatSession
}

type userChatSession struct {
	signature string
	cancel    context.CancelFunc
	done      chan struct{}
}

type userChatWebSocketMessage struct {
	Metadata struct {
		MessageID           string `json:"message_id"`
		MessageType         string `json:"message_type"`
		SubscriptionType    string `json:"subscription_type"`
		SubscriptionVersion string `json:"subscription_version"`
	} `json:"metadata"`
	Payload struct {
		Session struct {
			ID                      string `json:"id"`
			ReconnectURL            string `json:"reconnect_url"`
			KeepaliveTimeoutSeconds int    `json:"keepalive_timeout_seconds"`
		} `json:"session"`
		Subscription struct {
			ID        string            `json:"id"`
			Type      string            `json:"type"`
			Version   string            `json:"version"`
			Status    string            `json:"status"`
			Condition map[string]string `json:"condition"`
		} `json:"subscription"`
		Event map[string]any `json:"event"`
	} `json:"payload"`
}

type userChatSubscriptionRequest struct {
	Type      string            `json:"type"`
	Version   string            `json:"version"`
	Condition map[string]string `json:"condition"`
	Transport struct {
		Method    string `json:"method"`
		SessionID string `json:"session_id"`
	} `json:"transport"`
}

func newUserChatEventSubManager(server *Server) *userChatEventSubManager {
	return &userChatEventSubManager{
		server:   server,
		wsURL:    defaultUserChatEventSubURL,
		http:     &http.Client{Timeout: 20 * time.Second},
		sessions: map[string]*userChatSession{},
	}
}

// RunUserChatEventSub maintains one personal Twitch EventSub WebSocket per
// token owner that is currently needed to cover ordinary viewer chats.
func (s *Server) RunUserChatEventSub(ctx context.Context) {
	manager := newUserChatEventSubManager(s)
	if !manager.enabled() {
		return
	}
	defer manager.stopAll()

	reconcile := func() {
		started, stopped := manager.reconcile(ctx, s.store.List())
		if started > 0 || stopped > 0 {
			s.log.Info(
				"user chat EventSub reconciled",
				"started", started,
				"stopped", stopped,
			)
		}
	}
	reconcile()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

func (m *userChatEventSubManager) enabled() bool {
	if m == nil || m.server == nil || m.server.authStore == nil || m.server.oauth == nil {
		return false
	}
	_, ok := m.server.authStore.(userChatCredentialProvider)
	return ok && strings.TrimSpace(m.server.cfg.TwitchClientID) != "" &&
		strings.TrimSpace(m.server.cfg.TwitchHelixBaseURL) != ""
}

func (m *userChatEventSubManager) reconcile(ctx context.Context, registrations []Registration) (started, stopped int) {
	if !m.enabled() {
		return 0, m.stopAll()
	}

	webhookEnabled := m.server.eventSub != nil && m.server.eventSub.enabled()
	desired := assignUserChatChannels(registrations, webhookEnabled)
	m.mu.Lock()
	defer m.mu.Unlock()

	for userID, session := range m.sessions {
		channels, ok := desired[userID]
		if ok && session.signature == userChatSessionSignature(channels) {
			delete(desired, userID)
			continue
		}
		session.cancel()
		delete(m.sessions, userID)
		stopped++
	}

	for userID, channels := range desired {
		if len(channels) == 0 {
			continue
		}
		sessionCtx, cancel := context.WithCancel(ctx)
		session := &userChatSession{
			signature: userChatSessionSignature(channels),
			cancel:    cancel,
			done:      make(chan struct{}),
		}
		m.sessions[userID] = session
		started++
		go m.runSession(sessionCtx, userID, append([]string(nil), channels...), session.done)
	}
	return started, stopped
}

func (m *userChatEventSubManager) stopAll() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stopped := len(m.sessions)
	for userID, session := range m.sessions {
		session.cancel()
		delete(m.sessions, userID)
	}
	return stopped
}

func assignUserChatChannels(registrations []Registration, webhookEnabled bool) map[string][]string {
	coveredByWebhook := map[string]struct{}{}
	watchers := map[string]map[string]struct{}{}

	for _, registration := range registrations {
		userID := strings.TrimSpace(registration.UserID)
		if userID == "" || !anyRule(registration, "mention", "reply", "highlight", "selected_user") {
			continue
		}
		for _, rawChannelID := range registration.ChannelIDs {
			channelID := strings.TrimSpace(rawChannelID)
			if channelID == "" {
				continue
			}
			if webhookEnabled && (channelID == userID || containsString(registration.ModeratorChannelIDs, channelID)) {
				coveredByWebhook[channelID] = struct{}{}
			}
			if watchers[channelID] == nil {
				watchers[channelID] = map[string]struct{}{}
			}
			watchers[channelID][userID] = struct{}{}
		}
	}

	channels := make([]string, 0, len(watchers))
	for channelID := range watchers {
		if _, covered := coveredByWebhook[channelID]; !covered {
			channels = append(channels, channelID)
		}
	}
	sort.Slice(channels, func(i, j int) bool {
		left := len(watchers[channels[i]])
		right := len(watchers[channels[j]])
		if left != right {
			return left < right
		}
		return channels[i] < channels[j]
	})

	assigned := map[string][]string{}
	for _, channelID := range channels {
		candidates := make([]string, 0, len(watchers[channelID]))
		for userID := range watchers[channelID] {
			candidates = append(candidates, userID)
		}
		sort.Slice(candidates, func(i, j int) bool {
			left := len(assigned[candidates[i]])
			right := len(assigned[candidates[j]])
			if left != right {
				return left < right
			}
			return candidates[i] < candidates[j]
		})
		for _, userID := range candidates {
			if len(assigned[userID]) >= maxUserChatChannels {
				continue
			}
			assigned[userID] = append(assigned[userID], channelID)
			break
		}
	}
	for userID := range assigned {
		sort.Strings(assigned[userID])
	}
	return assigned
}

func userChatSessionSignature(channels []string) string {
	hash := sha256.Sum256([]byte(strings.Join(channels, "\x00")))
	return hex.EncodeToString(hash[:])
}

func (m *userChatEventSubManager) runSession(
	ctx context.Context,
	userID string,
	channels []string,
	done chan<- struct{},
) {
	defer close(done)
	provider := m.server.authStore.(userChatCredentialProvider)
	endpoint := m.wsURL
	resubscribe := true
	backoff := time.Second

	for ctx.Err() == nil {
		credential, err := provider.CredentialForUser(userID)
		if err == nil {
			credential, err = m.server.oauth.lease(ctx, credential.ID, false)
		}
		if err != nil {
			m.server.log.Warn("user chat EventSub credential unavailable", "user_id", userID, "error", err)
			if !waitUserChatRetry(ctx, backoff) {
				return
			}
			backoff = nextUserChatBackoff(backoff)
			continue
		}

		reconnectURL, serveErr := m.serveConnection(ctx, endpoint, credential, userID, channels, resubscribe)
		if ctx.Err() != nil {
			return
		}
		if reconnectURL != "" {
			endpoint = reconnectURL
			resubscribe = false
			backoff = time.Second
			continue
		}
		endpoint = m.wsURL
		resubscribe = true
		if errors.Is(serveErr, errUserChatUnauthorized) {
			_, _ = m.server.oauth.lease(ctx, credential.ID, true)
		}
		if serveErr != nil {
			m.server.log.Warn(
				"user chat EventSub connection closed",
				"user_id", userID,
				"channels", len(channels),
				"error", serveErr,
			)
		}
		if !waitUserChatRetry(ctx, backoff) {
			return
		}
		backoff = nextUserChatBackoff(backoff)
	}
}

func (m *userChatEventSubManager) serveConnection(
	ctx context.Context,
	endpoint string,
	credential authCredential,
	userID string,
	channels []string,
	resubscribe bool,
) (string, error) {
	config, err := websocket.NewConfig(endpoint, "https://ferventio.app")
	if err != nil {
		return "", fmt.Errorf("create user chat WebSocket config: %w", err)
	}
	config.Dialer = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	connection, err := websocket.DialConfig(config)
	if err != nil {
		return "", fmt.Errorf("dial user chat EventSub: %w", err)
	}
	defer connection.Close()

	cancelRead := make(chan struct{})
	defer close(cancelRead)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-cancelRead:
		}
	}()

	_ = connection.SetReadDeadline(time.Now().Add(15 * time.Second))
	welcomed := false
	for {
		var raw []byte
		if err := websocket.Message.Receive(connection, &raw); err != nil {
			return "", err
		}
		if len(raw) == 0 || len(raw) > maxUserChatMessageBytes {
			return "", errors.New("invalid user chat EventSub frame size")
		}
		var message userChatWebSocketMessage
		if err := json.Unmarshal(raw, &message); err != nil {
			return "", fmt.Errorf("decode user chat EventSub frame: %w", err)
		}

		keepalive := message.Payload.Session.KeepaliveTimeoutSeconds
		if keepalive <= 0 {
			keepalive = 10
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Duration(keepalive+10) * time.Second))

		switch message.Metadata.MessageType {
		case "session_welcome":
			if welcomed || strings.TrimSpace(message.Payload.Session.ID) == "" {
				return "", errors.New("invalid user chat EventSub welcome")
			}
			welcomed = true
			if resubscribe {
				_ = connection.SetReadDeadline(time.Now().Add(2 * time.Minute))
				if err := m.createChatSubscriptions(
					ctx,
					credential.AccessToken,
					userID,
					message.Payload.Session.ID,
					channels,
				); err != nil {
					return "", err
				}
				_ = connection.SetReadDeadline(time.Now().Add(time.Duration(keepalive+10) * time.Second))
			}
			m.server.log.Info("user chat EventSub connected", "user_id", userID, "channels", len(channels))
		case "session_keepalive":
			if !welcomed {
				return "", errors.New("user chat EventSub keepalive before welcome")
			}
		case "session_reconnect":
			reconnectURL := strings.TrimSpace(message.Payload.Session.ReconnectURL)
			if reconnectURL == "" {
				return "", errors.New("user chat EventSub reconnect URL is missing")
			}
			if err := validateUserChatReconnectURL(reconnectURL); err != nil {
				return "", err
			}
			return reconnectURL, nil
		case "notification":
			if !welcomed || message.Metadata.SubscriptionType != "channel.chat.message" {
				continue
			}
			if err := m.server.enqueueUserChatEvent(message); err != nil {
				m.server.log.Warn(
					"user chat EventSub event was not enqueued",
					"user_id", userID,
					"event_id", message.Metadata.MessageID,
					"error", err,
				)
			}
		case "revocation":
			return "", fmt.Errorf(
				"user chat EventSub subscription revoked: %s",
				message.Payload.Subscription.Status,
			)
		}
	}
}

func (m *userChatEventSubManager) createChatSubscriptions(
	ctx context.Context,
	accessToken string,
	userID string,
	sessionID string,
	channels []string,
) error {
	if len(channels) == 0 {
		return nil
	}
	if err := m.createChatSubscription(ctx, accessToken, userID, sessionID, channels[0]); err != nil {
		return err
	}
	if len(channels) == 1 {
		return nil
	}

	workerCount := 4
	if len(channels)-1 < workerCount {
		workerCount = len(channels) - 1
	}
	jobs := make(chan string)
	errorsChannel := make(chan error, len(channels)-1)
	var workers sync.WaitGroup
	for index := 0; index < workerCount; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for channelID := range jobs {
				if err := m.createChatSubscription(ctx, accessToken, userID, sessionID, channelID); err != nil {
					errorsChannel <- err
				}
			}
		}()
	}
	for _, channelID := range channels[1:] {
		jobs <- channelID
	}
	close(jobs)
	workers.Wait()
	close(errorsChannel)
	var failures []error
	for err := range errorsChannel {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (m *userChatEventSubManager) createChatSubscription(
	ctx context.Context,
	accessToken string,
	userID string,
	sessionID string,
	channelID string,
) error {
	requestBody := userChatSubscriptionRequest{
		Type:    "channel.chat.message",
		Version: "1",
		Condition: map[string]string{
			"broadcaster_user_id": channelID,
			"user_id":             userID,
		},
	}
	requestBody.Transport.Method = "websocket"
	requestBody.Transport.SessionID = sessionID
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(m.server.cfg.TwitchHelixBaseURL, "/") + "/eventsub/subscriptions"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Client-Id", m.server.cfg.TwitchClientID)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := m.http.Do(request)
	if err != nil {
		return fmt.Errorf("create user chat EventSub subscription for %s: %w", channelID, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode == http.StatusUnauthorized {
		return errUserChatUnauthorized
	}
	if response.StatusCode == http.StatusConflict {
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf(
			"create user chat EventSub subscription for %s HTTP %d: %s",
			channelID,
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}
	return nil
}

func (s *Server) enqueueUserChatEvent(message userChatWebSocketMessage) error {
	envelope := eventSubEnvelope{}
	envelope.Subscription.ID = message.Payload.Subscription.ID
	envelope.Subscription.Type = firstNonBlank(message.Payload.Subscription.Type, message.Metadata.SubscriptionType)
	envelope.Subscription.Version = firstNonBlank(message.Payload.Subscription.Version, message.Metadata.SubscriptionVersion)
	envelope.Subscription.Status = message.Payload.Subscription.Status
	envelope.Subscription.Condition = message.Payload.Subscription.Condition
	envelope.Event = message.Payload.Event

	messageID := strings.TrimSpace(stringValue(envelope.Event, "message_id"))
	if messageID != "" {
		messageID = "chat:" + messageID
	} else {
		messageID = "ws:" + strings.TrimSpace(message.Metadata.MessageID)
	}
	if messageID == "ws:" {
		return errors.New("user chat EventSub message ID is missing")
	}

	now := time.Now().UTC()
	record, created, err := s.deliveries.EnqueueEventSub(messageID, envelope, now)
	if err != nil {
		return fmt.Errorf("persist user chat EventSub event: %w", err)
	}
	if created {
		s.auditRecord(AuditRecord{
			Action:    "eventsub.websocket.enqueue",
			Status:    "persisted",
			EventID:   messageID,
			ChannelID: stringValue(envelope.Event, "broadcaster_user_id"),
			Detail:    envelope.Subscription.Type,
		})
	}
	if record.MessageID != "" && record.Status == eventSubInboxStatusPending {
		_ = s.scheduleEventSub(record)
	}
	return nil
}

func waitUserChatRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextUserChatBackoff(current time.Duration) time.Duration {
	current *= 2
	if current > time.Minute {
		return time.Minute
	}
	return current
}

func validateUserChatReconnectURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() != "eventsub.wss.twitch.tv" ||
		parsed.User != nil || parsed.Fragment != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return errors.New("invalid Twitch EventSub reconnect URL")
	}
	return nil
}
