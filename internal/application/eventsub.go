package application

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const eventSubReplayWindow = 10 * time.Minute

type queuedEventSub struct {
	MessageID string
	Envelope  eventSubEnvelope
}

func (s *Server) eventSubWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EventSubSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "EventSub webhook is not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.RequestBodyMaxBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid EventSub body")
		return
	}
	messageID := strings.TrimSpace(r.Header.Get("Twitch-Eventsub-Message-Id"))
	messageTimestamp := strings.TrimSpace(r.Header.Get("Twitch-Eventsub-Message-Timestamp"))
	signature := strings.TrimSpace(r.Header.Get("Twitch-Eventsub-Message-Signature"))
	if err := verifyEventSubMessage(s.cfg.EventSubSecret, messageID, messageTimestamp, signature, body, time.Now().UTC()); err != nil {
		s.log.Warn("EventSub verification failed", "error", err, "message_id", messageID)
		s.auditRecord(AuditRecord{Action: "eventsub.verify", Status: "rejected", EventID: messageID, Detail: err.Error()})
		writeError(w, http.StatusForbidden, "invalid EventSub signature")
		return
	}

	var envelope eventSubEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		writeError(w, http.StatusBadRequest, "invalid EventSub JSON")
		return
	}
	messageType := r.Header.Get("Twitch-Eventsub-Message-Type")
	switch messageType {
	case "webhook_callback_verification":
		if envelope.Challenge == "" {
			writeError(w, http.StatusBadRequest, "missing EventSub challenge")
			return
		}
		s.auditRecord(AuditRecord{
			Action:  "eventsub.challenge",
			Status:  "ok",
			EventID: messageID,
			Detail:  envelope.Subscription.Type,
		})
		challenge := []byte(envelope.Challenge)
		// Twitch requires a raw challenge body and an explicit Content-Length.
		// Set it ourselves so a reverse proxy cannot turn the response into an
		// indeterminate/chunked response during callback verification.
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(challenge)))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(challenge)
	case "notification":
		now := time.Now().UTC()
		record, created, err := s.deliveries.EnqueueEventSub(messageID, envelope, now)
		if err != nil {
			s.log.Error("EventSub inbox persistence failed", "event_id", messageID, "error", err)
			s.auditRecord(AuditRecord{Action: "eventsub.enqueue", Status: "persist_failed", EventID: messageID, Detail: err.Error()})
			writeError(w, http.StatusServiceUnavailable, "EventSub inbox is unavailable")
			return
		}
		if created {
			s.auditRecord(AuditRecord{
				Action:    "eventsub.enqueue",
				Status:    "persisted",
				EventID:   messageID,
				ChannelID: firstNonBlank(stringValue(envelope.Event, "broadcaster_user_id"), stringValue(envelope.Event, "to_broadcaster_user_id")),
				Detail:    envelope.Subscription.Type,
			})
		}
		if record.MessageID != "" && record.Status == eventSubInboxStatusPending && !s.scheduleEventSub(record) {
			s.auditRecord(AuditRecord{
				Action:  "eventsub.enqueue",
				Status:  "persisted_waiting",
				EventID: messageID,
				Detail:  envelope.Subscription.Type,
			})
		}
		// The event is already durable, so Twitch can safely stop retrying even if
		// all in-memory workers are momentarily busy. The inbox drainer will pick it up.
		w.WriteHeader(http.StatusNoContent)
	case "revocation":
		_, _ = s.deliveries.SeenEventSub(messageID, time.Now().UTC(), 24*time.Hour)
		s.log.Warn(
			"EventSub subscription revoked",
			"subscription_id", envelope.Subscription.ID,
			"type", envelope.Subscription.Type,
			"status", envelope.Subscription.Status,
		)
		s.auditRecord(AuditRecord{
			Action:  "eventsub.revocation",
			Status:  envelope.Subscription.Status,
			EventID: messageID,
			Detail:  envelope.Subscription.Type + ":" + envelope.Subscription.ID,
		})
		s.requestEventSubReconcile()
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusBadRequest, "unsupported EventSub message type")
	}
}

func verifyEventSubMessage(secret, messageID, rawTimestamp, signature string, body []byte, now time.Time) error {
	if messageID == "" || rawTimestamp == "" || !strings.HasPrefix(signature, "sha256=") {
		return errors.New("missing EventSub verification headers")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, rawTimestamp)
	if err != nil {
		return fmt.Errorf("invalid EventSub timestamp: %w", err)
	}
	if delta := now.Sub(timestamp); delta > eventSubReplayWindow || delta < -eventSubReplayWindow {
		return errors.New("EventSub timestamp is outside replay window")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(messageID))
	_, _ = mac.Write([]byte(rawTimestamp))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || !hmac.Equal(expected, provided) {
		return errors.New("EventSub signature mismatch")
	}
	return nil
}

func (s *Server) runEventSubWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case queued := <-s.eventQueue:
			s.handleQueuedEventSub(queued)
		}
	}
}

func (s *Server) runEventSubInboxDrainer(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	drain := func() {
		for _, record := range s.deliveries.PendingEventSub(512, time.Now().UTC()) {
			_ = s.scheduleEventSub(record)
		}
	}
	drain()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drain()
		}
	}
}

func (s *Server) scheduleEventSub(record EventSubInboxRecord) bool {
	if record.MessageID == "" || record.Status != eventSubInboxStatusPending || !s.reserveEventSub(record.MessageID) {
		return false
	}
	queued := queuedEventSub{MessageID: record.MessageID, Envelope: record.Envelope}
	select {
	case s.eventQueue <- queued:
		return true
	default:
		s.releaseEventSub(record.MessageID)
		return false
	}
}

func (s *Server) handleQueuedEventSub(queued queuedEventSub) {
	var processErr error
	defer func() {
		if recovered := recover(); recovered != nil {
			processErr = fmt.Errorf("panic: %v", recovered)
			s.log.Error("EventSub worker panic", "event_id", queued.MessageID, "value", recovered)
		}
		s.releaseEventSub(queued.MessageID)
		if processErr != nil {
			if err := s.deliveries.MarkEventSubFailed(queued.MessageID, processErr, time.Now().UTC()); err != nil {
				s.log.Error("EventSub retry state was not saved", "event_id", queued.MessageID, "error", err)
			}
			s.auditRecord(AuditRecord{
				Action:  "eventsub.process",
				Status:  "failed",
				EventID: queued.MessageID,
				Detail:  processErr.Error(),
			})
			return
		}
		if err := s.deliveries.CompleteEventSub(queued.MessageID, time.Now().UTC()); err != nil {
			s.log.Error("EventSub completion was not saved", "event_id", queued.MessageID, "error", err)
			s.auditRecord(AuditRecord{Action: "eventsub.process", Status: "completion_failed", EventID: queued.MessageID, Detail: err.Error()})
		}
	}()
	processErr = s.processEventSubNotification(queued.MessageID, queued.Envelope)
}

func (s *Server) processEventSubNotification(messageID string, envelope eventSubEnvelope) error {
	var (
		channelID        string
		channelTitle     string
		channelCategory  string
		saveChannelState bool
		unlockChannel    func()
	)
	if envelope.Subscription.Type == "channel.update" {
		channelID = stringValue(envelope.Event, "broadcaster_user_id")
		channelTitle = stringValue(envelope.Event, "title")
		channelCategory = stringValue(envelope.Event, "category_name")
		lock := s.channelStateLock(channelID)
		lock.Lock()
		unlockChannel = lock.Unlock
		defer unlockChannel()

		titleChanged, gameChanged, initialized, err := s.deliveries.ChannelStateChanges(
			channelID,
			channelTitle,
			channelCategory,
		)
		if err != nil {
			return fmt.Errorf("inspect channel notification state: %w", err)
		}
		if initialized {
			if err := s.deliveries.SaveChannelState(channelID, channelTitle, channelCategory, time.Now().UTC()); err != nil {
				return fmt.Errorf("initialize channel notification state: %w", err)
			}
			s.auditRecord(AuditRecord{
				Action:    "eventsub.process",
				Status:    "state_initialized",
				EventID:   messageID,
				ChannelID: channelID,
				Detail:    envelope.Subscription.Type,
			})
			return nil
		}
		if !titleChanged && !gameChanged {
			s.auditRecord(AuditRecord{
				Action:    "eventsub.process",
				Status:    "unchanged",
				EventID:   messageID,
				ChannelID: channelID,
				Detail:    envelope.Subscription.Type,
			})
			return nil
		}
		envelope.Event["_ferventio_title_changed"] = titleChanged
		envelope.Event["_ferventio_game_changed"] = gameChanged
		saveChannelState = true
	}

	matched := 0
	var deliveryErrors []error
	for _, registration := range s.store.List() {
		notification, ok := eventNotificationForRegistration(
			messageID,
			envelope.Subscription.Type,
			envelope.Event,
			registration,
		)
		if !ok {
			continue
		}
		matched++
		if err := s.deliverToRegistration(routingContext(), registration, notification); err != nil {
			deliveryErrors = append(deliveryErrors, fmt.Errorf("%s: %w", registration.InstallationID, err))
			s.log.Warn(
				"EventSub push delivery failed",
				"event_id", messageID,
				"installation", registration.InstallationID,
				"error", err,
			)
		}
	}
	if len(deliveryErrors) > 0 {
		s.auditRecord(AuditRecord{
			Action:  "eventsub.process",
			Status:  "retry_pending",
			EventID: messageID,
			Detail:  fmt.Sprintf("type=%s matched=%d failed=%d", envelope.Subscription.Type, matched, len(deliveryErrors)),
		})
		return errors.Join(deliveryErrors...)
	}
	if saveChannelState {
		if err := s.deliveries.SaveChannelState(channelID, channelTitle, channelCategory, time.Now().UTC()); err != nil {
			return fmt.Errorf("save channel notification state: %w", err)
		}
	}
	s.auditRecord(AuditRecord{
		Action:  "eventsub.process",
		Status:  "processed",
		EventID: messageID,
		Detail:  fmt.Sprintf("type=%s matched=%d", envelope.Subscription.Type, matched),
	})
	return nil
}

func (s *Server) channelStateLock(channelID string) *sync.Mutex {
	value, _ := s.channelStateLocks.LoadOrStore(channelID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func eventNotificationForRegistration(
	eventID string,
	subscriptionType string,
	event map[string]any,
	registration Registration,
) (Notification, bool) {
	channelID := firstNonBlank(
		stringValue(event, "broadcaster_user_id"),
		stringValue(event, "to_broadcaster_user_id"),
	)
	if channelID != "" && !containsString(registration.ChannelIDs, channelID) {
		return Notification{}, false
	}
	channelLogin := firstNonBlank(
		stringValue(event, "broadcaster_user_login"),
		stringValue(event, "to_broadcaster_user_login"),
	)
	channelName := firstNonBlank(
		stringValue(event, "broadcaster_user_name"),
		stringValue(event, "to_broadcaster_user_name"),
		channelLogin,
	)
	base := Notification{
		EventID:              eventID,
		ChannelID:            channelID,
		ChannelLogin:         channelLogin,
		CreatedAtEpochMillis: time.Now().UTC().UnixMilli(),
	}

	switch subscriptionType {
	case "channel.chat.message":
		return chatMessageNotification(base, event, registration)
	case "automod.message.hold":
		if !ruleEnabled(registration, "automod_hold") {
			return Notification{}, false
		}
		base.Type = "automod_hold"
		base.Title = "AutoMod: " + firstNonBlank(stringValue(event, "user_name"), stringValue(event, "user_login"))
		base.Body = nestedString(event, "message", "text")
		base.MessageID = stringValue(event, "message_id")
		base.Destination = "moderation"
		return base, base.Body != ""
	case "channel.ban":
		typeName := "ban"
		if !boolValue(event, "is_permanent") || stringValue(event, "ends_at") != "" {
			typeName = "timeout"
		}
		if !ruleEnabled(registration, typeName) {
			return Notification{}, false
		}
		base.Type = typeName
		base.Title = map[bool]string{true: "Блокировка", false: "Timeout"}[typeName == "ban"] + " в #" + channelName
		base.Body = firstNonBlank(stringValue(event, "user_name"), stringValue(event, "user_login"))
		base.Destination = "moderation"
		return base, true
	case "channel.moderate":
		if !ruleEnabled(registration, "moderation_action") {
			return Notification{}, false
		}
		base.Type = "moderation_action"
		base.Title = "Действие модерации в #" + channelName
		base.Body = firstNonBlank(stringValue(event, "action"), "Изменение модерации")
		base.Destination = "moderation"
		return base, true
	case "stream.online":
		if !ruleEnabled(registration, "stream_online") {
			return Notification{}, false
		}
		base.Type = "stream_online"
		base.Title = channelName + " начал трансляцию"
		base.Body = "Канал сейчас онлайн"
		return base, true
	case "channel.update":
		titleChanged := boolValue(event, "_ferventio_title_changed")
		gameChanged := boolValue(event, "_ferventio_game_changed")
		canTitle := titleChanged && ruleEnabled(registration, "title_change")
		canGame := gameChanged && ruleEnabled(registration, "game_change")
		if !canTitle && !canGame {
			return Notification{}, false
		}
		title := stringValue(event, "title")
		category := stringValue(event, "category_name")
		switch {
		case canTitle && canGame:
			base.Type = "title_change"
			base.Title = "Title и game изменены: " + channelName
			base.Body = strings.TrimSpace(strings.Join(nonBlank([]string{title, category}), " · "))
		case canTitle:
			base.Type = "title_change"
			base.Title = "Новый title: " + channelName
			base.Body = title
		case canGame:
			base.Type = "game_change"
			base.Title = "Новая категория: " + channelName
			base.Body = category
		}
		return base, base.Body != ""
	case "channel.raid":
		if !ruleEnabled(registration, "raid") {
			return Notification{}, false
		}
		base.Type = "raid"
		base.Title = "Raid на " + channelName
		base.Body = fmt.Sprintf(
			"%s · зрителей: %s",
			firstNonBlank(stringValue(event, "from_broadcaster_user_name"), stringValue(event, "from_broadcaster_user_login")),
			numberString(event["viewers"]),
		)
		return base, true
	case "channel.channel_points_custom_reward_redemption.add":
		if !ruleEnabled(registration, "reward") {
			return Notification{}, false
		}
		base.Type = "reward"
		base.Title = "Награда в #" + channelName
		base.Body = firstNonBlank(
			nestedString(event, "reward", "title"),
			stringValue(event, "user_input"),
			"Использована награда канала",
		)
		return base, true
	case "channel.subscribe", "channel.subscription.message", "channel.subscription.gift", "channel.chat.notification":
		if !ruleEnabled(registration, "subscription") {
			return Notification{}, false
		}
		base.Type = "subscription"
		base.Title = "Подписка в #" + channelName
		base.Body = firstNonBlank(
			stringValue(event, "user_name"),
			stringValue(event, "user_login"),
			nestedString(event, "message", "text"),
			"Новое событие подписки",
		)
		return base, true
	default:
		return Notification{}, false
	}
}

func chatMessageNotification(base Notification, event map[string]any, registration Registration) (Notification, bool) {
	text := nestedString(event, "message", "text")
	if text == "" {
		return Notification{}, false
	}
	authorID := stringValue(event, "chatter_user_id")
	authorLogin := stringValue(event, "chatter_user_login")
	authorName := firstNonBlank(stringValue(event, "chatter_user_name"), authorLogin)
	base.ActorID = authorID
	base.ActorLogin = authorLogin
	base.ActorDisplayName = authorName
	if registration.UserID != "" && authorID == registration.UserID {
		return Notification{}, false
	}
	base.MessageID = stringValue(event, "message_id")
	base.Body = text
	parentUserID := nestedString(event, "reply", "parent_user_id")
	parentUserLogin := nestedString(event, "reply", "parent_user_login")
	switch {
	case ruleEnabled(registration, "reply") && registration.UserID != "" && parentUserID == registration.UserID:
		base.Type = "reply"
		base.Title = "Ответ от " + authorName
		base.Destination = "mentions"
		return base, true
	case ruleEnabled(registration, "reply") && registration.UserLogin != "" && strings.EqualFold(parentUserLogin, registration.UserLogin):
		base.Type = "reply"
		base.Title = "Ответ от " + authorName
		base.Destination = "mentions"
		return base, true
	case ruleEnabled(registration, "mention") && containsMention(text, registration.UserLogin):
		base.Type = "mention"
		base.Title = "Упоминание от " + authorName
		base.Destination = "mentions"
		return base, true
	case ruleEnabled(registration, "selected_user") && containsFold(registration.SelectedUserLogins, authorLogin):
		base.Type = "selected_user"
		base.Title = "Сообщение от " + authorName
		base.Destination = "mentions"
		return base, true
	case ruleEnabled(registration, "highlight") && containsAnyPhrase(text, registration.HighlightPhrases):
		base.Type = "highlight"
		base.Title = "Highlight: " + authorName
		base.Destination = "mentions"
		return base, true
	default:
		return Notification{}, false
	}
}

func ruleEnabled(registration Registration, rule string) bool {
	return len(registration.NotificationRules) == 0 || containsString(registration.NotificationRules, rule)
}

func containsMention(text, login string) bool {
	login = strings.TrimSpace(login)
	if login == "" {
		return false
	}
	lowerText := strings.ToLower(text)
	needle := "@" + strings.ToLower(login)
	for offset := 0; offset < len(lowerText); {
		index := strings.Index(lowerText[offset:], needle)
		if index < 0 {
			return false
		}
		end := offset + index + len(needle)
		if end == len(lowerText) || !isTwitchLoginCharacter(lowerText[end]) {
			return true
		}
		offset = end
	}
	return false
}

func isTwitchLoginCharacter(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func containsAnyPhrase(text string, phrases []string) bool {
	lower := strings.ToLower(text)
	for _, phrase := range phrases {
		if phrase = strings.TrimSpace(phrase); phrase != "" && strings.Contains(lower, strings.ToLower(phrase)) {
			return true
		}
	}
	return false
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringValue(value map[string]any, key string) string {
	if raw, ok := value[key].(string); ok {
		return strings.TrimSpace(raw)
	}
	return ""
}

func nestedString(value map[string]any, outer, inner string) string {
	nested, ok := value[outer].(map[string]any)
	if !ok {
		return ""
	}
	return stringValue(nested, inner)
}

func boolValue(value map[string]any, key string) bool {
	result, _ := value[key].(bool)
	return result
}

func numberString(value any) string {
	switch current := value.(type) {
	case float64:
		return fmt.Sprintf("%.0f", current)
	case json.Number:
		return current.String()
	case string:
		return current
	default:
		return "0"
	}
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func nonBlank(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func routingContext() context.Context { return context.Background() }
