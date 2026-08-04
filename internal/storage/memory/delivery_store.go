package memory

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

type DeliveryStore struct {
	mu    sync.RWMutex
	state deliveryDiskState
}

func newMemoryDeliveryStore() *DeliveryStore {
	return &DeliveryStore{
		state: deliveryDiskState{
			Version:       1,
			Records:       map[string]DeliveryRecord{},
			Seen:          map[string]time.Time{},
			EventSubInbox: map[string]EventSubInboxRecord{},
			ChannelStates: map[string]ChannelNotificationState{},
		},
	}
}

func OpenDeliveryStore(_ string) (*DeliveryStore, error) {
	return newMemoryDeliveryStore(), nil
}
func (s *DeliveryStore) Enqueue(record DeliveryRecord) (DeliveryRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.cleanupLocked(now)
	for _, existing := range s.state.Records {
		if existing.InstallationID == record.InstallationID && existing.EventID == record.EventID {
			return existing, false, nil
		}
	}
	if record.ID == "" || record.EventID == "" || record.InstallationID == "" {
		return DeliveryRecord{}, false, errors.New("delivery id, event id, and installation id are required")
	}
	if record.Status == "" {
		record.Status = deliveryStatusPending
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.AvailableAt.IsZero() {
		record.AvailableAt = now
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = now.Add(24 * time.Hour)
	}
	if len(s.state.Records) >= maxDeliveryRecords {
		s.trimCompletedDeliveriesLocked(maxDeliveryRecords - 1)
		if len(s.state.Records) >= maxDeliveryRecords {
			return DeliveryRecord{}, false, errors.New("delivery queue is full")
		}
	}
	s.state.Records[record.ID] = record
	return record, true, s.persistLocked()
}

func (s *DeliveryStore) List(limit int) []DeliveryRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1_000 {
		limit = 200
	}
	records := make([]DeliveryRecord, 0, len(s.state.Records))
	for _, record := range s.state.Records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].ID > records[j].ID
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records
}

// ListDeliveries implements DeliveryRepository while retaining List for focused
// in-memory store tests.
func (s *DeliveryStore) ListDeliveries(limit int) []DeliveryRecord {
	return s.List(limit)
}

func (s *DeliveryStore) PendingForInstallation(installationID string, limit int, now time.Time) []DeliveryRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	result := make([]DeliveryRecord, 0, limit)
	for _, record := range s.state.Records {
		if record.InstallationID != installationID || record.Status == deliveryStatusAcked || record.Status == deliveryStatusDead {
			continue
		}
		if now.Before(record.AvailableAt) || !now.Before(record.ExpiresAt) {
			continue
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (s *DeliveryStore) MarkSent(id string, sentAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.Records[id]
	if !ok {
		return ErrNotFound
	}
	record.Status = deliveryStatusSent
	record.AttemptCount++
	record.SentAt = sentAt
	record.LastError = ""
	record.AvailableAt = sentAt.Add(retryDelay(record.AttemptCount))
	s.state.Records[id] = record
	return s.persistLocked()
}

func (s *DeliveryStore) MarkFailed(id string, failure error, failedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.Records[id]
	if !ok {
		return ErrNotFound
	}
	record.AttemptCount++
	record.LastError = failure.Error()
	if record.AttemptCount >= 8 || !failedAt.Before(record.ExpiresAt) {
		record.Status = deliveryStatusDead
	} else {
		record.Status = deliveryStatusPending
		record.AvailableAt = failedAt.Add(retryDelay(record.AttemptCount))
	}
	s.state.Records[id] = record
	return s.persistLocked()
}

func (s *DeliveryStore) AckThrough(installationID, eventID string, ackedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target time.Time
	for _, record := range s.state.Records {
		if record.InstallationID == installationID && record.EventID == eventID {
			target = record.CreatedAt
			break
		}
	}
	if target.IsZero() {
		return ErrNotFound
	}
	for id, record := range s.state.Records {
		if record.InstallationID != installationID || record.CreatedAt.After(target) {
			continue
		}
		record.Status = deliveryStatusAcked
		record.AckedAt = ackedAt
		record.LastError = ""
		s.state.Records[id] = record
	}
	return s.persistLocked()
}

func (s *DeliveryStore) Ack(installationID, eventID string, ackedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for id, record := range s.state.Records {
		if record.InstallationID == installationID && record.EventID == eventID {
			record.Status = deliveryStatusAcked
			record.AckedAt = ackedAt
			record.LastError = ""
			s.state.Records[id] = record
			found = true
		}
	}
	if !found {
		return ErrNotFound
	}
	return s.persistLocked()
}

// DeleteForInstallation removes queued notifications after a device is revoked.
func (s *DeliveryStore) DeleteForInstallation(installationID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, record := range s.state.Records {
		if record.InstallationID == installationID {
			delete(s.state.Records, id)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, s.persistLocked()
}

func (s *DeliveryStore) EnqueueEventSub(
	messageID string,
	envelope eventSubEnvelope,
	now time.Time,
) (EventSubInboxRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return EventSubInboxRecord{}, false, errors.New("EventSub message id is required")
	}
	s.cleanupSeenLocked(now, 24*time.Hour)
	if _, seen := s.state.Seen[messageID]; seen {
		return EventSubInboxRecord{}, false, nil
	}
	if existing, queued := s.state.EventSubInbox[messageID]; queued {
		return existing, false, nil
	}
	if len(s.state.EventSubInbox) >= maxEventSubInboxRecords {
		s.trimDeadEventSubInboxLocked(maxEventSubInboxRecords - 1)
		if len(s.state.EventSubInbox) >= maxEventSubInboxRecords {
			return EventSubInboxRecord{}, false, errors.New("EventSub inbox is full")
		}
	}
	record := EventSubInboxRecord{
		MessageID:   messageID,
		Envelope:    envelope,
		Status:      eventSubInboxStatusPending,
		AvailableAt: now,
		ExpiresAt:   now.Add(24 * time.Hour),
		ReceivedAt:  now,
	}
	s.state.EventSubInbox[messageID] = record
	if err := s.persistLocked(); err != nil {
		delete(s.state.EventSubInbox, messageID)
		return EventSubInboxRecord{}, false, err
	}
	return record, true, nil
}

func (s *DeliveryStore) PendingEventSub(limit int, now time.Time) []EventSubInboxRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1_000 {
		limit = 200
	}
	result := make([]EventSubInboxRecord, 0, limit)
	for _, record := range s.state.EventSubInbox {
		if record.Status != eventSubInboxStatusPending || now.Before(record.AvailableAt) || !now.Before(record.ExpiresAt) {
			continue
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ReceivedAt.Equal(result[j].ReceivedAt) {
			return result[i].MessageID < result[j].MessageID
		}
		return result[i].ReceivedAt.Before(result[j].ReceivedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (s *DeliveryStore) ListEventSubInbox(limit int) []EventSubInboxRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1_000 {
		limit = 200
	}
	result := make([]EventSubInboxRecord, 0, len(s.state.EventSubInbox))
	for _, record := range s.state.EventSubInbox {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ReceivedAt.Equal(result[j].ReceivedAt) {
			return result[i].MessageID > result[j].MessageID
		}
		return result[i].ReceivedAt.After(result[j].ReceivedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (s *DeliveryStore) CompleteEventSub(messageID string, completedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.state.EventSubInbox[messageID]
	if !exists {
		if _, seen := s.state.Seen[messageID]; seen {
			return nil
		}
		return ErrNotFound
	}
	delete(s.state.EventSubInbox, messageID)
	previousSeen, hadSeen := s.state.Seen[messageID]
	s.addSeenEventSubLocked(messageID, completedAt)
	if err := s.persistLocked(); err != nil {
		s.state.EventSubInbox[messageID] = record
		if hadSeen {
			s.state.Seen[messageID] = previousSeen
		} else {
			delete(s.state.Seen, messageID)
		}
		return err
	}
	return nil
}

func (s *DeliveryStore) MarkEventSubFailed(messageID string, failure error, failedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.state.EventSubInbox[messageID]
	if !exists {
		return ErrNotFound
	}
	record.AttemptCount++
	record.LastAttemptAt = failedAt
	if failure != nil {
		record.LastError = failure.Error()
	}
	if record.AttemptCount >= 8 || !failedAt.Before(record.ExpiresAt) {
		record.Status = eventSubInboxStatusDead
	} else {
		record.Status = eventSubInboxStatusPending
		record.AvailableAt = failedAt.Add(retryDelay(record.AttemptCount))
	}
	s.state.EventSubInbox[messageID] = record
	return s.persistLocked()
}

func (s *DeliveryStore) RetryEventSub(messageID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.state.EventSubInbox[messageID]
	if !exists {
		return ErrNotFound
	}
	record.Status = eventSubInboxStatusPending
	record.AttemptCount = 0
	record.AvailableAt = now
	record.ExpiresAt = now.Add(24 * time.Hour)
	record.LastError = ""
	s.state.EventSubInbox[messageID] = record
	return s.persistLocked()
}

func (s *DeliveryStore) HasSeenEventSub(messageID string, now time.Time, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupSeenLocked(now, ttl)
	_, exists := s.state.Seen[messageID]
	return exists
}

func (s *DeliveryStore) SeenEventSub(messageID string, now time.Time, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupSeenLocked(now, ttl)
	if _, exists := s.state.Seen[messageID]; exists {
		return true, nil
	}
	s.addSeenEventSubLocked(messageID, now)
	if err := s.persistLocked(); err != nil {
		delete(s.state.Seen, messageID)
		return false, err
	}
	return false, nil
}

func (s *DeliveryStore) ForgetEventSub(messageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Seen, messageID)
	return s.persistLocked()
}

func (s *DeliveryStore) ChannelStateChanges(
	channelID, title, categoryName string,
) (titleChanged, gameChanged, initialized bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if channelID == "" {
		return false, false, false, errors.New("channel id is required")
	}
	previous, exists := s.state.ChannelStates[channelID]
	if !exists {
		return false, false, true, nil
	}
	return previous.Title != title, previous.CategoryName != categoryName, false, nil
}

func (s *DeliveryStore) SaveChannelState(
	channelID, title, categoryName string,
	now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if channelID == "" {
		return errors.New("channel id is required")
	}
	previous, exists := s.state.ChannelStates[channelID]
	s.state.ChannelStates[channelID] = ChannelNotificationState{
		Title:        title,
		CategoryName: categoryName,
		UpdatedAt:    now,
	}
	if err := s.persistLocked(); err != nil {
		if exists {
			s.state.ChannelStates[channelID] = previous
		} else {
			delete(s.state.ChannelStates, channelID)
		}
		return err
	}
	return nil
}

func (s *DeliveryStore) UpdateChannelState(
	channelID, title, categoryName string,
	now time.Time,
) (titleChanged, gameChanged, initialized bool, err error) {
	titleChanged, gameChanged, initialized, err = s.ChannelStateChanges(channelID, title, categoryName)
	if err != nil {
		return false, false, false, err
	}
	if err = s.SaveChannelState(channelID, title, categoryName, now); err != nil {
		return false, false, false, err
	}
	return titleChanged, gameChanged, initialized, nil
}

func (s *DeliveryStore) Cleanup(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	return s.persistLocked()
}

func (s *DeliveryStore) cleanupLocked(now time.Time) {
	for id, record := range s.state.Records {
		if !now.Before(record.ExpiresAt) && record.Status != deliveryStatusAcked {
			record.Status = deliveryStatusDead
			s.state.Records[id] = record
		}
		if record.Status == deliveryStatusAcked && !record.AckedAt.IsZero() && now.Sub(record.AckedAt) > 7*24*time.Hour {
			delete(s.state.Records, id)
		}
		if record.Status == deliveryStatusDead && now.Sub(record.CreatedAt) > 7*24*time.Hour {
			delete(s.state.Records, id)
		}
	}
	for messageID, record := range s.state.EventSubInbox {
		if !now.Before(record.ExpiresAt) && record.Status != eventSubInboxStatusDead {
			record.Status = eventSubInboxStatusDead
			record.LastError = "EventSub inbox item expired before processing"
			s.state.EventSubInbox[messageID] = record
		}
		if record.Status == eventSubInboxStatusDead && now.Sub(record.ReceivedAt) > 7*24*time.Hour {
			delete(s.state.EventSubInbox, messageID)
		}
	}
	s.cleanupSeenLocked(now, 24*time.Hour)
	if len(s.state.Records) > maxDeliveryRecords {
		s.trimCompletedDeliveriesLocked(maxDeliveryRecords)
	}
	if len(s.state.EventSubInbox) > maxEventSubInboxRecords {
		s.trimDeadEventSubInboxLocked(maxEventSubInboxRecords)
	}
}

func (s *DeliveryStore) addSeenEventSubLocked(messageID string, now time.Time) {
	if len(s.state.Seen) >= maxSeenEventRecords {
		oldestKey := ""
		var oldest time.Time
		for key, timestamp := range s.state.Seen {
			if oldestKey == "" || timestamp.Before(oldest) {
				oldestKey, oldest = key, timestamp
			}
		}
		delete(s.state.Seen, oldestKey)
	}
	s.state.Seen[messageID] = now
}

func (s *DeliveryStore) trimDeadEventSubInboxLocked(limit int) {
	if len(s.state.EventSubInbox) <= limit {
		return
	}
	records := make([]EventSubInboxRecord, 0, len(s.state.EventSubInbox))
	for _, record := range s.state.EventSubInbox {
		if record.Status == eventSubInboxStatusDead {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ReceivedAt.Before(records[j].ReceivedAt) })
	for _, record := range records {
		if len(s.state.EventSubInbox) <= limit {
			break
		}
		delete(s.state.EventSubInbox, record.MessageID)
	}
}

func (s *DeliveryStore) cleanupSeenLocked(now time.Time, ttl time.Duration) {
	for key, timestamp := range s.state.Seen {
		if now.Sub(timestamp) > ttl {
			delete(s.state.Seen, key)
		}
	}
}

func (s *DeliveryStore) trimCompletedDeliveriesLocked(limit int) {
	if len(s.state.Records) <= limit {
		return
	}
	records := make([]DeliveryRecord, 0, len(s.state.Records))
	for _, record := range s.state.Records {
		if record.Status == deliveryStatusAcked || record.Status == deliveryStatusDead {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.Before(records[j].CreatedAt) })
	for _, record := range records {
		if len(s.state.Records) <= limit {
			break
		}
		delete(s.state.Records, record.ID)
	}
}

func (s *DeliveryStore) persistLocked() error {
	return nil
}
func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	seconds := 1 << minInt(attempt-1, 6)
	return time.Duration(seconds) * time.Second
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// NewDeliveryStore creates an isolated in-memory delivery repository.
func NewDeliveryStore() *DeliveryStore { return newMemoryDeliveryStore() }
