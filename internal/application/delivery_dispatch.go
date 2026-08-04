package application

import (
	"context"
	"fmt"
	"sync"
	"time"
)

func (s *Server) deliverToRegistration(
	_ context.Context,
	registration Registration,
	notification Notification,
) error {
	now := time.Now().UTC()
	if notification.EventID == "" {
		eventID, err := randomToken("pe_", 18)
		if err != nil {
			return fmt.Errorf("create event id: %w", err)
		}
		notification.EventID = eventID
	}
	if notification.Type == "" {
		notification.Type = "generic"
	}
	if notification.CreatedAtEpochMillis == 0 {
		notification.CreatedAtEpochMillis = now.UnixMilli()
	}
	deliveryID, err := randomToken("pd_", 18)
	if err != nil {
		return fmt.Errorf("create delivery id: %w", err)
	}
	record, created, err := s.deliveries.Enqueue(DeliveryRecord{
		ID:             deliveryID,
		EventID:        notification.EventID,
		InstallationID: registration.InstallationID,
		Notification:   notification,
		Status:         deliveryStatusPending,
		AvailableAt:    now,
		ExpiresAt:      now.Add(notificationTTL(notification.Type)),
		CreatedAt:      now,
	})
	if err != nil {
		return fmt.Errorf("enqueue notification: %w", err)
	}
	if created {
		s.auditRecord(AuditRecord{
			Action:         "push.delivery.enqueue",
			Status:         "pending",
			InstallationID: registration.InstallationID,
			UserID:         registration.UserID,
			ChannelID:      notification.ChannelID,
			EventID:        notification.EventID,
			Detail:         notification.Type,
		})
	} else {
		// A retried EventSub item may reach the same installation again after the
		// durable delivery was already written. Keep the existing record and only
		// trigger another flush instead of creating a duplicate notification.
		notification = record.Notification
	}
	s.flushPending(registration.InstallationID)
	return nil
}

func (s *Server) installationFlushLock(installationID string) *sync.Mutex {
	value, _ := s.flushLocks.LoadOrStore(installationID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func notificationTTL(eventType string) time.Duration {
	switch eventType {
	case "title_change", "game_change":
		return 30 * time.Minute
	case "stream_online":
		return 2 * time.Hour
	default:
		return 24 * time.Hour
	}
}
