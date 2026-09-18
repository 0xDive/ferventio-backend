package application

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type retryTestSender struct {
	mu       sync.Mutex
	failures int
	calls    int
}

func (s *retryTestSender) Send(context.Context, Registration, Notification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failures > 0 {
		s.failures--
		return errors.New("temporary sender failure")
	}
	return nil
}

func TestDeliveryQueueRetriesNonSocketTransport(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{InstallationID: "device-1", DeviceSecret: "secret", Provider: "fcm", Platform: "android"}
	if err := store.Upsert(registration); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Authenticate("device-1", "secret")
	if err != nil {
		t.Fatal(err)
	}
	deliveries := newMemoryDeliveryStore()
	sender := &retryTestSender{failures: 1}
	server := NewServerWithStores(Config{}, store, nil, sender, newDiscardLogger(), deliveries, newMemoryAuditStore())
	if err := server.deliverToRegistration(context.Background(), stored, Notification{
		EventID: "event-1", Type: "mention", Title: "title", Body: "body",
	}); err != nil {
		t.Fatal(err)
	}
	records := deliveries.List(10)
	if len(records) != 1 || records[0].Status != deliveryStatusPending || records[0].AttemptCount != 1 {
		t.Fatalf("after failure = %#v", records)
	}

	time.Sleep(1100 * time.Millisecond)
	server.flushPending("device-1")

	records = deliveries.List(10)
	if len(records) != 1 || records[0].Status != deliveryStatusAcked {
		t.Fatalf("after retry = %#v", records)
	}
	if sender.calls != 2 {
		t.Fatalf("sender calls = %d, want 2", sender.calls)
	}
}

func TestFlushPendingStopsAfterFirstTransportFailure(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		InstallationID: "device-failure-isolation",
		DeviceSecret:   "secret",
		Provider:       "fcm",
		Platform:       "android",
	}
	if err := store.Upsert(registration); err != nil {
		t.Fatal(err)
	}
	deliveries := newMemoryDeliveryStore()
	now := time.Now().UTC()
	for index, eventID := range []string{"event-1", "event-2"} {
		if _, _, err := deliveries.Enqueue(DeliveryRecord{
			ID:             "delivery-" + eventID,
			EventID:        eventID,
			InstallationID: registration.InstallationID,
			Notification: Notification{
				EventID: eventID,
				Type:    "mention",
				Title:   "title",
				Body:    "body",
			},
			Status:      deliveryStatusPending,
			AvailableAt: now,
			ExpiresAt:   now.Add(time.Hour),
			CreatedAt:   now.Add(time.Duration(index) * time.Millisecond),
		}); err != nil {
			t.Fatal(err)
		}
	}
	sender := &retryTestSender{failures: 2}
	server := NewServerWithStores(
		Config{},
		store,
		nil,
		sender,
		newDiscardLogger(),
		deliveries,
		newMemoryAuditStore(),
	)
	server.flushPending(registration.InstallationID)
	if sender.calls != 1 {
		t.Fatalf("sender calls = %d, want 1 after first transport failure", sender.calls)
	}
	records := deliveries.List(10)
	attempted := 0
	for _, record := range records {
		if record.AttemptCount > 0 {
			attempted++
		}
	}
	if attempted != 1 {
		t.Fatalf("attempted deliveries = %d, want 1", attempted)
	}
}
