package memory

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestDeliveryStoreQueueAckAndResume(t *testing.T) {
	store, err := OpenDeliveryStore(filepath.Join(t.TempDir(), "deliveries.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	first, created, err := store.Enqueue(DeliveryRecord{
		ID: "delivery-1", EventID: "event-1", InstallationID: "device-1",
		Notification: Notification{EventID: "event-1", Body: "one"},
		CreatedAt:    now, AvailableAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || !created || first.EventID != "event-1" {
		t.Fatalf("enqueue first = %#v, %v, %v", first, created, err)
	}
	_, created, err = store.Enqueue(DeliveryRecord{
		ID: "delivery-duplicate", EventID: "event-1", InstallationID: "device-1",
		Notification: Notification{EventID: "event-1", Body: "duplicate"},
		CreatedAt:    now, AvailableAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || created {
		t.Fatalf("duplicate created = %v, error = %v", created, err)
	}
	_, _, err = store.Enqueue(DeliveryRecord{
		ID: "delivery-2", EventID: "event-2", InstallationID: "device-1",
		Notification: Notification{EventID: "event-2", Body: "two"},
		CreatedAt:    now.Add(time.Second), AvailableAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.PendingForInstallation("device-1", 10, now); len(got) != 2 {
		t.Fatalf("pending count = %d, want 2", len(got))
	}
	if err := store.AckThrough("device-1", "event-1", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	pending := store.PendingForInstallation("device-1", 10, now.Add(3*time.Second))
	if len(pending) != 1 || pending[0].EventID != "event-2" {
		t.Fatalf("pending after resume = %#v", pending)
	}
	if err := store.Ack("device-1", "missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing ack = %v", err)
	}
}

func TestEventSubDedupCanBeReleased(t *testing.T) {
	store := newMemoryDeliveryStore()
	now := time.Now().UTC()
	seen, err := store.SeenEventSub("message-1", now, time.Hour)
	if err != nil || seen {
		t.Fatalf("first seen = %v, error = %v", seen, err)
	}
	seen, err = store.SeenEventSub("message-1", now, time.Hour)
	if err != nil || !seen {
		t.Fatalf("second seen = %v, error = %v", seen, err)
	}
	if err := store.ForgetEventSub("message-1"); err != nil {
		t.Fatal(err)
	}
	seen, err = store.SeenEventSub("message-1", now, time.Hour)
	if err != nil || seen {
		t.Fatalf("seen after release = %v, error = %v", seen, err)
	}
}

func TestChannelNotificationStateDetectsTitleAndGameChanges(t *testing.T) {
	store := newMemoryDeliveryStore()
	now := time.Now().UTC()
	titleChanged, gameChanged, initialized, err := store.UpdateChannelState("channel-1", "Title one", "Game one", now)
	if err != nil || !initialized || titleChanged || gameChanged {
		t.Fatalf("initial state = title:%v game:%v initialized:%v err:%v", titleChanged, gameChanged, initialized, err)
	}
	titleChanged, gameChanged, initialized, err = store.UpdateChannelState("channel-1", "Title two", "Game one", now.Add(time.Second))
	if err != nil || initialized || !titleChanged || gameChanged {
		t.Fatalf("title update = title:%v game:%v initialized:%v err:%v", titleChanged, gameChanged, initialized, err)
	}
	titleChanged, gameChanged, initialized, err = store.UpdateChannelState("channel-1", "Title two", "Game two", now.Add(2*time.Second))
	if err != nil || initialized || titleChanged || !gameChanged {
		t.Fatalf("game update = title:%v game:%v initialized:%v err:%v", titleChanged, gameChanged, initialized, err)
	}
}

func TestEventSubInboxPersistsRetriesAndCompletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store, err := OpenDeliveryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope := eventSubEnvelope{Event: map[string]any{"broadcaster_user_id": "channel-1"}}
	envelope.Subscription.Type = "stream.online"
	record, created, err := store.EnqueueEventSub("message-1", envelope, now)
	if err != nil || !created || record.Status != eventSubInboxStatusPending {
		t.Fatalf("enqueue inbox = %#v, created=%v, err=%v", record, created, err)
	}
	if _, created, err = store.EnqueueEventSub("message-1", envelope, now); err != nil || created {
		t.Fatalf("duplicate inbox created=%v, err=%v", created, err)
	}

	pending := store.PendingEventSub(10, now)
	if len(pending) != 1 || pending[0].MessageID != "message-1" {
		t.Fatalf("pending after enqueue = %#v", pending)
	}
	if err := store.MarkEventSubFailed("message-1", errors.New("temporary"), now); err != nil {
		t.Fatal(err)
	}
	if got := store.PendingEventSub(10, now); len(got) != 0 {
		t.Fatalf("failed item retried too early = %#v", got)
	}
	if got := store.PendingEventSub(10, now.Add(2*time.Second)); len(got) != 1 {
		t.Fatalf("failed item did not become available = %#v", got)
	}
	if err := store.CompleteEventSub("message-1", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := store.ListEventSubInbox(10); len(got) != 0 {
		t.Fatalf("completed inbox still present = %#v", got)
	}
	if !store.HasSeenEventSub("message-1", now.Add(3*time.Second), time.Hour) {
		t.Fatal("completed message was not marked as seen")
	}
}

func TestDeliveryStoreDoesNotDropPendingRecordsWhenFull(t *testing.T) {
	store := newMemoryDeliveryStore()
	now := time.Now().UTC()
	for index := 0; index < maxDeliveryRecords; index++ {
		id := fmt.Sprintf("delivery-%d", index)
		store.state.Records[id] = DeliveryRecord{
			ID: id, EventID: id, InstallationID: "device-1",
			Status: deliveryStatusPending, CreatedAt: now, AvailableAt: now, ExpiresAt: now.Add(time.Hour),
		}
	}
	_, created, err := store.Enqueue(DeliveryRecord{
		ID: "overflow", EventID: "overflow", InstallationID: "device-1",
		CreatedAt: now, AvailableAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err == nil || created {
		t.Fatalf("overflow created=%v, err=%v", created, err)
	}
	if len(store.state.Records) != maxDeliveryRecords {
		t.Fatalf("pending delivery was dropped: count=%d", len(store.state.Records))
	}
}

func TestEventSubInboxDoesNotDropPendingRecordsWhenFull(t *testing.T) {
	store := newMemoryDeliveryStore()
	now := time.Now().UTC()
	for index := 0; index < maxEventSubInboxRecords; index++ {
		id := fmt.Sprintf("message-%d", index)
		store.state.EventSubInbox[id] = EventSubInboxRecord{
			MessageID: id, Status: eventSubInboxStatusPending,
			AvailableAt: now, ExpiresAt: now.Add(time.Hour), ReceivedAt: now,
		}
	}
	envelope := eventSubEnvelope{}
	envelope.Subscription.Type = "stream.online"
	_, created, err := store.EnqueueEventSub("overflow", envelope, now)
	if err == nil || created {
		t.Fatalf("overflow created=%v, err=%v", created, err)
	}
	if len(store.state.EventSubInbox) != maxEventSubInboxRecords {
		t.Fatalf("pending EventSub item was dropped: count=%d", len(store.state.EventSubInbox))
	}
}
