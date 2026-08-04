package memory

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func TestSettingsSyncStoreConflictHistoryAndRestore(t *testing.T) {
	store, err := OpenSettingsSyncStore(filepath.Join(t.TempDir(), "sync.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Put("user", "device-a", 0, false, "0.9.7", "hash-a", json.RawMessage(`{"value":1}`))
	if err != nil || first.Revision != 1 {
		t.Fatalf("first put: snapshot=%+v err=%v", first, err)
	}
	if _, err := store.Put("user", "device-b", 0, false, "0.9.7", "hash-b", json.RawMessage(`{"value":2}`)); !errors.Is(err, ErrSettingsSyncConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	second, err := store.Put("user", "device-a", 1, false, "0.9.7", "hash-b", json.RawMessage(`{"value":2}`))
	if err != nil || second.Revision != 2 {
		t.Fatalf("second put: snapshot=%+v err=%v", second, err)
	}
	if history := store.History("user"); len(history) != 2 || history[0].Revision != 2 || history[1].Revision != 1 {
		t.Fatalf("unexpected history: %+v", history)
	}
	restored, err := store.Restore("user", "device-b", 1)
	if err != nil || restored.Revision != 3 || restored.ContentHash != "hash-a" {
		t.Fatalf("restore: snapshot=%+v err=%v", restored, err)
	}
}
