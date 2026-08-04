package memory

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAuditStoreBoundsList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	store, err := OpenAuditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(AuditRecord{Action: "one", Timestamp: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(AuditRecord{Action: "two", Timestamp: time.Unix(2, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	records := store.List(1)
	if len(records) != 1 || records[0].Action != "two" {
		t.Fatalf("audit records = %#v", records)
	}
}
