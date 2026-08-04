package memory

import (
	"sort"
	"sync"
	"time"
)

type AuditStore struct {
	mu    sync.RWMutex
	state auditDiskState
}

func newMemoryAuditStore() *AuditStore {
	return &AuditStore{state: auditDiskState{Version: 1, Records: []AuditRecord{}}}
}

func OpenAuditStore(_ string) (*AuditStore, error) {
	return newMemoryAuditStore(), nil
}
func (s *AuditStore) Append(record AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.ID == "" {
		value, err := randomToken("audit_", 12)
		if err != nil {
			return err
		}
		record.ID = value
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}
	if len(record.Detail) > 1_000 {
		record.Detail = record.Detail[:1_000]
	}
	s.state.Records = append(s.state.Records, record)
	s.trimLocked()
	return s.persistLocked()
}

func (s *AuditStore) List(limit int) []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1_000 {
		limit = 200
	}
	start := len(s.state.Records) - limit
	if start < 0 {
		start = 0
	}
	result := append([]AuditRecord(nil), s.state.Records[start:]...)
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp.After(result[j].Timestamp) })
	return result
}

func (s *AuditStore) trimLocked() {
	if len(s.state.Records) <= maxAuditRecords {
		return
	}
	start := len(s.state.Records) - maxAuditRecords
	s.state.Records = append([]AuditRecord(nil), s.state.Records[start:]...)
}

func (s *AuditStore) persistLocked() error {
	return nil
}

// ListAudit implements AuditRepository without colliding with DeliveryRepository.List
// on the shared PostgreSQL implementation.
func (s *AuditStore) ListAudit(limit int) []AuditRecord {
	return s.List(limit)
}

// NewAuditStore creates an isolated in-memory audit repository.
func NewAuditStore() *AuditStore { return newMemoryAuditStore() }
