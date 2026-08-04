package application

import "github.com/0xDive/ferventio-backend/internal/storage/memory"

type Store = memory.Store
type AuthStore = memory.AuthStore
type DeliveryStore = memory.DeliveryStore
type AuditStore = memory.AuditStore
type SettingsSyncStore = memory.SettingsSyncStore

func OpenStore(path string) (*Store, error) { return memory.OpenStore(path) }
func OpenAuthStore(path, encryptionKey string) (*AuthStore, error) {
	return memory.OpenAuthStore(path, encryptionKey)
}
func OpenDeliveryStore(path string) (*DeliveryStore, error) { return memory.OpenDeliveryStore(path) }
func OpenAuditStore(path string) (*AuditStore, error)       { return memory.OpenAuditStore(path) }
func OpenSettingsSyncStore(path string) (*SettingsSyncStore, error) {
	return memory.OpenSettingsSyncStore(path)
}

func newMemoryDeliveryStore() *DeliveryStore         { return memory.NewDeliveryStore() }
func newMemoryAuditStore() *AuditStore               { return memory.NewAuditStore() }
func newMemorySettingsSyncStore() *SettingsSyncStore { return memory.NewSettingsSyncStore() }
