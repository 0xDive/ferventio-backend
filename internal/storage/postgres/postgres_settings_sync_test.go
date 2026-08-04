package postgres

import "testing"

func TestSettingsSyncLockKeyIsStableAndNamespaced(t *testing.T) {
	first := settingsSyncLockKey("user-123")
	if first != settingsSyncLockKey("user-123") {
		t.Fatal("settings sync advisory lock key is not stable")
	}
	if first == settingsSyncLockKey("user-124") {
		t.Fatal("different users unexpectedly share the same advisory lock key")
	}
	if first == 0 {
		t.Fatal("settings sync advisory lock key must not be zero for the fixture")
	}
}
