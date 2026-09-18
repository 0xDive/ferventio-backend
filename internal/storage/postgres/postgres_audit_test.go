package postgres

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateAuditTextBoundsAndRepairsUTF8(t *testing.T) {
	value := strings.Repeat("аб", 300) + string([]byte{0xff})
	got := truncateAuditText(value, 32)
	if !utf8.ValidString(got) {
		t.Fatalf("truncateAuditText returned invalid UTF-8: %q", got)
	}
	if count := utf8.RuneCountInString(got); count != 32 {
		t.Fatalf("rune count=%d want 32", count)
	}
}
