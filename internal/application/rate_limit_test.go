package application

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRateLimiterTokenBucketAndRetryAfter(t *testing.T) {
	limiter := newRateLimiter(100, time.Hour)
	now := time.Unix(1_700_000_000, 0).UTC()
	limiter.now = func() time.Time { return now }
	policy := rateLimitPolicy{name: "test", perMinute: 60, burst: 2}

	for attempt := 0; attempt < 2; attempt++ {
		decision := limiter.take(policy, "client")
		if !decision.Allowed {
			t.Fatalf("attempt %d unexpectedly blocked: %+v", attempt, decision)
		}
	}
	blocked := limiter.take(policy, "client")
	if blocked.Allowed || blocked.RetryAfter != time.Second || !blocked.Audit {
		t.Fatalf("unexpected blocked decision: %+v", blocked)
	}
	if limiter.take(policy, "client").Audit {
		t.Fatal("repeated blocked request must not flood the audit log")
	}
	now = now.Add(time.Second)
	if decision := limiter.take(policy, "client"); !decision.Allowed {
		t.Fatalf("token was not refilled: %+v", decision)
	}
}

func TestRateLimiterBoundsKeyCardinality(t *testing.T) {
	limiter := newRateLimiter(3, time.Hour)
	limiter.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	policy := rateLimitPolicy{name: "test", perMinute: 60, burst: 1}
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		_ = limiter.take(policy, key)
	}
	if len(limiter.buckets) > 3 {
		t.Fatalf("limiter exceeded max key count: %d", len(limiter.buckets))
	}
}

func TestRequestClientIPIgnoresUntrustedForwardedHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.50")
	if got := requestClientIP(request, nil); got != "198.51.100.10" {
		t.Fatalf("untrusted forwarded header was accepted: %q", got)
	}
}

func TestRequestClientIPWalksTrustedProxyChainRightToLeft(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "10.0.0.5:443"
	request.Header.Set("X-Forwarded-For", "192.0.2.20, 10.0.0.4")
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if got := requestClientIP(request, trusted); got != "192.0.2.20" {
		t.Fatalf("unexpected client IP: %q", got)
	}
}

func TestAuthIPRateLimitReturns429AndAudit(t *testing.T) {
	cfg := Config{
		RateLimitGeneralPerMinute:      100,
		RateLimitGeneralBurst:          10,
		RateLimitAuthPerMinute:         60,
		RateLimitAuthBurst:             1,
		RateLimitInstallationPerMinute: 100,
		RateLimitInstallationBurst:     10,
		RateLimitAdminPerMinute:        100,
		RateLimitAdminBurst:            10,
		RateLimitMaxKeys:               100,
		RateLimitIdleTTL:               time.Hour,
	}
	audit := newMemoryAuditStore()
	server := NewServerWithStores(
		cfg,
		nil,
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		audit,
	)
	handler := server.Handler()
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/auth/mobile/browser", nil))
	if first.Code == http.StatusTooManyRequests {
		t.Fatalf("first request unexpectedly limited: %s", first.Body.String())
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/v1/auth/mobile/browser", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") != "1" || second.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("missing rate-limit headers: %+v", second.Header())
	}
	if !strings.Contains(second.Body.String(), "rate limit exceeded") {
		t.Fatalf("unexpected body: %s", second.Body.String())
	}
	records := audit.List(10)
	if len(records) != 1 || records[0].Action != "security.rate_limit" || !strings.Contains(records[0].Detail, "policy=auth_ip") {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestEventSubWebhookIsExemptFromGenericIPLimit(t *testing.T) {
	cfg := Config{
		RateLimitGeneralPerMinute:      60,
		RateLimitGeneralBurst:          1,
		RateLimitAuthPerMinute:         60,
		RateLimitAuthBurst:             1,
		RateLimitInstallationPerMinute: 60,
		RateLimitInstallationBurst:     1,
		RateLimitAdminPerMinute:        60,
		RateLimitAdminBurst:            1,
	}
	server := NewServer(cfg, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := server.Handler()
	for attempt := 0; attempt < 3; attempt++ {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/eventsub/webhook", nil))
		if response.Code == http.StatusTooManyRequests {
			t.Fatalf("EventSub webhook was generically rate limited on attempt %d", attempt)
		}
	}
}

func TestInstallationRateKeyRequiresBothDeviceValues(t *testing.T) {
	first := installationRateKey("installation", strings.Repeat("a", 48))
	second := installationRateKey("installation", strings.Repeat("b", 48))
	if first == second || strings.Contains(first, "installation") {
		t.Fatalf("unsafe installation rate key: %q %q", first, second)
	}
}
