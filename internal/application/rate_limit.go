package application

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	configpkg "github.com/0xDive/ferventio-backend/internal/config"
)

const rateLimitAuditInterval = time.Minute

type rateLimitPolicy struct {
	name      string
	perMinute int
	burst     int
}

type rateLimitDecision struct {
	Allowed    bool
	RetryAfter time.Duration
	Limit      int
	Remaining  int
	Audit      bool
}

type rateLimitBucket struct {
	tokens           float64
	updatedAt        time.Time
	lastSeen         time.Time
	lastBlockedAudit time.Time
}

type rateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]rateLimitBucket
	maxKeys    int
	idleTTL    time.Duration
	now        func() time.Time
	operations uint64
}

func newRateLimiter(maxKeys int, idleTTL time.Duration) *rateLimiter {
	if maxKeys <= 0 {
		maxKeys = 50_000
	}
	if idleTTL <= 0 {
		idleTTL = 30 * time.Minute
	}
	return &rateLimiter{
		buckets: make(map[string]rateLimitBucket),
		maxKeys: maxKeys,
		idleTTL: idleTTL,
		now:     time.Now,
	}
}

func (l *rateLimiter) take(policy rateLimitPolicy, key string) rateLimitDecision {
	if l == nil || policy.perMinute <= 0 || policy.burst <= 0 {
		return rateLimitDecision{Allowed: true}
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	now := l.now().UTC()
	bucketKey := policy.name + "\x00" + key
	ratePerSecond := float64(policy.perMinute) / 60.0

	l.mu.Lock()
	defer l.mu.Unlock()
	l.operations++
	if l.operations%256 == 0 || len(l.buckets) >= l.maxKeys {
		l.cleanupLocked(now)
	}

	bucket, exists := l.buckets[bucketKey]
	if !exists {
		bucket = rateLimitBucket{tokens: float64(policy.burst), updatedAt: now, lastSeen: now}
	} else if now.After(bucket.updatedAt) {
		bucket.tokens = math.Min(
			float64(policy.burst),
			bucket.tokens+now.Sub(bucket.updatedAt).Seconds()*ratePerSecond,
		)
		bucket.updatedAt = now
	}
	bucket.lastSeen = now

	decision := rateLimitDecision{Limit: policy.perMinute}
	if bucket.tokens >= 1 {
		bucket.tokens--
		decision.Allowed = true
		decision.Remaining = int(math.Floor(bucket.tokens))
	} else {
		decision.Allowed = false
		missing := 1 - bucket.tokens
		decision.RetryAfter = time.Duration(math.Ceil(missing / ratePerSecond * float64(time.Second)))
		if decision.RetryAfter < time.Second {
			decision.RetryAfter = time.Second
		}
		if bucket.lastBlockedAudit.IsZero() || now.Sub(bucket.lastBlockedAudit) >= rateLimitAuditInterval {
			decision.Audit = true
			bucket.lastBlockedAudit = now
		}
	}
	l.buckets[bucketKey] = bucket
	return decision
}

func (l *rateLimiter) cleanupLocked(now time.Time) {
	cutoff := now.Add(-l.idleTTL)
	for key, bucket := range l.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
	for len(l.buckets) >= l.maxKeys {
		var oldestKey string
		var oldest time.Time
		for key, bucket := range l.buckets {
			if oldestKey == "" || bucket.lastSeen.Before(oldest) {
				oldestKey = key
				oldest = bucket.lastSeen
			}
		}
		if oldestKey == "" {
			break
		}
		delete(l.buckets, oldestKey)
	}
}

func (s *Server) rateLimitRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimiter == nil || s.cfg.RateLimitDisabled || rateLimitExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		policy := s.rateLimitGeneralPolicy
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/auth/"):
			policy = s.rateLimitAuthPolicy
		case strings.HasPrefix(r.URL.Path, "/v1/admin/"):
			policy = s.rateLimitAdminPolicy
		}
		clientIP := requestClientIP(r, s.cfg.RateLimitTrustedProxyCIDRs)
		if !s.enforceRateLimit(w, r, policy, "ip:"+clientIP, "", "") {
			return
		}
		if installationID, deviceSecret := requestInstallationCredentials(r); installationID != "" && deviceSecret != "" {
			if !s.enforceInstallationRateLimit(w, r, installationID, deviceSecret) {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimitExemptPath(path string) bool {
	// Twitch already authenticates EventSub with HMAC, and a busy channel may deliver
	// legitimate bursts through a small set of Twitch egress addresses. Applying the
	// generic per-IP bucket here would turn a shared upstream into a denial-of-service
	// primitive. WebSocket handshakes remain covered by the general IP bucket.
	return path == "/v1/eventsub/webhook"
}

func (s *Server) enforceInstallationRateLimit(
	w http.ResponseWriter,
	r *http.Request,
	installationID string,
	deviceSecret string,
) bool {
	if s.rateLimiter == nil || s.cfg.RateLimitDisabled {
		return true
	}
	if err := validateMobileDevice(installationID, deviceSecret); err != nil {
		// Validation remains the handler's responsibility. Invalid identifiers should
		// not allocate unbounded limiter keys, while the request is still protected by IP.
		return true
	}
	key := installationRateKey(installationID, deviceSecret)
	return s.enforceRateLimit(
		w,
		r,
		s.rateLimitInstallationPolicy,
		"installation:"+key,
		strings.TrimSpace(installationID),
		"",
	)
}

func (s *Server) takeInstallationRateLimit(installationID, deviceSecret string) rateLimitDecision {
	if s.rateLimiter == nil || s.cfg.RateLimitDisabled {
		return rateLimitDecision{Allowed: true}
	}
	if err := validateMobileDevice(installationID, deviceSecret); err != nil {
		return rateLimitDecision{Allowed: true}
	}
	return s.rateLimiter.take(
		s.rateLimitInstallationPolicy,
		"installation:"+installationRateKey(installationID, deviceSecret),
	)
}

func (s *Server) enforceRateLimit(
	w http.ResponseWriter,
	r *http.Request,
	policy rateLimitPolicy,
	key string,
	installationID string,
	userID string,
) bool {
	decision := s.rateLimiter.take(policy, key)
	if decision.Allowed {
		return true
	}
	retrySeconds := int(math.Ceil(decision.RetryAfter.Seconds()))
	if retrySeconds < 1 {
		retrySeconds = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySeconds))
	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", decision.Limit))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("Cache-Control", "no-store")
	s.auditRateLimitBlock(decision, policy.name, r.Method, r.URL.Path, installationID, userID)
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
	return false
}

func (s *Server) auditRateLimitBlock(
	decision rateLimitDecision,
	policyName string,
	method string,
	path string,
	installationID string,
	userID string,
) {
	if !decision.Audit || s.rateLimiter == nil {
		return
	}
	// A rotating-key attack must not turn audit persistence itself into a write-amplification
	// vector. Per-key sampling above is combined with this bounded global audit budget.
	auditDecision := s.rateLimiter.take(
		rateLimitPolicy{name: "rate_limit_audit", perMinute: 60, burst: 10},
		"global",
	)
	if !auditDecision.Allowed {
		return
	}
	s.auditRecord(AuditRecord{
		Action:         "security.rate_limit",
		Status:         "blocked",
		InstallationID: installationID,
		UserID:         userID,
		Detail:         fmt.Sprintf("policy=%s method=%s path=%s", policyName, method, path),
	})
}

func installationRateKey(installationID, deviceSecret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(installationID) + "\x00" + strings.TrimSpace(deviceSecret)))
	return hex.EncodeToString(sum[:])
}

func requestInstallationCredentials(r *http.Request) (string, string) {
	installationID := strings.TrimSpace(r.Header.Get("X-Installation-ID"))
	deviceSecret := strings.TrimSpace(r.Header.Get("X-Device-Secret"))
	if installationID == "" && strings.HasPrefix(r.URL.Path, "/v1/push/registrations/") {
		remainder := strings.TrimPrefix(r.URL.Path, "/v1/push/registrations/")
		installationID = strings.TrimSpace(strings.SplitN(remainder, "/", 2)[0])
	}
	return installationID, deviceSecret
}

func requestClientIP(r *http.Request, trusted []netip.Prefix) string {
	remote := parseRequestIP(r.RemoteAddr)
	if !remote.IsValid() {
		return "unknown"
	}
	if !ipInPrefixes(remote, trusted) {
		return remote.String()
	}

	chain := make([]netip.Addr, 0, 8)
	for _, raw := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if candidate := parseRequestIP(strings.TrimSpace(raw)); candidate.IsValid() {
			chain = append(chain, candidate)
		}
	}
	chain = append(chain, remote)
	for index := len(chain) - 1; index >= 0; index-- {
		candidate := chain[index]
		if !ipInPrefixes(candidate, trusted) {
			return candidate.String()
		}
	}
	if len(chain) > 0 {
		return chain[0].String()
	}
	return remote.String()
}

func parseRequestIP(raw string) netip.Addr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}

func ipInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	if !address.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func rateLimitGeneralPerMinute(cfg Config) int {
	if cfg.RateLimitGeneralPerMinute > 0 {
		return cfg.RateLimitGeneralPerMinute
	}
	return configpkg.DefaultRateLimitGeneralPerMinute
}

func rateLimitGeneralBurst(cfg Config) int {
	if cfg.RateLimitGeneralBurst > 0 {
		return cfg.RateLimitGeneralBurst
	}
	return configpkg.DefaultRateLimitGeneralBurst
}

func rateLimitAuthPerMinute(cfg Config) int {
	if cfg.RateLimitAuthPerMinute > 0 {
		return cfg.RateLimitAuthPerMinute
	}
	return configpkg.DefaultRateLimitAuthPerMinute
}

func rateLimitAuthBurst(cfg Config) int {
	if cfg.RateLimitAuthBurst > 0 {
		return cfg.RateLimitAuthBurst
	}
	return configpkg.DefaultRateLimitAuthBurst
}

func rateLimitInstallationPerMinute(cfg Config) int {
	if cfg.RateLimitInstallationPerMinute > 0 {
		return cfg.RateLimitInstallationPerMinute
	}
	return configpkg.DefaultRateLimitInstallationPerMinute
}

func rateLimitInstallationBurst(cfg Config) int {
	if cfg.RateLimitInstallationBurst > 0 {
		return cfg.RateLimitInstallationBurst
	}
	return configpkg.DefaultRateLimitInstallationBurst
}

func rateLimitAdminPerMinute(cfg Config) int {
	if cfg.RateLimitAdminPerMinute > 0 {
		return cfg.RateLimitAdminPerMinute
	}
	return configpkg.DefaultRateLimitAdminPerMinute
}

func rateLimitAdminBurst(cfg Config) int {
	if cfg.RateLimitAdminBurst > 0 {
		return cfg.RateLimitAdminBurst
	}
	return configpkg.DefaultRateLimitAdminBurst
}

func rateLimitMaxKeys(cfg Config) int {
	if cfg.RateLimitMaxKeys > 0 {
		return cfg.RateLimitMaxKeys
	}
	return configpkg.DefaultRateLimitMaxKeys
}

func rateLimitIdleTTL(cfg Config) time.Duration {
	if cfg.RateLimitIdleTTL > 0 {
		return cfg.RateLimitIdleTTL
	}
	return configpkg.DefaultRateLimitIdleTTL
}
