package application

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PushSender interface {
	Send(context.Context, Registration, Notification) error
}

type Server struct {
	cfg                         Config
	store                       RegistrationRepository
	authStore                   AuthRepository
	sender                      PushSender
	deliveries                  DeliveryRepository
	audit                       AuditRepository
	settingsSync                SettingsSyncRepository
	readiness                   ReadinessChecker
	hub                         *PushHub
	eventQueue                  chan queuedEventSub
	eventInFlight               map[string]struct{}
	eventSubReconcile           chan struct{}
	eventMu                     sync.Mutex
	eventSub                    *eventSubManager
	flushLocks                  sync.Map
	channelStateLocks           sync.Map
	metadata                    *twitchMetadataClient
	oauth                       *twitchOAuthClient
	rateLimiter                 *rateLimiter
	rateLimitGeneralPolicy      rateLimitPolicy
	rateLimitAuthPolicy         rateLimitPolicy
	rateLimitInstallationPolicy rateLimitPolicy
	rateLimitAdminPolicy        rateLimitPolicy
	log                         *slog.Logger
}

// Dependencies contains every external adapter required by the HTTP application.
// The process composition root owns concrete construction; application never opens
// databases or reads deployment files directly.
type Dependencies struct {
	Config        Config
	Registrations RegistrationRepository
	Auth          AuthRepository
	Sender        PushSender
	Deliveries    DeliveryRepository
	Audit         AuditRepository
	Settings      SettingsSyncRepository
	Readiness     ReadinessChecker
	Logger        *slog.Logger
}

// New creates the application using explicit ports and adapters.
func New(deps Dependencies) *Server {
	deliveries := deps.Deliveries
	if deliveries == nil {
		deliveries = newMemoryDeliveryStore()
	}
	audit := deps.Audit
	if audit == nil {
		audit = newMemoryAuditStore()
	}
	settingsSync := deps.Settings
	if settingsSync == nil {
		settingsSync = newMemorySettingsSyncStore()
	}
	readiness := deps.Readiness
	if readiness == nil {
		if checker, ok := deps.Registrations.(ReadinessChecker); ok {
			readiness = checker
		}
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:               deps.Config,
		store:             deps.Registrations,
		authStore:         deps.Auth,
		sender:            deps.Sender,
		deliveries:        deliveries,
		audit:             audit,
		settingsSync:      settingsSync,
		readiness:         readiness,
		hub:               NewPushHub(),
		eventQueue:        make(chan queuedEventSub, 1_024),
		eventInFlight:     map[string]struct{}{},
		eventSubReconcile: make(chan struct{}, 1),
		eventSub:          newEventSubManager(deps.Config),
		metadata:          newTwitchMetadataClient(deps.Config),
		oauth:             newTwitchOAuthClient(deps.Config, deps.Auth),
		rateLimiter:       newRateLimiter(rateLimitMaxKeys(deps.Config), rateLimitIdleTTL(deps.Config)),
		rateLimitGeneralPolicy: rateLimitPolicy{
			name:      "general_ip",
			perMinute: rateLimitGeneralPerMinute(deps.Config),
			burst:     rateLimitGeneralBurst(deps.Config),
		},
		rateLimitAuthPolicy: rateLimitPolicy{
			name:      "auth_ip",
			perMinute: rateLimitAuthPerMinute(deps.Config),
			burst:     rateLimitAuthBurst(deps.Config),
		},
		rateLimitInstallationPolicy: rateLimitPolicy{
			name:      "installation",
			perMinute: rateLimitInstallationPerMinute(deps.Config),
			burst:     rateLimitInstallationBurst(deps.Config),
		},
		rateLimitAdminPolicy: rateLimitPolicy{
			name:      "admin_ip",
			perMinute: rateLimitAdminPerMinute(deps.Config),
			burst:     rateLimitAdminBurst(deps.Config),
		},
		log: logger,
	}
}

// NewServer is retained for focused unit tests. Production code should use New with
// explicit Dependencies.
func NewServer(
	cfg Config,
	store RegistrationRepository,
	authStore AuthRepository,
	sender PushSender,
	logger *slog.Logger,
	deliveryStores ...DeliveryRepository,
) *Server {
	var deliveries DeliveryRepository
	if len(deliveryStores) > 0 {
		deliveries = deliveryStores[0]
	}
	return New(Dependencies{
		Config: cfg, Registrations: store, Auth: authStore, Sender: sender,
		Deliveries: deliveries, Logger: logger,
	})
}

// NewServerWithStores is retained for compatibility with the existing unit-test
// fixtures. New production wiring should use New.
func NewServerWithStores(
	cfg Config,
	store RegistrationRepository,
	authStore AuthRepository,
	sender PushSender,
	logger *slog.Logger,
	deliveries DeliveryRepository,
	audit AuditRepository,
	syncStores ...SettingsSyncRepository,
) *Server {
	var settings SettingsSyncRepository
	if len(syncStores) > 0 {
		settings = syncStores[0]
	}
	return New(Dependencies{
		Config: cfg, Registrations: store, Auth: authStore, Sender: sender,
		Deliveries: deliveries, Audit: audit, Settings: settings, Logger: logger,
	})
}

func (s *Server) RunBackgroundWorkers(ctx context.Context) {
	go s.runDeliveryWorker(ctx)
	go s.runEventSubReconciler(ctx)
	go s.runEventSubInboxDrainer(ctx)
	for index := 0; index < 4; index++ {
		go s.runEventSubWorker(ctx)
	}
	<-ctx.Done()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /v1/push/vapid-public-key", s.vapidPublicKey)
	mux.HandleFunc("GET /v1/twitch/badges/global", s.globalTwitchBadges)
	mux.HandleFunc("GET /v1/twitch/badges/{broadcasterID}", s.channelTwitchBadges)
	mux.HandleFunc("POST /v1/auth/mobile/start", s.startMobileAuth)
	mux.HandleFunc("GET /v1/auth/mobile/browser", s.beginBrowserAuth)
	mux.HandleFunc("GET /v1/auth/twitch/callback", s.twitchOAuthCallback)
	mux.HandleFunc("POST /v1/auth/mobile/complete", s.completeMobileAuth)
	mux.HandleFunc("POST /v1/auth/token", s.leaseMobileToken)
	mux.HandleFunc("DELETE /v1/auth/session", s.deleteMobileSession)
	mux.HandleFunc("DELETE /v1/auth/device", s.revokeMobileDevice)
	mux.HandleFunc("DELETE /v1/auth/sessions", s.revokeAllMobileSessions)
	mux.HandleFunc("GET /v1/sync/settings", s.getSettingsSync)
	mux.HandleFunc("PUT /v1/sync/settings", s.putSettingsSync)
	mux.HandleFunc("GET /v1/sync/settings/history", s.getSettingsSyncHistory)
	mux.HandleFunc("POST /v1/sync/settings/restore/{revision}", s.restoreSettingsSyncRevision)
	mux.HandleFunc("PUT /v1/push/registrations/{installationID}", s.upsertRegistration)
	mux.HandleFunc("DELETE /v1/push/registrations/{installationID}", s.deleteRegistration)
	mux.HandleFunc("POST /v1/push/registrations/{installationID}/self-test", s.selfTest)
	mux.HandleFunc("GET /v1/push/socket", s.pushSocket)
	mux.HandleFunc("POST /v1/eventsub/webhook", s.eventSubWebhook)
	mux.HandleFunc("POST /v1/admin/eventsub/reconcile", s.adminReconcileEventSub)
	mux.HandleFunc("GET /v1/admin/eventsub/subscriptions", s.adminListEventSubSubscriptions)
	mux.HandleFunc("DELETE /v1/admin/eventsub/subscriptions", s.adminDeleteEventSubSubscriptions)
	mux.HandleFunc("GET /v1/admin/eventsub/inbox", s.adminEventSubInbox)
	mux.HandleFunc("POST /v1/admin/eventsub/inbox/{messageID}/retry", s.adminRetryEventSubInbox)
	mux.HandleFunc("GET /v1/admin/deliveries", s.adminDeliveryHistory)
	mux.HandleFunc("GET /v1/admin/audit", s.adminAuditLog)
	mux.HandleFunc("POST /v1/admin/push/{installationID}", s.adminPush)
	return s.recoverPanic(s.logRequests(s.rateLimitRequests(mux)))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.readiness == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.readiness.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) vapidPublicKey(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.VAPIDPublicKey == "" {
		writeError(w, http.StatusServiceUnavailable, "VAPID is not configured")
		return
	}
	writeJSON(w, http.StatusOK, VAPIDResponse{PublicKey: s.cfg.VAPIDPublicKey})
}

func (s *Server) globalTwitchBadges(w http.ResponseWriter, r *http.Request) {
	body, err := s.metadata.globalChatBadges(r.Context())
	if err != nil {
		s.writeMetadataError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=21600, stale-if-error=86400")
	writeRawJSON(w, http.StatusOK, body)
}

func (s *Server) channelTwitchBadges(w http.ResponseWriter, r *http.Request) {
	body, err := s.metadata.channelChatBadges(r.Context(), r.PathValue("broadcasterID"))
	if err != nil {
		s.writeMetadataError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=1800, stale-if-error=21600")
	writeRawJSON(w, http.StatusOK, body)
}

func (s *Server) writeMetadataError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTwitchMetadataDisabled):
		writeError(w, http.StatusServiceUnavailable, "Twitch metadata relay is not configured")
	case strings.Contains(err.Error(), "invalid broadcaster ID"):
		writeError(w, http.StatusBadRequest, "invalid broadcaster ID")
	default:
		s.log.Warn("Twitch metadata request failed", "error", err)
		writeError(w, http.StatusBadGateway, "Twitch metadata is temporarily unavailable")
	}
}

func (s *Server) upsertRegistration(w http.ResponseWriter, r *http.Request) {
	installationID := r.PathValue("installationID")
	var registration Registration
	if err := s.decodeJSON(w, r, &registration); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if registration.InstallationID != installationID {
		writeError(w, http.StatusBadRequest, "installationId does not match URL")
		return
	}
	normalizeRegistration(&registration)
	if err := validateRegistration(registration); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.enforceInstallationRateLimit(w, r, registration.InstallationID, registration.DeviceSecret) {
		return
	}
	registration.ChannelIDs = normalizeLimitedStrings(registration.ChannelIDs, 100, 64)
	registration.ModeratorChannelIDs = normalizeLimitedStrings(registration.ModeratorChannelIDs, 100, 64)
	registration.ModeratorChannelIDs = intersectStrings(registration.ModeratorChannelIDs, registration.ChannelIDs)
	registration.NotificationRules = normalizeLimitedStrings(registration.NotificationRules, 32, 64)
	registration.HighlightPhrases = normalizeLimitedStrings(registration.HighlightPhrases, 100, 200)
	registration.SelectedUserLogins = normalizeLimitedStrings(registration.SelectedUserLogins, 100, 50)
	if s.authStore != nil && s.oauth != nil {
		credential, err := s.authStore.CredentialForInstallation(
			registration.InstallationID,
			registration.DeviceSecret,
		)
		if err != nil {
			// A production server with OAuth enabled must never accept an orphaned
			// installation. Otherwise an attacker could fill the registration store
			// or bind arbitrary channel rules without completing Twitch authorization.
			s.auditRecord(AuditRecord{
				Action:         "push.registration.upsert",
				Status:         "unauthorized",
				InstallationID: registration.InstallationID,
				Detail:         err.Error(),
			})
			writeError(w, http.StatusUnauthorized, "active Twitch authorization is required")
			return
		}
		registration.UserID = credential.UserID
		registration.UserLogin = credential.Login
		requestedModeratorIDs := append([]string(nil), registration.ModeratorChannelIDs...)
		verifiedModeratorIDs, verifyErr := s.oauth.moderatedChannelIDs(r.Context(), credential.ID)
		if verifyErr != nil {
			// Never grant moderator-only subscriptions from client assertions. During a
			// temporary Twitch failure, retain only previously verified IDs for this device.
			registration.ModeratorChannelIDs = nil
			if existing, existingErr := s.store.Get(registration.InstallationID); existingErr == nil &&
				existing.UserID == credential.UserID {
				registration.ModeratorChannelIDs = intersectStrings(
					requestedModeratorIDs,
					existing.ModeratorChannelIDs,
				)
			}
			s.log.Warn(
				"moderated channels verification failed",
				"installation", registration.InstallationID,
				"user_id", credential.UserID,
				"error", verifyErr,
			)
			s.auditRecord(AuditRecord{
				Action:         "push.registration.moderation_verify",
				Status:         "failed_safe",
				InstallationID: registration.InstallationID,
				UserID:         credential.UserID,
				Detail:         verifyErr.Error(),
			})
		} else {
			registration.ModeratorChannelIDs = intersectStrings(
				requestedModeratorIDs,
				verifiedModeratorIDs,
			)
		}
	} else {
		// EventSub rules and channel bindings are accepted only from a server-backed
		// OAuth session. An unauthenticated client may register a transport for a
		// self-test, but it cannot create subscriptions or impersonate a moderator.
		registration.UserID = ""
		registration.UserLogin = ""
		registration.ChannelIDs = nil
		registration.ModeratorChannelIDs = nil
		registration.NotificationRules = nil
		registration.HighlightPhrases = nil
		registration.SelectedUserLogins = nil
	}
	registration.UpdatedAt = time.Now().UTC()
	if err := s.store.Upsert(registration); err != nil {
		if errors.Is(err, ErrSecretMismatch) {
			writeError(w, http.StatusForbidden, "device secret mismatch")
			return
		}
		writeError(w, http.StatusInternalServerError, "registration was not saved")
		return
	}
	s.auditRecord(AuditRecord{
		Action:         "push.registration.upsert",
		Status:         "ok",
		InstallationID: registration.InstallationID,
		UserID:         registration.UserID,
		Detail:         registration.Provider,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
	s.requestEventSubReconcile()
}

func (s *Server) deleteRegistration(w http.ResponseWriter, r *http.Request) {
	err := s.store.Delete(r.PathValue("installationID"), r.Header.Get("X-Device-Secret"))
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "registration not found")
	case errors.Is(err, ErrSecretMismatch):
		writeError(w, http.StatusForbidden, "device secret mismatch")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "registration was not deleted")
	default:
		installationID := r.PathValue("installationID")
		s.hub.Close(installationID)
		s.auditRecord(AuditRecord{
			Action:         "push.registration.delete",
			Status:         "ok",
			InstallationID: installationID,
		})
		w.WriteHeader(http.StatusNoContent)
		s.requestEventSubReconcile()
	}
}

func (s *Server) selfTest(w http.ResponseWriter, r *http.Request) {
	registration, ok := s.authorizeDevice(w, r)
	if !ok {
		return
	}
	notification := Notification{
		Title:     "Ferventio",
		Body:      "Тестовое push-уведомление работает",
		MessageID: fmt.Sprintf("self-test-%d", time.Now().UnixNano()),
	}
	if err := s.deliverToRegistration(r.Context(), registration, notification); err != nil {
		s.log.Error("self test push failed", "error", err, "installation", registration.InstallationID)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
}

func (s *Server) adminPush(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AdminToken == "" || !secureEqual(bearerToken(r), s.cfg.AdminToken) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	registration, err := s.store.Get(r.PathValue("installationID"))
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "registration not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration lookup failed")
		return
	}
	var notification Notification
	if err := s.decodeJSON(w, r, &notification); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(notification.Body) == "" {
		writeError(w, http.StatusBadRequest, "body is required")
		return
	}
	if notification.Title == "" {
		notification.Title = "Ferventio"
	}
	if err := s.deliverToRegistration(r.Context(), registration, notification); err != nil {
		s.log.Error("admin push failed", "error", err, "installation", registration.InstallationID)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
}

func (s *Server) authorizeDevice(w http.ResponseWriter, r *http.Request) (Registration, bool) {
	registration, err := s.store.Authenticate(
		r.PathValue("installationID"),
		r.Header.Get("X-Device-Secret"),
	)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "registration not found")
		return Registration{}, false
	case errors.Is(err, ErrSecretMismatch):
		writeError(w, http.StatusForbidden, "device secret mismatch")
		return Registration{}, false
	case err != nil:
		writeError(w, http.StatusInternalServerError, "registration lookup failed")
		return Registration{}, false
	default:
		return registration, true
	}
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.RequestBodyMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON: multiple values are not allowed")
	}
	return nil
}

func normalizeRegistration(registration *Registration) {
	registration.Platform = strings.ToLower(strings.TrimSpace(registration.Platform))
	registration.Provider = strings.ToLower(strings.TrimSpace(registration.Provider))
	registration.APNsDeviceToken = strings.TrimSpace(registration.APNsDeviceToken)
	if registration.Platform == "" {
		// 0.9.5 Android clients omitted this default value because kotlinx.serialization
		// does not encode default-valued properties unless encodeDefaults is enabled.
		registration.Platform = "android"
	}
}

func validateRegistration(registration Registration) error {
	if registration.InstallationID == "" || registration.DeviceSecret == "" {
		return errors.New("installationId and deviceSecret are required")
	}
	switch registration.Platform {
	case "android":
		switch registration.Provider {
		case "fcm":
			if registration.FirebaseInstallation == "" {
				return errors.New("firebaseInstallationId is required for FCM")
			}
		case "unifiedpush":
			if registration.Endpoint == "" || registration.P256DH == "" || registration.Auth == "" {
				return errors.New("endpoint, p256dh and auth are required for UnifiedPush")
			}
		case "embedded_socket":
			// The device authenticates the persistent WebSocket with installationId and deviceSecret.
		default:
			return errors.New("android provider must be fcm, unifiedpush, or embedded_socket")
		}
	case "ios":
		if registration.Provider != "apns" {
			return errors.New("ios provider must be apns")
		}
		if registration.APNsDeviceToken == "" {
			return errors.New("apnsDeviceToken is required for APNs")
		}
	default:
		return errors.New("platform must be android or ios")
	}
	return nil
}

func intersectStrings(values, allowed []string) []string {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedSet[strings.ToLower(value)] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := allowedSet[strings.ToLower(value)]; ok {
			result = append(result, value)
		}
	}
	return result
}

func normalizeLimitedStrings(values []string, maxItems, maxLength int) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, minInt(len(values), maxItems))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maxLength {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
		if len(result) >= maxItems {
			break
		}
	}
	return result
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started))
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error("panic", "value", recovered)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
}

func secureEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) reserveEventSub(messageID string) bool {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if _, exists := s.eventInFlight[messageID]; exists {
		return false
	}
	s.eventInFlight[messageID] = struct{}{}
	return true
}

func (s *Server) releaseEventSub(messageID string) {
	s.eventMu.Lock()
	delete(s.eventInFlight, messageID)
	s.eventMu.Unlock()
}

func (s *Server) auditRecord(record AuditRecord) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Append(record); err != nil {
		s.log.Warn("audit record was not persisted", "action", record.Action, "error", err)
	}
}

func (s *Server) adminEventSubInbox(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	limit := queryLimit(r, 200, 1_000)
	writeJSON(w, http.StatusOK, map[string]any{"data": s.deliveries.ListEventSubInbox(limit)})
}

func (s *Server) adminRetryEventSubInbox(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	messageID := strings.TrimSpace(r.PathValue("messageID"))
	if messageID == "" {
		writeError(w, http.StatusBadRequest, "message id is required")
		return
	}
	if err := s.deliveries.RetryEventSub(messageID, time.Now().UTC()); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "EventSub inbox item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "EventSub inbox item was not updated")
		return
	}
	s.auditRecord(AuditRecord{Action: "eventsub.retry", Status: "queued", EventID: messageID})
	for _, record := range s.deliveries.PendingEventSub(1_000, time.Now().UTC()) {
		if record.MessageID == messageID {
			_ = s.scheduleEventSub(record)
			break
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) adminDeliveryHistory(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	limit := queryLimit(r, 200, 1_000)
	writeJSON(w, http.StatusOK, map[string]any{"data": s.deliveries.ListDeliveries(limit)})
}

func (s *Server) adminAuditLog(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	limit := queryLimit(r, 200, 1_000)
	writeJSON(w, http.StatusOK, map[string]any{"data": s.audit.ListAudit(limit)})
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" || !secureEqual(bearerToken(r), s.cfg.AdminToken) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func queryLimit(r *http.Request, fallback, maximum int) int {
	value := fallback
	if parsed, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && parsed > 0 {
		value = parsed
	}
	if value > maximum {
		value = maximum
	}
	return value
}
