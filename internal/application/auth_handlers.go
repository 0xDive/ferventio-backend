package application

import (
	"errors"
	"fmt"
	htmlTemplate "html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type mobileAuthStartRequest struct {
	InstallationID string `json:"installationId"`
	DeviceSecret   string `json:"deviceSecret"`
	AppCallbackURI string `json:"appCallbackUri"`
}

type mobileAuthStartResponse struct {
	AuthorizationURL string    `json:"authorizationUrl"`
	State            string    `json:"state"`
	ServerTime       time.Time `json:"serverTime"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type mobileAuthCompleteRequest struct {
	InstallationID string `json:"installationId"`
	DeviceSecret   string `json:"deviceSecret"`
	Code           string `json:"code"`
	State          string `json:"state"`
}

type mobileAuthCompleteResponse struct {
	SessionToken     string           `json:"sessionToken"`
	SessionExpiresAt time.Time        `json:"sessionExpiresAt"`
	Lease            mobileTokenLease `json:"lease"`
}

type mobileTokenLease struct {
	AccessToken       string    `json:"accessToken"`
	ServerTime        time.Time `json:"serverTime"`
	ClientID          string    `json:"clientId"`
	UserID            string    `json:"userId"`
	Login             string    `json:"login"`
	Scopes            []string  `json:"scopes"`
	LeaseExpiresAt    time.Time `json:"leaseExpiresAt"`
	TwitchExpiresAt   time.Time `json:"twitchExpiresAt"`
	TwitchValidatedAt time.Time `json:"twitchValidatedAt"`
	SessionExpiresAt  time.Time `json:"sessionExpiresAt"`
}

func (s *Server) startMobileAuth(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	var request mobileAuthStartRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateMobileDevice(request.InstallationID, request.DeviceSecret); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.enforceInstallationRateLimit(w, r, request.InstallationID, request.DeviceSecret) {
		return
	}
	if err := s.validateAppCallbackURI(request.AppCallbackURI); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := randomToken("fs1_", 32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create OAuth state")
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(s.cfg.AuthStateTTL)
	if err := s.authStore.PutPending(state, pendingAuthRecord{
		InstallationID: request.InstallationID,
		DeviceHash:     hashSecret(request.DeviceSecret),
		AppCallbackURI: request.AppCallbackURI,
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
	}); err != nil {
		if errors.Is(err, ErrAuthCapacity) {
			writeError(w, http.StatusTooManyRequests, "too many pending OAuth sessions")
			return
		}
		s.log.Error("save OAuth state", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to start OAuth")
		return
	}
	noStore(w)
	writeJSON(w, http.StatusCreated, mobileAuthStartResponse{
		AuthorizationURL: s.publicAuthURL(state),
		State:            state,
		ServerTime:       now,
		ExpiresAt:        expiresAt,
	})
}

func (s *Server) beginBrowserAuth(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		writeError(w, http.StatusBadRequest, "missing OAuth state")
		return
	}
	if _, err := s.authStore.GetPending(state); err != nil {
		writeError(w, http.StatusBadRequest, "OAuth session is missing or expired")
		return
	}
	noStore(w)
	http.Redirect(w, r, s.oauth.authorizationURL(state), http.StatusFound)
}

func (s *Server) publicAuthURL(state string) string {
	return strings.TrimSuffix(s.cfg.PublicBaseURL, "/") + "/v1/auth/mobile/browser?state=" + url.QueryEscape(state)
}

func (s *Server) twitchOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		writeError(w, http.StatusBadRequest, "missing OAuth state")
		return
	}
	pending, err := s.authStore.ConsumePending(state)
	if err != nil {
		writeError(w, http.StatusBadRequest, "OAuth session is missing or expired")
		return
	}
	if denied := strings.TrimSpace(r.URL.Query().Get("error")); denied != "" {
		s.renderAppReturn(w, pending.AppCallbackURI, state, "", denied)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		s.renderAppReturn(w, pending.AppCallbackURI, state, "", "missing_code")
		return
	}
	credential, err := s.oauth.exchangeCode(r.Context(), code)
	if err != nil {
		s.log.Warn("Twitch OAuth exchange failed", "error", err)
		s.renderAppReturn(w, pending.AppCallbackURI, state, "", "oauth_exchange_failed")
		return
	}
	handoffCode, err := randomToken("fh1_", 32)
	if err != nil {
		s.renderAppReturn(w, pending.AppCallbackURI, state, "", "server_random_failed")
		return
	}
	now := time.Now().UTC()
	if err := s.authStore.PutCredentialAndHandoff(credential, handoffCode, authHandoffRecord{
		CredentialID:   credential.ID,
		InstallationID: pending.InstallationID,
		DeviceHash:     pending.DeviceHash,
		AppCallbackURI: pending.AppCallbackURI,
		StateHash:      hashSecret(state),
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.cfg.AuthHandoffTTL),
	}); err != nil {
		s.log.Error("save OAuth credential and handoff", "error", err)
		s.renderAppReturn(w, pending.AppCallbackURI, state, "", "server_storage_failed")
		return
	}
	s.renderAppReturn(w, pending.AppCallbackURI, state, handoffCode, "")
}

func (s *Server) completeMobileAuth(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	var request mobileAuthCompleteRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateMobileDevice(request.InstallationID, request.DeviceSecret); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.enforceInstallationRateLimit(w, r, request.InstallationID, request.DeviceSecret) {
		return
	}
	handoff, err := s.authStore.ConsumeHandoff(
		strings.TrimSpace(request.Code),
		request.InstallationID,
		request.DeviceSecret,
		request.State,
	)
	if err != nil {
		s.writeAuthRecordError(w, err)
		return
	}
	// Validate the newly authorized Twitch credential before replacing the installation's
	// current mobile session. A transient Twitch failure must not log out a working device.
	credential, err := s.oauth.lease(r.Context(), handoff.CredentialID, false)
	if err != nil {
		_ = s.authStore.DeleteCredentialIfUnused(handoff.CredentialID)
		s.writeOAuthLeaseError(w, err)
		return
	}
	sessionToken, sessionExpiresAt, err := s.authStore.CreateSession(
		handoff.CredentialID,
		request.InstallationID,
		request.DeviceSecret,
		s.cfg.AuthSessionTTL,
	)
	if err != nil {
		_ = s.authStore.DeleteCredentialIfUnused(handoff.CredentialID)
		if errors.Is(err, ErrAuthCapacity) {
			writeError(w, http.StatusTooManyRequests, "too many mobile sessions")
			return
		}
		s.log.Error("create mobile session", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create mobile session")
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, mobileAuthCompleteResponse{
		SessionToken:     sessionToken,
		SessionExpiresAt: sessionExpiresAt,
		Lease:            s.mobileLease(credential, sessionExpiresAt),
	})
}

func (s *Server) leaseMobileToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	session, ok := s.authorizeMobileSession(w, r)
	if !ok {
		return
	}
	forceRefresh := r.URL.Query().Get("force_refresh") == "true"
	credential, err := s.oauth.lease(r.Context(), session.CredentialID, forceRefresh)
	if err != nil {
		s.writeOAuthLeaseError(w, err)
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, s.mobileLease(credential, session.ExpiresAt))
}

func (s *Server) deleteMobileSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	token := bearerToken(r)
	installationID := strings.TrimSpace(r.Header.Get("X-Installation-ID"))
	deviceSecret := strings.TrimSpace(r.Header.Get("X-Device-Secret"))
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing backend session")
		return
	}
	err := s.authStore.DeleteSession(token, installationID, deviceSecret)
	switch {
	case errors.Is(err, ErrAuthNotFound):
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrAuthDeviceMismatch):
		writeError(w, http.StatusForbidden, "device binding mismatch")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "failed to delete session")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) revokeMobileDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	token := bearerToken(r)
	installationID := strings.TrimSpace(r.Header.Get("X-Installation-ID"))
	deviceSecret := strings.TrimSpace(r.Header.Get("X-Device-Secret"))
	if token == "" || installationID == "" || deviceSecret == "" {
		writeError(w, http.StatusUnauthorized, "missing backend session credentials")
		return
	}
	_, sessionErr := s.authStore.ResolveSession(token, installationID, deviceSecret, s.cfg.AuthSessionTTL)
	if sessionErr != nil {
		switch {
		case errors.Is(sessionErr, ErrAuthDeviceMismatch):
			writeError(w, http.StatusForbidden, "device binding mismatch")
			return
		case errors.Is(sessionErr, ErrAuthNotFound):
			// A wrong/old bearer must not revoke a still-active installation merely because
			// the caller also knows its public installation ID.
			if bound, bindingErr := s.authStore.InstallationBinding(installationID, deviceSecret); bindingErr == nil && bound {
				writeError(w, http.StatusUnauthorized, "authentication record not found")
				return
			} else if errors.Is(bindingErr, ErrAuthDeviceMismatch) {
				writeError(w, http.StatusForbidden, "device binding mismatch")
				return
			} else if bindingErr != nil && !errors.Is(bindingErr, ErrAuthNotFound) {
				writeError(w, http.StatusInternalServerError, "authentication storage failed")
				return
			}
		case errors.Is(sessionErr, ErrAuthExpired):
			// The token was real but expired. Continue with the device-secret binding below
			// so a stale installation can still remove its remaining push data.
		default:
			writeError(w, http.StatusInternalServerError, "authentication storage failed")
			return
		}
		if s.store != nil {
			if _, err := s.store.Authenticate(installationID, deviceSecret); err != nil {
				switch {
				case errors.Is(err, ErrSecretMismatch):
					writeError(w, http.StatusForbidden, "device secret mismatch")
					return
				case errors.Is(err, ErrNotFound):
					// Idempotent retry after a successful revoke whose HTTP response was lost.
					w.WriteHeader(http.StatusNoContent)
					return
				default:
					writeError(w, http.StatusInternalServerError, "failed to authenticate device registration")
					return
				}
			}
		} else {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// Remove device delivery surfaces before invalidating its final backend credential,
	// allowing the client to retry safely if a persistent store write fails.
	if s.store != nil {
		err := s.store.Delete(installationID, deviceSecret)
		if err != nil && !errors.Is(err, ErrNotFound) {
			if errors.Is(err, ErrSecretMismatch) {
				writeError(w, http.StatusForbidden, "device secret mismatch")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to delete device registration")
			return
		}
	}
	if s.deliveries != nil {
		if _, err := s.deliveries.DeleteForInstallation(installationID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete device deliveries")
			return
		}
	}
	removedSessions, err := s.authStore.RevokeInstallation(installationID, deviceSecret)
	switch {
	case errors.Is(err, ErrAuthDeviceMismatch):
		writeError(w, http.StatusForbidden, "device binding mismatch")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "failed to revoke device")
		return
	}
	if s.hub != nil {
		s.hub.Close(installationID)
	}
	s.auditRecord(AuditRecord{
		Action:         "auth.device.revoke",
		Status:         "ok",
		InstallationID: installationID,
		Detail:         fmt.Sprintf("sessions=%d", removedSessions),
	})
	w.WriteHeader(http.StatusNoContent)
	s.requestEventSubReconcile()
}

func (s *Server) revokeAllMobileSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthBroker(w) {
		return
	}
	token := bearerToken(r)
	installationID := strings.TrimSpace(r.Header.Get("X-Installation-ID"))
	deviceSecret := strings.TrimSpace(r.Header.Get("X-Device-Secret"))
	if token == "" || installationID == "" || deviceSecret == "" {
		writeError(w, http.StatusUnauthorized, "missing backend session credentials")
		return
	}

	userID, _, sessionErr := s.authStore.SessionAccount(token, installationID, deviceSecret)
	if sessionErr != nil {
		switch {
		case errors.Is(sessionErr, ErrAuthDeviceMismatch):
			writeError(w, http.StatusForbidden, "device binding mismatch")
			return
		case errors.Is(sessionErr, ErrAuthNotFound):
			// Reject a guessed or stale bearer while this installation still has an active
			// auth artifact. A fully stale installation may recover its account identity
			// from the authenticated push registration and complete the destructive revoke.
			if bound, bindingErr := s.authStore.InstallationBinding(installationID, deviceSecret); bindingErr == nil && bound {
				writeError(w, http.StatusUnauthorized, "authentication record not found")
				return
			} else if errors.Is(bindingErr, ErrAuthDeviceMismatch) {
				writeError(w, http.StatusForbidden, "device binding mismatch")
				return
			} else if bindingErr != nil && !errors.Is(bindingErr, ErrAuthNotFound) {
				writeError(w, http.StatusInternalServerError, "authentication storage failed")
				return
			}
			if s.store == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			registration, registrationErr := s.store.Authenticate(installationID, deviceSecret)
			switch {
			case errors.Is(registrationErr, ErrSecretMismatch):
				writeError(w, http.StatusForbidden, "device secret mismatch")
				return
			case errors.Is(registrationErr, ErrNotFound):
				// Idempotent retry after account-wide revocation and a lost 204 response.
				w.WriteHeader(http.StatusNoContent)
				return
			case registrationErr != nil:
				writeError(w, http.StatusInternalServerError, "failed to authenticate device registration")
				return
			}
			userID = strings.TrimSpace(registration.UserID)
		default:
			writeError(w, http.StatusInternalServerError, "authentication storage failed")
			return
		}
	}
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "Twitch account binding is missing")
		return
	}

	targets, err := s.authStore.AccountRevocationTargets(userID)
	if err != nil && !errors.Is(err, ErrAuthNotFound) {
		writeError(w, http.StatusInternalServerError, "failed to enumerate account sessions")
		return
	}
	installationSet := map[string]struct{}{installationID: {}}
	for _, targetInstallationID := range targets.InstallationIDs {
		installationSet[targetInstallationID] = struct{}{}
	}
	if s.store != nil {
		for _, registration := range s.store.List() {
			if registration.UserID == userID {
				installationSet[registration.InstallationID] = struct{}{}
			}
		}
	}
	installationIDs := make([]string, 0, len(installationSet))
	for targetInstallationID := range installationSet {
		installationIDs = append(installationIDs, targetInstallationID)
	}
	sort.Strings(installationIDs)

	revokedTwitchTokens := 0
	for _, credential := range targets.Credentials {
		if err := s.oauth.revokeAccessToken(r.Context(), credential); err != nil {
			s.log.Warn("Twitch access token revoke failed", "credential_id", credential.ID, "error", err)
			continue
		}
		revokedTwitchTokens++
	}

	if s.store != nil {
		removedRegistrationIDs, err := s.store.DeleteForAccount(userID, installationIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete account registrations")
			return
		}
		for _, targetInstallationID := range removedRegistrationIDs {
			installationSet[targetInstallationID] = struct{}{}
		}
	}
	for targetInstallationID := range installationSet {
		if s.deliveries != nil {
			if _, err := s.deliveries.DeleteForInstallation(targetInstallationID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to delete account deliveries")
				return
			}
		}
	}
	installationIDs = installationIDs[:0]
	for targetInstallationID := range installationSet {
		installationIDs = append(installationIDs, targetInstallationID)
	}
	sort.Strings(installationIDs)

	result, err := s.authStore.RevokeAccount(userID, installationIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke account sessions")
		return
	}
	if s.hub != nil {
		for _, targetInstallationID := range installationIDs {
			s.hub.Close(targetInstallationID)
		}
	}
	s.auditRecord(AuditRecord{
		Action:         "auth.sessions.revoke_all",
		Status:         "ok",
		InstallationID: installationID,
		Detail: fmt.Sprintf(
			"sessions=%d credentials=%d installations=%d twitch_tokens=%d/%d",
			result.RemovedSessions,
			result.RemovedCredentials,
			len(installationIDs),
			revokedTwitchTokens,
			len(targets.Credentials),
		),
	})
	w.WriteHeader(http.StatusNoContent)
	s.requestEventSubReconcile()
}

func (s *Server) authorizeMobileSession(w http.ResponseWriter, r *http.Request) (authSessionRecord, bool) {
	token := bearerToken(r)
	installationID := strings.TrimSpace(r.Header.Get("X-Installation-ID"))
	deviceSecret := strings.TrimSpace(r.Header.Get("X-Device-Secret"))
	if token == "" || installationID == "" || deviceSecret == "" {
		writeError(w, http.StatusUnauthorized, "missing backend session credentials")
		return authSessionRecord{}, false
	}
	session, err := s.authStore.ResolveSession(token, installationID, deviceSecret, s.cfg.AuthSessionTTL)
	if err != nil {
		s.writeAuthRecordError(w, err)
		return authSessionRecord{}, false
	}
	return session, true
}

func (s *Server) mobileLease(credential authCredential, sessionExpiresAt time.Time) mobileTokenLease {
	now := time.Now().UTC()
	leaseExpiresAt := now.Add(s.cfg.AuthLeaseTTL)
	if credential.AccessExpiresAt.Before(leaseExpiresAt) {
		leaseExpiresAt = credential.AccessExpiresAt
	}
	twitchValidatedAt := credential.LastValidatedAt
	if twitchValidatedAt.IsZero() {
		twitchValidatedAt = now.Add(-55 * time.Minute)
	} else if twitchValidatedAt.After(now) {
		twitchValidatedAt = now
	}
	return mobileTokenLease{
		AccessToken:       credential.AccessToken,
		ServerTime:        now,
		ClientID:          credential.ClientID,
		UserID:            credential.UserID,
		Login:             credential.Login,
		Scopes:            append([]string(nil), credential.Scopes...),
		LeaseExpiresAt:    leaseExpiresAt,
		TwitchExpiresAt:   credential.AccessExpiresAt,
		TwitchValidatedAt: twitchValidatedAt,
		SessionExpiresAt:  sessionExpiresAt,
	}
}

func (s *Server) requireAuthBroker(w http.ResponseWriter) bool {
	if s.authStore == nil || s.oauth == nil {
		writeError(w, http.StatusServiceUnavailable, "Ferventio OAuth broker is not configured")
		return false
	}
	return true
}

func (s *Server) writeAuthRecordError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAuthExpired):
		writeError(w, http.StatusUnauthorized, "authentication record expired")
	case errors.Is(err, ErrAuthDeviceMismatch):
		writeError(w, http.StatusForbidden, "device binding mismatch")
	case errors.Is(err, ErrAuthStateMismatch):
		writeError(w, http.StatusForbidden, "OAuth state mismatch")
	case errors.Is(err, ErrAuthCapacity):
		writeError(w, http.StatusTooManyRequests, "authentication capacity exceeded")
	case errors.Is(err, ErrAuthNotFound):
		writeError(w, http.StatusUnauthorized, "authentication record not found")
	default:
		s.log.Error("authentication store error", "error", err)
		writeError(w, http.StatusInternalServerError, "authentication storage failed")
	}
}

func (s *Server) writeOAuthLeaseError(w http.ResponseWriter, err error) {
	if errors.Is(err, errOAuthRevoked) || errors.Is(err, ErrAuthNotFound) {
		writeError(w, http.StatusUnauthorized, "Twitch authorization is no longer valid")
		return
	}
	s.log.Warn("Twitch token lease failed", "error", err)
	writeError(w, http.StatusBadGateway, "Twitch authorization is temporarily unavailable")
}

func (s *Server) validateAppCallbackURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid appCallbackUri")
	}
	allowed := false
	for _, scheme := range s.cfg.AuthAllowedAppSchemes {
		if parsed.Scheme == scheme {
			allowed = true
			break
		}
	}
	if !allowed || parsed.Host != "oauth" || parsed.Path != "/callback" || parsed.User != nil {
		return errors.New("appCallbackUri is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("appCallbackUri must not contain query or fragment")
	}
	return nil
}

func validateMobileDevice(installationID, deviceSecret string) error {
	installationID = strings.TrimSpace(installationID)
	deviceSecret = strings.TrimSpace(deviceSecret)
	if installationID == "" || len(installationID) > 128 {
		return errors.New("invalid installationId")
	}
	if len(deviceSecret) < 32 || len(deviceSecret) > 256 {
		return errors.New("invalid deviceSecret")
	}
	return nil
}

func (s *Server) renderAppReturn(w http.ResponseWriter, callbackURI, state, code, errorCode string) {
	parsed, err := url.Parse(callbackURI)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid app callback")
		return
	}
	query := parsed.Query()
	query.Set("state", state)
	if code != "" {
		query.Set("code", code)
	}
	if errorCode != "" {
		query.Set("error", errorCode)
	}
	parsed.RawQuery = query.Encode()
	data := struct {
		DeepLinkURL htmlTemplate.URL
		DeepLinkJS  string
		Success     bool
	}{
		DeepLinkURL: htmlTemplate.URL(parsed.String()), // validated custom URI assembled by this server
		DeepLinkJS:  parsed.String(),
		Success:     errorCode == "",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
	w.WriteHeader(http.StatusOK)
	if err := appReturnTemplate.Execute(w, data); err != nil {
		s.log.Error("render OAuth return page", "error", err)
	}
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

var appReturnTemplate = htmlTemplate.Must(htmlTemplate.New("oauth-return").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ferventio</title><style>body{margin:0;background:#0c0b10;color:#f5f2f7;font:16px system-ui,sans-serif;display:grid;min-height:100vh;place-items:center}.card{max-width:420px;margin:24px;padding:28px;border-radius:24px;background:#211c22;text-align:center}a{display:block;margin-top:20px;padding:14px 18px;border-radius:999px;background:#ffca58;color:#201700;text-decoration:none;font-weight:700}</style></head>
<body><main class="card"><h1>Ferventio</h1>{{if .Success}}<p>Авторизация Twitch завершена. Возвращаемся в приложение.</p>{{else}}<p>Авторизация не завершена. Вернись в приложение и повтори вход.</p>{{end}}<a href="{{.DeepLinkURL}}">Вернуться в Ferventio</a></main><script>window.location.replace({{.DeepLinkJS}});</script></body></html>`))
