package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/domain"
)

const (
	apnsProductionEndpoint = "https://api.push.apple.com"
	apnsSandboxEndpoint    = "https://api.sandbox.push.apple.com"
	apnsMaximumPayloadSize = 4_096
	apnsTokenRefreshAge    = 50 * time.Minute
)

type apnsSender struct {
	teamID      string
	keyID       string
	bundleID    string
	privateKey  *ecdsa.PrivateKey
	endpoint    string
	client      *http.Client
	now         func() time.Time
	tokenMu     sync.Mutex
	cachedToken string
	tokenIssued time.Time
}

type apnsPayload struct {
	APS       apnsAPS             `json:"aps"`
	Ferventio domain.Notification `json:"ferventio"`
}

type apnsAPS struct {
	Alert            *apnsAlert `json:"alert,omitempty"`
	Sound            string     `json:"sound,omitempty"`
	ContentAvailable int        `json:"content-available,omitempty"`
}

type apnsAlert struct {
	Title string `json:"title,omitempty"`
	Body  string `json:"body"`
}

type apnsErrorResponse struct {
	Reason string `json:"reason"`
}

func newAPNsSender(cfg config.APNsConfig) (*apnsSender, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	privateKey, err := parseAPNsPrivateKey(cfg.PrivateKeyBase64)
	if err != nil {
		return nil, err
	}
	endpoint := apnsProductionEndpoint
	if cfg.Environment == config.APNsEnvironmentSandbox {
		endpoint = apnsSandboxEndpoint
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &apnsSender{
		teamID:     cfg.TeamID,
		keyID:      cfg.KeyID,
		bundleID:   cfg.BundleID,
		privateKey: privateKey,
		endpoint:   endpoint,
		client: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
		},
		now: time.Now,
	}, nil
}

func parseAPNsPrivateKey(encoded string) (*ecdsa.PrivateKey, error) {
	contents, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode APNs private key: %w", err)
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("APNs private key must contain exactly one PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse APNs private key: %w", err)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve.Params().Name != "P-256" {
		return nil, errors.New("APNs private key must be an ECDSA P-256 key")
	}
	return privateKey, nil
}

func (s *apnsSender) Send(
	ctx context.Context,
	deviceToken string,
	notification domain.Notification,
) error {
	deviceToken = strings.TrimSpace(deviceToken)
	if deviceToken == "" {
		return errors.New("APNs device token is empty")
	}
	payload, pushType, priority, err := makeAPNsPayload(notification)
	if err != nil {
		return err
	}
	return s.send(ctx, deviceToken, payload, pushType, priority, true)
}

func makeAPNsPayload(notification domain.Notification) ([]byte, string, string, error) {
	aps := apnsAPS{}
	pushType := "alert"
	priority := "10"
	if notification.Silent {
		aps.ContentAvailable = 1
		pushType = "background"
		priority = "5"
	} else {
		aps.Alert = &apnsAlert{Title: notification.Title, Body: notification.Body}
		aps.Sound = "default"
	}
	payload, err := json.Marshal(apnsPayload{APS: aps, Ferventio: notification})
	if err != nil {
		return nil, "", "", fmt.Errorf("encode APNs payload: %w", err)
	}
	if len(payload) > apnsMaximumPayloadSize {
		return nil, "", "", fmt.Errorf("APNs payload exceeds %d bytes", apnsMaximumPayloadSize)
	}
	return payload, pushType, priority, nil
}

func (s *apnsSender) send(
	ctx context.Context,
	deviceToken string,
	payload []byte,
	pushType string,
	priority string,
	allowTokenRefresh bool,
) error {
	providerToken, err := s.providerToken(false)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(s.endpoint, "/") + "/3/device/" + url.PathEscape(deviceToken)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create APNs request: %w", err)
	}
	request.Header.Set("Authorization", "bearer "+providerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("apns-topic", s.bundleID)
	request.Header.Set("apns-push-type", pushType)
	request.Header.Set("apns-priority", priority)

	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("send APNs request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	var failure apnsErrorResponse
	_ = json.Unmarshal(body, &failure)
	if allowTokenRefresh && response.StatusCode == http.StatusForbidden && failure.Reason == "ExpiredProviderToken" {
		if _, err := s.providerToken(true); err != nil {
			return err
		}
		return s.send(ctx, deviceToken, payload, pushType, priority, false)
	}
	if failure.Reason == "" {
		failure.Reason = strings.TrimSpace(string(body))
	}
	if failure.Reason == "" {
		failure.Reason = http.StatusText(response.StatusCode)
	}
	return fmt.Errorf("APNs returned HTTP %d: %s", response.StatusCode, failure.Reason)
}

func (s *apnsSender) providerToken(force bool) (string, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	now := s.now().UTC()
	if !force && s.cachedToken != "" && now.Sub(s.tokenIssued) < apnsTokenRefreshAge {
		return s.cachedToken, nil
	}
	token, err := makeAPNsProviderToken(s.privateKey, s.keyID, s.teamID, now)
	if err != nil {
		return "", err
	}
	s.cachedToken = token
	s.tokenIssued = now
	return token, nil
}

func makeAPNsProviderToken(
	privateKey *ecdsa.PrivateKey,
	keyID string,
	teamID string,
	now time.Time,
) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": teamID, "iat": now.Unix()})
	if err != nil {
		return "", err
	}
	encoder := base64.RawURLEncoding
	unsigned := encoder.EncodeToString(header) + "." + encoder.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign APNs provider token: %w", err)
	}
	fieldBytes := (privateKey.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, fieldBytes*2)
	r.FillBytes(signature[:fieldBytes])
	signatureS.FillBytes(signature[fieldBytes:])
	return unsigned + "." + encoder.EncodeToString(signature), nil
}
