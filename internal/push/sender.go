package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/domain"
)

type Sender struct {
	firebaseClient  *messaging.Client
	apns            *apnsSender
	vapidPublicKey  string
	vapidPrivateKey string
	vapidSubscriber string
}

func NewSender(ctx context.Context, cfg config.Config) (*Sender, error) {
	sender := &Sender{
		vapidPublicKey:  cfg.VAPIDPublicKey,
		vapidPrivateKey: cfg.VAPIDPrivateKey,
		vapidSubscriber: cfg.VAPIDSubscriber,
	}
	if cfg.FirebaseMessagingEnabled() {
		firebaseApp, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: cfg.FirebaseProjectID})
		if err != nil {
			return nil, fmt.Errorf("initialize Firebase Admin SDK: %w", err)
		}
		client, err := firebaseApp.Messaging(ctx)
		if err != nil {
			return nil, fmt.Errorf("initialize Firebase Messaging client: %w", err)
		}
		sender.firebaseClient = client
	}

	apnsConfig, err := config.LoadAPNsConfig()
	if err != nil {
		return nil, fmt.Errorf("load APNs configuration: %w", err)
	}
	apns, err := newAPNsSender(apnsConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize APNs sender: %w", err)
	}
	sender.apns = apns
	return sender, nil
}

func (s *Sender) Send(ctx context.Context, registration domain.Registration, notification domain.Notification) error {
	if registration.Provider == "apns" {
		if s.apns == nil {
			return errors.New("APNs is not configured on the server")
		}
		return s.apns.Send(ctx, registration.APNsDeviceToken, notification)
	}

	payload, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("encode notification: %w", err)
	}

	switch registration.Provider {
	case "fcm":
		return s.sendFCM(ctx, registration.FirebaseInstallation, payload)
	case "unifiedpush":
		return s.sendUnifiedPush(registration, payload)
	default:
		return fmt.Errorf("unsupported provider %q", registration.Provider)
	}
}

func (s *Sender) sendFCM(ctx context.Context, fid string, payload []byte) error {
	if s.firebaseClient == nil {
		return errors.New("FCM is not configured on the server")
	}
	if fid == "" {
		return errors.New("Firebase installation ID is empty")
	}
	_, err := s.firebaseClient.Send(ctx, &messaging.Message{
		Data: map[string]string{"payload": string(payload)},
		Fid:  fid,
		Android: &messaging.AndroidConfig{
			Priority: "high",
		},
	})
	if err != nil {
		return fmt.Errorf("send FCM message: %w", err)
	}
	return nil
}

func (s *Sender) sendUnifiedPush(registration domain.Registration, payload []byte) error {
	if s.vapidPublicKey == "" || s.vapidPrivateKey == "" {
		return errors.New("VAPID is not configured on the server")
	}
	if registration.Endpoint == "" || registration.P256DH == "" || registration.Auth == "" {
		return errors.New("UnifiedPush Web Push subscription is incomplete")
	}

	response, err := webpush.SendNotification(payload, &webpush.Subscription{
		Endpoint: registration.Endpoint,
		Keys: webpush.Keys{
			P256dh: registration.P256DH,
			Auth:   registration.Auth,
		},
	}, &webpush.Options{
		Subscriber:      s.vapidSubscriber,
		VAPIDPublicKey:  s.vapidPublicKey,
		VAPIDPrivateKey: s.vapidPrivateKey,
		TTL:             60,
	})
	if err != nil {
		return fmt.Errorf("send UnifiedPush message: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("UnifiedPush endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
