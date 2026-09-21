package application

import (
	"strings"
	"testing"
)

func TestValidateRegistration(t *testing.T) {
	strongSecret := strings.Repeat("s", 48)
	tests := []struct {
		name         string
		registration Registration
		wantError    bool
	}{
		{
			name: "android fcm",
			registration: Registration{
				InstallationID:       "installation",
				DeviceSecret:         strongSecret,
				Provider:             "fcm",
				FirebaseInstallation: "fid",
				Platform:             "android",
			},
		},
		{
			name: "android unifiedpush",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   strongSecret,
				Provider:       "unifiedpush",
				Endpoint:       "https://push.example/endpoint",
				P256DH:         "public-key",
				Auth:           "auth-secret",
				Platform:       "android",
			},
		},
		{
			name: "ios apns",
			registration: Registration{
				InstallationID:  "installation",
				DeviceSecret:    strongSecret,
				Provider:        "apns",
				APNsDeviceToken: "0123456789abcdef",
				Platform:        "ios",
			},
		},
		{
			name: "weak device secret",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   "short",
				Provider:       "embedded_socket",
				Platform:       "android",
			},
			wantError: true,
		},
		{
			name: "missing fcm fid",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   strongSecret,
				Provider:       "fcm",
				Platform:       "android",
			},
			wantError: true,
		},
		{
			name: "missing apns token",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   strongSecret,
				Provider:       "apns",
				Platform:       "ios",
			},
			wantError: true,
		},
		{
			name: "apns cannot claim android",
			registration: Registration{
				InstallationID:  "installation",
				DeviceSecret:    strongSecret,
				Provider:        "apns",
				APNsDeviceToken: "token",
				Platform:        "android",
			},
			wantError: true,
		},
		{
			name: "fcm cannot claim ios",
			registration: Registration{
				InstallationID:       "installation",
				DeviceSecret:         strongSecret,
				Provider:             "fcm",
				FirebaseInstallation: "fid",
				Platform:             "ios",
			},
			wantError: true,
		},
		{
			name: "unsupported platform",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   strongSecret,
				Provider:       "embedded_socket",
				Platform:       "desktop",
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRegistration(test.registration)
			if (err != nil) != test.wantError {
				t.Fatalf("validateRegistration() error = %v, wantError = %v", err, test.wantError)
			}
		})
	}
}

func TestNormalizeRegistrationDefaultsMissingPlatformToAndroid(t *testing.T) {
	registration := Registration{}
	normalizeRegistration(&registration)
	if registration.Platform != "android" {
		t.Fatalf("Platform = %q, want android", registration.Platform)
	}
}

func TestNormalizeRegistrationCanonicalizesTransport(t *testing.T) {
	registration := Registration{
		Platform:        " IOS ",
		Provider:        " APNS ",
		APNsDeviceToken: "  0123ABCD  ",
	}
	normalizeRegistration(&registration)
	if registration.Platform != "ios" {
		t.Fatalf("Platform = %q, want ios", registration.Platform)
	}
	if registration.Provider != "apns" {
		t.Fatalf("Provider = %q, want apns", registration.Provider)
	}
	if registration.APNsDeviceToken != "0123ABCD" {
		t.Fatalf("APNsDeviceToken = %q", registration.APNsDeviceToken)
	}
}

func TestNormalizeNotificationChannelRulesKeepsOnlyRegisteredChannels(t *testing.T) {
	got := normalizeNotificationChannelRules(
		map[string][]string{
			" channel-1 ": {"reply", " reply ", "automod_hold"},
			"other":       {"mention"},
		},
		[]string{"channel-1", "channel-2"},
	)
	if len(got) != 1 {
		t.Fatalf("rules = %#v, want one channel", got)
	}
	want := []string{"reply", "automod_hold"}
	if current := got["channel-1"]; len(current) != len(want) ||
		current[0] != want[0] || current[1] != want[1] {
		t.Fatalf("channel-1 rules = %#v, want %#v", current, want)
	}
}

func TestNormalizeNotificationChannelMutesKeepsOnlyRegisteredPositiveValues(t *testing.T) {
	got := normalizeNotificationChannelMutedUntilEpochMillis(
		map[string]int64{
			" channel-1 ": 12345,
			"channel-2":   0,
			"other":       99999,
		},
		[]string{"channel-1", "channel-2"},
	)
	if len(got) != 1 || got["channel-1"] != 12345 {
		t.Fatalf("mutes = %#v, want channel-1 only", got)
	}
}
