package application

import "testing"

func TestValidateRegistration(t *testing.T) {
	tests := []struct {
		name         string
		registration Registration
		wantError    bool
	}{
		{
			name: "android fcm",
			registration: Registration{
				InstallationID:       "installation",
				DeviceSecret:         "secret",
				Provider:             "fcm",
				FirebaseInstallation: "fid",
				Platform:             "android",
			},
		},
		{
			name: "android unifiedpush",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   "secret",
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
				DeviceSecret:    "secret",
				Provider:        "apns",
				APNsDeviceToken: "0123456789abcdef",
				Platform:        "ios",
			},
		},
		{
			name: "missing fcm fid",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   "secret",
				Provider:       "fcm",
				Platform:       "android",
			},
			wantError: true,
		},
		{
			name: "missing apns token",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   "secret",
				Provider:       "apns",
				Platform:       "ios",
			},
			wantError: true,
		},
		{
			name: "apns cannot claim android",
			registration: Registration{
				InstallationID:  "installation",
				DeviceSecret:    "secret",
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
				DeviceSecret:         "secret",
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
				DeviceSecret:   "secret",
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
