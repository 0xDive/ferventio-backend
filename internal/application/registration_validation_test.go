package application

import "testing"

func TestValidateRegistration(t *testing.T) {
	tests := []struct {
		name         string
		registration Registration
		wantError    bool
	}{
		{
			name: "fcm",
			registration: Registration{
				InstallationID:       "installation",
				DeviceSecret:         "secret",
				Provider:             "fcm",
				FirebaseInstallation: "fid",
				Platform:             "android",
			},
		},
		{
			name: "unifiedpush",
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
			name: "missing fcm fid",
			registration: Registration{
				InstallationID: "installation",
				DeviceSecret:   "secret",
				Provider:       "fcm",
				Platform:       "android",
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

func TestNormalizeRegistrationCanonicalizesAndroidPlatform(t *testing.T) {
	registration := Registration{Platform: " Android "}
	normalizeRegistration(&registration)
	if registration.Platform != "android" {
		t.Fatalf("Platform = %q, want android", registration.Platform)
	}
}
