package application

import "testing"

func TestValidatePushSocketAuthenticationAcceptsExplicitVersion(t *testing.T) {
	err := validatePushSocketAuthentication(socketClientMessage{
		Type:            "authenticate",
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("validatePushSocketAuthentication() error = %v", err)
	}
}

func TestValidatePushSocketAuthenticationAcceptsLegacyMissingVersion(t *testing.T) {
	err := validatePushSocketAuthentication(socketClientMessage{Type: "authenticate"})
	if err != nil {
		t.Fatalf("validatePushSocketAuthentication() error = %v", err)
	}
}

func TestValidatePushSocketAuthenticationRejectsUnknownVersion(t *testing.T) {
	err := validatePushSocketAuthentication(socketClientMessage{
		Type:            "authenticate",
		ProtocolVersion: 2,
	})
	if err == nil {
		t.Fatal("validatePushSocketAuthentication() error = nil, want rejection")
	}
}

func TestValidatePushSocketAuthenticationRejectsWrongMessageType(t *testing.T) {
	err := validatePushSocketAuthentication(socketClientMessage{
		Type:            "pong",
		ProtocolVersion: 1,
	})
	if err == nil {
		t.Fatal("validatePushSocketAuthentication() error = nil, want rejection")
	}
}
