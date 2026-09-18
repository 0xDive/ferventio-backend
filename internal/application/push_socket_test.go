package application

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

func TestReadTextRejectsOversizedControlFrame(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	connection := &pushSocketConnection{
		conn:   serverConn,
		reader: bufio.NewReader(serverConn),
		writer: bufio.NewWriter(serverConn),
		closed: make(chan struct{}),
	}
	go func() {
		_, _ = clientConn.Write([]byte{0x89, 0xfe, 0x00, 0x7e})
	}()
	_, err := connection.readTextWithDeadline(time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "control frame exceeds 125 bytes") {
		t.Fatalf("oversized control frame error = %v", err)
	}
}

func TestPreAuthPingDoesNotExtendAbsoluteDeadline(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	connection := &pushSocketConnection{
		conn:   serverConn,
		reader: bufio.NewReader(serverConn),
		writer: bufio.NewWriter(serverConn),
		closed: make(chan struct{}),
	}

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = clientConn.SetDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := clientConn.Write([]byte{0x89, 0x80, 1, 2, 3, 4}); err != nil {
				return
			}
			var pong [2]byte
			if _, err := io.ReadFull(clientConn, pong[:]); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	defer close(stop)

	started := time.Now()
	watchdog := time.AfterFunc(500*time.Millisecond, func() { _ = serverConn.Close() })
	defer watchdog.Stop()
	_, err := connection.readTextWithDeadline(started.Add(120 * time.Millisecond))
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("pre-auth socket unexpectedly returned a text frame")
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("ping frames extended pre-auth deadline: elapsed=%s error=%v", elapsed, err)
	}
}

func TestPushSocketRejectsWhenPreAuthCapacityIsFull(t *testing.T) {
	server := &Server{
		preAuthSockets: make(chan struct{}, 1),
		log:            newDiscardLogger(),
	}
	server.preAuthSockets <- struct{}{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/push/socket", nil)
	server.pushSocket(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
