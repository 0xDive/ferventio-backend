package application

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	websocketGUID          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxSocketMessageBytes  = 64 << 10
	defaultHeartbeatPeriod = 45 * time.Second
)

type pushSocketConnection struct {
	installationID string
	connectionID   string
	conn           net.Conn
	reader         *bufio.Reader
	writer         *bufio.Writer
	writeMu        sync.Mutex
	closed         chan struct{}
	closeOnce      sync.Once
}

func (c *pushSocketConnection) sendJSON(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.writeFrame(0x1, payload)
}

func (c *pushSocketConnection) writeFrame(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	first := byte(0x80) | opcode
	if err := c.writer.WriteByte(first); err != nil {
		return err
	}
	switch length := len(payload); {
	case length <= 125:
		if err := c.writer.WriteByte(byte(length)); err != nil {
			return err
		}
	case length <= 65535:
		if err := c.writer.WriteByte(126); err != nil {
			return err
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(length))
		if _, err := c.writer.Write(size[:]); err != nil {
			return err
		}
	default:
		if err := c.writer.WriteByte(127); err != nil {
			return err
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(length))
		if _, err := c.writer.Write(size[:]); err != nil {
			return err
		}
	}
	if _, err := c.writer.Write(payload); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *pushSocketConnection) readText() ([]byte, error) {
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(2 * defaultHeartbeatPeriod)); err != nil {
			return nil, err
		}
		first, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		second, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		fin := first&0x80 != 0
		opcode := first & 0x0f
		masked := second&0x80 != 0
		if !fin {
			return nil, errors.New("fragmented WebSocket frames are not supported")
		}
		if !masked {
			return nil, errors.New("client WebSocket frame is not masked")
		}
		length := uint64(second & 0x7f)
		switch length {
		case 126:
			var value [2]byte
			if _, err := io.ReadFull(c.reader, value[:]); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(value[:]))
		case 127:
			var value [8]byte
			if _, err := io.ReadFull(c.reader, value[:]); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(value[:])
		}
		if length > maxSocketMessageBytes {
			return nil, fmt.Errorf("WebSocket frame exceeds %d bytes", maxSocketMessageBytes)
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
			return nil, err
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return nil, err
		}
		for index := range payload {
			payload[index] ^= mask[index%4]
		}
		switch opcode {
		case 0x1:
			return payload, nil
		case 0x8:
			_ = c.writeFrame(0x8, payload)
			return nil, io.EOF
		case 0x9:
			if err := c.writeFrame(0xA, payload); err != nil {
				return nil, err
			}
		case 0xA:
			continue
		default:
			return nil, fmt.Errorf("unsupported WebSocket opcode %d", opcode)
		}
	}
}

func (c *pushSocketConnection) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

type PushHub struct {
	mu          sync.RWMutex
	connections map[string]*pushSocketConnection
}

func NewPushHub() *PushHub {
	return &PushHub{connections: map[string]*pushSocketConnection{}}
}

func (h *PushHub) Attach(connection *pushSocketConnection) {
	h.mu.Lock()
	previous := h.connections[connection.installationID]
	h.connections[connection.installationID] = connection
	h.mu.Unlock()
	if previous != nil && previous != connection {
		previous.close()
	}
}

func (h *PushHub) Detach(connection *pushSocketConnection) {
	h.mu.Lock()
	if h.connections[connection.installationID] == connection {
		delete(h.connections, connection.installationID)
	}
	h.mu.Unlock()
}

func (h *PushHub) Send(installationID string, message socketServerMessage) error {
	h.mu.RLock()
	connection := h.connections[installationID]
	h.mu.RUnlock()
	if connection == nil {
		return ErrNotFound
	}
	if err := connection.sendJSON(message); err != nil {
		connection.close()
		return err
	}
	return nil
}

func (h *PushHub) Close(installationID string) {
	h.mu.RLock()
	connection := h.connections[installationID]
	h.mu.RUnlock()
	if connection != nil {
		connection.close()
	}
}

func (s *Server) pushSocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradePushSocket(w, r)
	if err != nil {
		s.log.Warn("push WebSocket upgrade failed", "error", err)
		return
	}
	defer connection.close()

	registration, err := s.authenticatePushSocket(connection)
	if err != nil {
		_ = connection.sendJSON(socketServerMessage{Type: "error", Message: err.Error()})
		s.auditRecord(AuditRecord{Action: "push.socket.authenticate", Status: "rejected", Detail: err.Error()})
		return
	}
	s.hub.Attach(connection)
	s.auditRecord(AuditRecord{
		Action:         "push.socket.connect",
		Status:         "connected",
		InstallationID: registration.InstallationID,
		UserID:         registration.UserID,
	})
	defer func() {
		s.hub.Detach(connection)
		s.auditRecord(AuditRecord{
			Action:         "push.socket.disconnect",
			Status:         "disconnected",
			InstallationID: registration.InstallationID,
			UserID:         registration.UserID,
		})
	}()

	if err := connection.sendJSON(socketServerMessage{
		Type:                  "authenticated",
		ConnectionID:          connection.connectionID,
		HeartbeatSeconds:      int(defaultHeartbeatPeriod.Seconds()),
		ServerTimeEpochMillis: time.Now().UTC().UnixMilli(),
	}); err != nil {
		return
	}

	s.flushPending(connection.installationID)
	heartbeat := time.NewTicker(defaultHeartbeatPeriod)
	defer heartbeat.Stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			payload, err := connection.readText()
			if err != nil {
				return
			}
			var message socketClientMessage
			if err := json.Unmarshal(payload, &message); err != nil {
				_ = connection.sendJSON(socketServerMessage{Type: "error", Message: "invalid socket JSON"})
				continue
			}
			switch message.Type {
			case "ack":
				if message.EventID != "" {
					if err := s.deliveries.Ack(connection.installationID, message.EventID, time.Now().UTC()); err == nil {
						s.auditRecord(AuditRecord{
							Action:         "push.delivery.ack",
							Status:         "acked",
							InstallationID: connection.installationID,
							EventID:        message.EventID,
						})
					}
				}
			case "pong":
				// The read deadline is refreshed by every incoming frame.
			default:
				_ = connection.sendJSON(socketServerMessage{Type: "error", Message: "unsupported socket message"})
			}
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-connection.closed:
			return
		case <-done:
			return
		case <-heartbeat.C:
			if err := connection.sendJSON(socketServerMessage{
				Type:                  "heartbeat",
				ServerTimeEpochMillis: time.Now().UTC().UnixMilli(),
			}); err != nil {
				return
			}
			s.flushPending(connection.installationID)
		}
	}
}

func (s *Server) authenticatePushSocket(connection *pushSocketConnection) (Registration, error) {
	payload, err := connection.readText()
	if err != nil {
		return Registration{}, fmt.Errorf("read authentication: %w", err)
	}
	var message socketClientMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		return Registration{}, errors.New("invalid authentication JSON")
	}
	if err := validatePushSocketAuthentication(message); err != nil {
		return Registration{}, err
	}
	if err := validateMobileDevice(message.InstallationID, message.DeviceSecret); err != nil {
		return Registration{}, errors.New("push authentication failed")
	}
	decision := s.takeInstallationRateLimit(message.InstallationID, message.DeviceSecret)
	if !decision.Allowed {
		s.auditRateLimitBlock(
			decision,
			"installation",
			"WEBSOCKET",
			"/v1/push/socket",
			message.InstallationID,
			"",
		)
		retrySeconds := int(decision.RetryAfter.Round(time.Second).Seconds())
		if retrySeconds < 1 {
			retrySeconds = 1
		}
		return Registration{}, fmt.Errorf("push authentication rate limited; retry after %ds", retrySeconds)
	}
	registration, err := s.store.Authenticate(message.InstallationID, message.DeviceSecret)
	if err != nil {
		return Registration{}, errors.New("push authentication failed")
	}
	if registration.Provider != "embedded_socket" {
		return Registration{}, errors.New("push authentication failed")
	}
	connection.installationID = registration.InstallationID
	if message.LastEventID != "" {
		_ = s.deliveries.AckThrough(registration.InstallationID, message.LastEventID, time.Now().UTC())
	}
	return registration, nil
}

func validatePushSocketAuthentication(message socketClientMessage) error {
	if message.Type != "authenticate" {
		return errors.New("unsupported push protocol")
	}
	protocolVersion := message.ProtocolVersion
	if protocolVersion == 0 {
		// Ferventio 0.9.5 and 0.9.5.1 used kotlinx.serialization with
		// encodeDefaults=false, so protocolVersion=1 was omitted from JSON.
		// Treat a missing version as the original protocol version for backward
		// compatibility. Authentication still requires the device secret.
		protocolVersion = 1
	}
	if protocolVersion != 1 {
		return errors.New("unsupported push protocol")
	}
	return nil
}

func upgradePushSocket(w http.ResponseWriter, r *http.Request) (*pushSocketConnection, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerContainsToken(r.Header.Get("Connection"), "upgrade") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		writeError(w, http.StatusUpgradeRequired, "WebSocket upgrade required")
		return nil, errors.New("invalid WebSocket upgrade headers")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing Sec-WebSocket-Key")
		return nil, errors.New("missing WebSocket key")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "WebSocket is not supported")
		return nil, errors.New("HTTP writer does not support hijacking")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	acceptHash := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptHash[:])
	if _, err := fmt.Fprintf(
		rw,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	connectionID, err := randomSocketID()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &pushSocketConnection{
		connectionID: connectionID,
		conn:         conn,
		reader:       rw.Reader,
		writer:       rw.Writer,
		closed:       make(chan struct{}),
	}, nil
}

func headerContainsToken(value, token string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return true
		}
	}
	return false
}

func randomSocketID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "psc_" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (s *Server) flushPending(installationID string) {
	lock := s.installationFlushLock(installationID)
	lock.Lock()
	defer lock.Unlock()

	registration, err := s.store.Get(installationID)
	if err != nil {
		return
	}
	for _, record := range s.deliveries.PendingForInstallation(installationID, 100, time.Now().UTC()) {
		payload := record.Notification
		payload.EventID = record.EventID
		if registration.Provider == "embedded_socket" {
			err = s.hub.Send(installationID, socketServerMessage{
				Type:    "notification",
				EventID: record.EventID,
				Payload: &payload,
			})
			if err != nil {
				if !errors.Is(err, ErrNotFound) {
					_ = s.deliveries.MarkFailed(record.ID, err, time.Now().UTC())
				}
				return
			}
			_ = s.deliveries.MarkSent(record.ID, time.Now().UTC())
			continue
		}

		if s.sender == nil {
			err = errors.New("push sender is not configured")
		} else {
			sendContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err = s.sender.Send(sendContext, registration, payload)
			cancel()
		}
		if err != nil {
			_ = s.deliveries.MarkFailed(record.ID, err, time.Now().UTC())
			s.auditRecord(AuditRecord{
				Action:         "push.delivery.send",
				Status:         "failed",
				InstallationID: registration.InstallationID,
				UserID:         registration.UserID,
				ChannelID:      payload.ChannelID,
				EventID:        payload.EventID,
				Detail:         err.Error(),
			})
			continue
		}
		sentAt := time.Now().UTC()
		_ = s.deliveries.MarkSent(record.ID, sentAt)
		_ = s.deliveries.Ack(registration.InstallationID, record.EventID, sentAt)
		s.auditRecord(AuditRecord{
			Action:         "push.delivery.send",
			Status:         "acked",
			InstallationID: registration.InstallationID,
			UserID:         registration.UserID,
			ChannelID:      payload.ChannelID,
			EventID:        payload.EventID,
			Detail:         payload.Type,
		})
	}
}

func (s *Server) runDeliveryWorker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, registration := range s.store.List() {
				s.flushPending(registration.InstallationID)
			}
			_ = s.deliveries.Cleanup(time.Now().UTC())
		}
	}
}
