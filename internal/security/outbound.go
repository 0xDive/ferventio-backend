package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var disallowedPublicEndpointPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// ValidatePublicHTTPSURL validates the static parts of an outbound URL.
// Hostname resolution is checked again at dial time by NewPublicHTTPSClient.
func ValidatePublicHTTPSURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("URL must be absolute HTTPS")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must not contain credentials or a fragment")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return errors.New("URL host is required")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !isPublicOutboundAddr(address.Unmap()) {
			return errors.New("URL host is not a public address")
		}
	}
	return nil
}

// NewPublicHTTPSClient returns a client that disables proxy inheritance, validates
// every redirect, resolves hostnames itself, rejects non-public answers, and dials
// the exact IP address that was validated to prevent DNS-rebinding bypasses.
func NewPublicHTTPSClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   minDuration(timeout, 10*time.Second),
		KeepAlive: 30 * time.Second,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split outbound address: %w", err)
		}
		candidates, err := resolvePublicOutboundAddrs(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, candidate := range candidates {
			if strings.HasSuffix(network, "4") && !candidate.Is4() {
				continue
			}
			if strings.HasSuffix(network, "6") && !candidate.Is6() {
				continue
			}
			connection, dialErr := dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(candidate.String(), port),
			)
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("no compatible public address was resolved")
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many outbound redirects")
			}
			if err := ValidatePublicHTTPSURL(request.URL.String()); err != nil {
				return fmt.Errorf("redirect target rejected: %w", err)
			}
			return nil
		},
	}
}

func resolvePublicOutboundAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !isPublicOutboundAddr(address) {
			return nil, errors.New("outbound address is not public")
		}
		return []netip.Addr{address}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("outbound host did not resolve")
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !isPublicOutboundAddr(address) {
			return nil, fmt.Errorf("outbound host resolved to disallowed address %s", address)
		}
		result = append(result, address)
	}
	return result, nil
}

func isPublicOutboundAddr(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() ||
		address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range disallowedPublicEndpointPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
