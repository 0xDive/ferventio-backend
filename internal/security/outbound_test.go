package security

import (
	"net/netip"
	"testing"
)

func TestValidatePublicHTTPSURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "public https hostname", raw: "https://push.example.com/message"},
		{name: "public literal", raw: "https://1.1.1.1/push"},
		{name: "http rejected", raw: "http://push.example.com/message", wantErr: true},
		{name: "credentials rejected", raw: "https://user:pass@push.example.com/message", wantErr: true},
		{name: "loopback rejected", raw: "https://127.0.0.1/admin", wantErr: true},
		{name: "private rejected", raw: "https://10.0.0.1/admin", wantErr: true},
		{name: "metadata rejected", raw: "https://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "cgnat rejected", raw: "https://100.64.0.1/push", wantErr: true},
		{name: "ipv6 private rejected", raw: "https://[fd00::1]/push", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePublicHTTPSURL(test.raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidatePublicHTTPSURL(%q) error=%v wantErr=%t", test.raw, err, test.wantErr)
			}
		})
	}
}

func TestPublicOutboundAddressPolicy(t *testing.T) {
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !isPublicOutboundAddr(netip.MustParseAddr(raw)) {
			t.Fatalf("expected %s to be allowed", raw)
		}
	}
	for _, raw := range []string{
		"0.1.2.3",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"::1",
		"fd00::1",
		"64:ff9b::7f00:1",
		"2002:7f00:1::",
		"2001::1",
		"fec0::1",
	} {
		if isPublicOutboundAddr(netip.MustParseAddr(raw)) {
			t.Fatalf("expected %s to be rejected", raw)
		}
	}
}
