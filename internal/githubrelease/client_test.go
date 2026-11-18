package githubrelease

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestUpdateGitHubHTTPSAndPublicDNSGuards(t *testing.T) {
	for _, raw := range []string{"http://github.com/a", "https://api.github.com.evil.test/a", "https://127.0.0.1/a", "https://github.com:8443/a", "https://user:password@github.com/a", "https://github.com/a#fragment"} {
		if _, err := updateGitHubURL(raw); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.0.2.8", "198.18.0.1", "::1", "fd00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:0a00:0001::1", "2001::1"} {
		if updatePublicIP(netip.MustParseAddr(address)) {
			t.Fatal("nonpublic outbound address accepted")
		}
	}
	for _, address := range []string{"8.8.8.8", "2606:4700::1111", "2001:4860:4860::8888"} {
		if !updatePublicIP(netip.MustParseAddr(address)) {
			t.Fatal("public IPv4/IPv6 was rejected")
		}
	}
	for _, addresses := range [][]netip.Addr{{netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}} {
		called := false
		dialer := updatePublicDialer{lookup: func(context.Context, string) ([]netip.Addr, error) { return addresses, nil }, dial: func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }}
		if _, err := dialer.DialContext(context.Background(), "tcp", "api.github.com:443"); err == nil || called {
			t.Fatal("private or mixed DNS reached dial")
		}
	}
	dialed := ""
	dialer := updatePublicDialer{lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return nil, nil
	}}
	if _, err := dialer.DialContext(context.Background(), "tcp", "api.github.com:443"); err != nil || dialed != "8.8.8.8:443" {
		t.Fatal("resolved address was not pinned")
	}
}
