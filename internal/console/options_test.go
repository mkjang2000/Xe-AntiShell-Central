package console

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyOptionsValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options Options
		valid   bool
	}{
		{"native defaults", Options{}, true},
		{"public loopback proxy", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"127.0.0.1/32", "::1/128"}}, true},
		{"public custom proxy", Options{PublicOrigin: "https://console.example:8443", TrustedProxies: []string{"192.0.2.0/24"}}, true},
		{"IPv6 public origin", Options{PublicOrigin: "https://[2001:db8::1]:8443", TrustedProxies: []string{"::1/128"}}, true},
		{"proxies without origin", Options{PublicOrigin: "", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"origin without proxies", Options{PublicOrigin: "https://console.example"}, false},
		{"empty proxy", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{""}}, false},
		{"IP without prefix", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"127.0.0.1"}}, false},
		{"hostname proxy", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"localhost/32"}}, false},
		{"invalid prefix", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"127.0.0.1/33"}}, false},
		{"all IPv4 peers", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"0.0.0.0/0"}}, false},
		{"all IPv6 peers", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"::/0"}}, false},
		{"all mapped IPv4 peers", Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"::ffff:0.0.0.0/96"}}, false},
		{"HTTP origin", Options{PublicOrigin: "http://console.example", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"scheme only", Options{PublicOrigin: "https:", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"missing scheme", Options{PublicOrigin: "console.example", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"missing host", Options{PublicOrigin: "https://", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"opaque origin", Options{PublicOrigin: "https:console.example", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"credentials", Options{PublicOrigin: "https://user:password@console.example", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"path", Options{PublicOrigin: "https://console.example/login", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"trailing slash", Options{PublicOrigin: "https://console.example/", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"query", Options{PublicOrigin: "https://console.example?x=1", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"empty query", Options{PublicOrigin: "https://console.example?", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"fragment", Options{PublicOrigin: "https://console.example#login", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"empty fragment", Options{PublicOrigin: "https://console.example#", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"bad port", Options{PublicOrigin: "https://console.example:abc", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"empty port", Options{PublicOrigin: "https://console.example:", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"zero port", Options{PublicOrigin: "https://console.example:0", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"out of range port", Options{PublicOrigin: "https://console.example:65536", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"noncanonical port", Options{PublicOrigin: "https://console.example:0443", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"unbracketed IPv6", Options{PublicOrigin: "https://2001:db8::1", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"bracketed hostname", Options{PublicOrigin: "https://[console.example]", TrustedProxies: []string{"127.0.0.1/32"}}, false},
		{"IPv6 zone", Options{PublicOrigin: "https://[fe80::1%25eth0]", TrustedProxies: []string{"127.0.0.1/32"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.options.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() error=%v, valid=%v", err, tc.valid)
			}
		})
	}
	if _, err := NewWithOptions(testCredentials(t), http.NotFoundHandler(), nil, Options{PublicOrigin: "http://console.example"}); err == nil {
		t.Fatal("constructor accepted invalid options")
	}
}

func TestProxyOriginUsesRealPeerAndPublicHost(t *testing.T) {
	policy, err := (Options{PublicOrigin: "https://console.example", TrustedProxies: []string{"127.0.0.1/32", "::1/128"}}).originPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, host, peer, origin, referer, site string
		tls, allowed, secure                    bool
	}{
		{"trusted IPv4", "console.example", "127.0.0.1:4567", "https://console.example", "", "", false, true, true},
		{"trusted IPv6", "console.example", "[::1]:4567", "https://console.example", "", "", false, true, true},
		{"mapped IPv4 peer", "console.example", "[::ffff:127.0.0.1]:4567", "https://console.example", "", "", false, true, true},
		{"default port authority", "CONSOLE.example:443", "127.0.0.1:4567", "https://console.example", "", "", false, true, true},
		{"referer fallback", "console.example", "127.0.0.1:4567", "", "https://console.example/path?x=1", "", false, true, true},
		{"fetch fallback", "console.example", "127.0.0.1:4567", "", "", "same-origin", false, true, true},
		{"untrusted peer", "console.example", "192.0.2.1:4567", "https://console.example", "", "", false, false, false},
		{"other loopback address", "console.example", "127.0.0.2:4567", "https://console.example", "", "", false, false, false},
		{"malformed peer", "console.example", "127.0.0.1", "https://console.example", "", "", false, false, false},
		{"hostname peer", "console.example", "localhost:4567", "https://console.example", "", "", false, false, false},
		{"host override", "127.0.0.1:9089", "127.0.0.1:4567", "https://console.example", "", "", false, false, false},
		{"foreign host", "evil.example", "127.0.0.1:4567", "https://console.example", "", "", false, false, false},
		{"wrong host port", "console.example:9089", "127.0.0.1:4567", "https://console.example", "", "", false, false, false},
		{"invalid host suffix", "console.example#", "127.0.0.1:4567", "https://console.example", "", "", false, false, false},
		{"wrong origin port", "console.example", "127.0.0.1:4567", "https://console.example:9089", "", "", false, false, true},
		{"HTTP public origin", "console.example", "127.0.0.1:4567", "http://console.example", "", "", false, false, true},
		{"foreign origin", "console.example", "127.0.0.1:4567", "https://evil.example", "", "", false, false, true},
		{"null origin", "console.example", "127.0.0.1:4567", "null", "", "", false, false, true},
		{"missing origin", "console.example", "127.0.0.1:4567", "", "", "", false, false, true},
		{"cross site", "console.example", "127.0.0.1:4567", "https://console.example", "", "cross-site", false, false, true},
		{"direct local HTTP", "127.0.0.1:9089", "127.0.0.1:4567", "http://localhost:9089", "", "", false, true, false},
		{"direct local TLS", "127.0.0.1:9089", "127.0.0.1:4567", "https://localhost:9089", "", "", true, true, true},
		{"untrusted native TLS", "console.example", "192.0.2.1:4567", "https://console.example", "", "", true, true, true},
		{"untrusted native HTTP", "console.example", "192.0.2.1:4567", "http://console.example", "", "", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://console.example/login", nil)
			r.Host, r.RemoteAddr = tc.host, tc.peer
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Referer", tc.referer)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			r.Header.Set("Forwarded", "for=127.0.0.1;proto=https;host=console.example")
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "console.example")
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			r.Header.Set("CF-Connecting-IP", "127.0.0.1")
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := policy.sameOrigin(r); got != tc.allowed {
				t.Fatalf("sameOrigin=%v, expected=%v", got, tc.allowed)
			}
			if got := policy.secure(r); got != tc.secure {
				t.Fatalf("secure=%v, expected=%v", got, tc.secure)
			}
		})
	}
	r := httptest.NewRequest(http.MethodPost, "http://console.example/login", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Add("Origin", "https://console.example")
	r.Header.Add("Origin", "https://evil.example")
	if policy.sameOrigin(r) {
		t.Fatal("multiple origins accepted")
	}
}
