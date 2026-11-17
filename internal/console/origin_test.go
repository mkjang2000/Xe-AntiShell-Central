package console

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, origin, referer, site string
		tls, allowed                bool
	}{
		{"same", "http://127.0.0.1:9090", "", "", false, true},
		{"localhost alias", "http://localhost:9090", "", "", false, true},
		{"IPv6 alias", "http://[::1]:9090", "", "", false, true},
		{"TLS", "https://localhost:9090", "", "", true, true},
		{"referer fallback", "", "http://localhost:9090/path?query=x", "", false, true},
		{"fetch fallback", "", "", "same-origin", false, true},
		{"missing", "", "", "", false, false},
		{"null", "null", "", "", false, false},
		{"wrong scheme", "https://localhost:9090", "", "", false, false},
		{"wrong port", "http://localhost:9091", "", "", false, false},
		{"foreign", "http://evil.example:9090", "", "", false, false},
		{"path", "http://localhost:9090/path", "", "", false, false},
		{"userinfo", "http://user@localhost:9090", "", "", false, false},
		{"cross site hint", "http://localhost:9090", "", "cross-site", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/login", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Referer", tc.referer)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "evil.example:9090")
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := sameOrigin(r); got != tc.allowed {
				t.Fatalf("sameOrigin=%v expected=%v", got, tc.allowed)
			}
		})
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/login", nil)
	r.Header.Add("Origin", "http://localhost:9090")
	r.Header.Add("Origin", "http://evil.example")
	if sameOrigin(r) {
		t.Fatal("multiple origins were accepted")
	}
}
