package console

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Origin checks intentionally ignore Forwarded and X-Forwarded-* headers.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if len(r.Header.Values("Origin")) > 1 || origin == "null" {
		return false
	}
	if origin == "" {
		if referer := r.Header.Get("Referer"); referer != "" {
			parsed, err := url.Parse(referer)
			if err != nil {
				return false
			}
			parsed.Path, parsed.RawPath, parsed.RawQuery, parsed.Fragment = "", "", "", ""
			origin = parsed.String()
		} else if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
			return true
		} else {
			return false
		}
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	request, err := url.Parse(scheme + "://" + r.Host)
	if err != nil || request.Host == "" || request.Path != "" || request.User != nil {
		return false
	}
	return parsed.Scheme == scheme &&
		sameOriginHost(parsed.Hostname(), request.Hostname()) &&
		effectivePort(parsed.Scheme, parsed.Port()) == effectivePort(scheme, request.Port())
}

func sameOriginHost(a, b string) bool {
	if loopbackHost(a) && loopbackHost(b) {
		return true
	}
	left, leftErr := netip.ParseAddr(a)
	right, rightErr := netip.ParseAddr(b)
	if leftErr == nil && rightErr == nil {
		return left.Unmap() == right.Unmap()
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func effectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		return parsed.Unmap().String()
	}
	return host
}
