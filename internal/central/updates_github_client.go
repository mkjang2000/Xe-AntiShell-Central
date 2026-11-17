package central

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const updateGitHubRepository = "mkjang2000/Xe-AntiShell"
const updateGitHubAPI = "https://api.github.com/repos/" + updateGitHubRepository + "/releases"

var errUpdateGitHub = errors.New("public release source unavailable")
var updateGitHubHosts = map[string]bool{"api.github.com": true, "github.com": true, "release-assets.githubusercontent.com": true, "objects.githubusercontent.com": true}
var updateNonPublicRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}
var updatePublicIPv6 = netip.MustParsePrefix("2000::/3")

func updatePublicIP(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	// Public GitHub destinations need neither NAT64/translation addresses nor
	// transition mechanisms that can encode a private IPv4 destination.
	if ip.Is6() && !updatePublicIPv6.Contains(ip) {
		return false
	}
	for _, prefix := range updateNonPublicRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
func updateGitHubURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || !updateGitHubHosts[strings.ToLower(parsed.Hostname())] || parsed.User != nil || parsed.Fragment != "" || len(raw) > 8192 || (parsed.Port() != "" && parsed.Port() != "443") {
		return nil, errUpdateGitHub
	}
	return parsed, nil
}

type updatePublicDialer struct {
	lookup func(context.Context, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func (d updatePublicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || !updateGitHubHosts[strings.ToLower(host)] {
		return nil, errUpdateGitHub
	}
	ips, err := d.lookup(ctx, host)
	if err != nil || len(ips) == 0 || len(ips) > 16 {
		return nil, errUpdateGitHub
	}
	for _, ip := range ips {
		if !updatePublicIP(ip) {
			return nil, errUpdateGitHub
		}
	}
	for _, ip := range ips {
		connection, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
	}
	return nil, errUpdateGitHub
}

type updateGitHubClient struct {
	http   *http.Client
	mu     sync.Mutex
	cached updateGitHubCatalog
	now    func() time.Time
}

func newUpdateGitHubClient() *updateGitHubClient {
	dialer := updatePublicDialer{lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 32 << 10, IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 2}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errUpdateGitHub
		}
		_, err := updateGitHubURL(request.URL.String())
		return err
	}}
	return &updateGitHubClient{http: client, now: time.Now}
}

func (c *updateGitHubClient) get(ctx context.Context, raw string) (*http.Response, error) {
	parsed, err := updateGitHubURL(raw)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errUpdateGitHub
	}
	request.Header.Set("User-Agent", "Xe-AntiShell-Central-Release-Import")
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, errUpdateGitHub
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, errUpdateGitHub
	}
	return response, nil
}

func (c *updateGitHubClient) json(ctx context.Context, raw string, maximum int64, target any) error {
	response, err := c.get(ctx, raw)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ContentLength > maximum {
		return errUpdateGitHub
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(body)) > maximum || json.Unmarshal(body, target) != nil {
		return errUpdateGitHub
	}
	return nil
}
