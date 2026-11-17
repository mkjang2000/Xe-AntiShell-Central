package console

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Options declares a fixed public origin and the actual TCP peers allowed to
// present it. Forwarded, X-Forwarded-* and Cloudflare headers are never trusted.
type Options struct {
	// AccountsPath enables durable accounts. Empty keeps isolated in-memory
	// compatibility for embedded callers; the serving command always supplies it.
	AccountsPath   string
	PublicOrigin   string
	TrustedProxies []string
}

// Validate checks proxy options without opening listeners or loading credentials.
func (o Options) Validate() error {
	_, err := o.originPolicy()
	return err
}

type originPolicy struct {
	public  *url.URL
	proxies []netip.Prefix
}

func (o Options) originPolicy() (originPolicy, error) {
	if o.PublicOrigin == "" {
		if len(o.TrustedProxies) != 0 {
			return originPolicy{}, errors.New("console trusted proxies require a public origin")
		}
		return originPolicy{}, nil
	}
	public, err := url.Parse(o.PublicOrigin)
	if err != nil || !strings.HasPrefix(o.PublicOrigin, "https://") ||
		!validOriginURL(public) || strings.ContainsAny(o.PublicOrigin, "?#") || !validAuthority(public) {
		return originPolicy{}, errors.New("console public origin must be a canonical HTTPS origin without credentials, path, query or fragment")
	}
	if len(o.TrustedProxies) == 0 {
		return originPolicy{}, errors.New("console public origin requires at least one trusted proxy CIDR")
	}
	policy := originPolicy{public: public}
	for _, value := range o.TrustedProxies {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 || (prefix.Addr().Is4In6() && prefix.Bits() <= 96) {
			return originPolicy{}, errors.New("console trusted proxies must be literal CIDRs narrower than /0")
		}
		policy.proxies = append(policy.proxies, prefix.Masked())
	}
	return policy, nil
}

func validOriginURL(parsed *url.URL) bool {
	return parsed != nil && parsed.Opaque == "" && parsed.User == nil && parsed.Host != "" &&
		parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == ""
}

func validAuthority(parsed *url.URL) bool {
	if parsed.Hostname() == "" || strings.ContainsAny(parsed.Hostname(), "%\\") || strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return false
		}
	}
	// Colons are valid only in bracketed IPv6 literals, apart from the port.
	if strings.Contains(parsed.Hostname(), ":") {
		address, err := netip.ParseAddr(parsed.Hostname())
		return err == nil && address.Is6() && strings.HasPrefix(parsed.Host, "[")
	}
	return !strings.ContainsAny(parsed.Host, "[]")
}

func (p originPolicy) proxied(r *http.Request) bool {
	if p.public == nil {
		return false
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	trusted := false
	for _, prefix := range p.proxies {
		if prefix.Contains(peer.Addr().Unmap()) || prefix.Contains(peer.Addr()) {
			trusted = true
			break
		}
	}
	if !trusted {
		return false
	}
	if strings.ContainsAny(r.Host, "/?#@\\") {
		return false
	}
	host, err := url.Parse("https://" + r.Host)
	return err == nil && validOriginURL(host) && validAuthority(host) &&
		equalHost(host.Hostname(), p.public.Hostname()) &&
		effectivePort("https", host.Port()) == effectivePort("https", p.public.Port())
}

func (p originPolicy) secure(r *http.Request) bool {
	return r.TLS != nil || p.proxied(r)
}

func (p originPolicy) sameOrigin(r *http.Request) bool {
	if p.proxied(r) {
		return sameOriginFor(r, "https", p.public.Host)
	}
	return sameOrigin(r)
}
