# Purpose

Support HTTPS Cloudflare Tunnel / local TLS-terminating proxies in front of the
HTTP management console, preserving direct localhost access and CSRF protection.

# Cause

An HTTPS tunnel service URL against an HTTP listener fails before HTTP routing.
After correcting that route, current login/API mutations still compare external
HTTPS Origin to internal HTTP and reject legitimate requests. Secure cookies also
currently reflect only native TLS.

# Design

- Add optional `--panel-public-origin https://console.example` and
  `--panel-trusted-proxies 127.0.0.1/32,::1/128`. The latter configures actual
  connector peers, not client-provided forwarded headers. An empty public origin
  preserves the existing console constructor and direct-access behavior.
- `console.NewWithOptions` validates a canonical HTTPS origin (no credentials,
  path, query, fragment), literal trusted-proxy CIDRs and coherent options.
- Only requests whose real peer matches a trusted proxy and whose Host authority
  matches the configured external origin use its HTTPS scheme/authority. Other
  requests retain existing native TLS/HTTP checks. Preserve localhost forwarding.
- Use this same decision for login/CSRF checks and Secure session/logout cookies.
  Continue ignoring Forwarded, X-Forwarded-* and CF-Connecting-IP. A public origin
  is an origin declaration, not proof of Cloudflare Access authentication; native
  console credentials and CSRF remain required.
- Keep remote tunnel configuration, access policy and credentials separate from
  source. Correct service URL in Cloudflare is HTTP for the deployed HTTP panel;
  the browser URL remains HTTPS. Do not weaken certificate verification.

# Scope and Compatibility

Auth origin module, credential middleware wiring, console CLI flags, docs and
RPM release. No agent/policy/database/frontend protocol changes. Host-header
overrides must preserve the configured public hostname. Single-user rate limits
continue applying to the actual proxy peer; no new client-IP header trust.

# Validation

Regression tests for trusted loopback HTTP origin + external HTTPS login,
session/CSRF mutation/logout and Secure cookies. Reject untrusted peers, wrong
host/scheme/port, opaque/multiple/foreign origins, invalid options and spoofed
forwarded headers. Preserve native TLS/local HTTP cases and invalid-config
startup without opening listeners. Real Chrome local reverse-proxy smoke verifies
Secure cookies with a synthetic HTTPS hostname and existing console login.
