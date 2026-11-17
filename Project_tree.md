# Project Structure

## Overview

- Project Name: Xe-AntiShell-Central
- Purpose: Central fleet console, enrollment, mTLS delivery and signed policy administration
- Repository: https://github.com/mkjang2000/Xe-AntiShell-Central
- Language / Runtime: Go 1.22+, Linux
- Package Manager: Go modules
- Database: SQLite (modernc.org/sqlite, WAL mode)
- Entry Point: `cmd/sentinel-central`
- Build / Test: `make static` / `make verify`
- Run: `build/sentinel-central serve --state-dir /var/lib/xe-antishell-central`

## Managed Project Structure

```text
Xe-AntiShell-Central/
├── cmd/sentinel-central/          # Thin init/token/server CLI
├── internal/central/              # PKI, SQLite, agent and operator HTTP APIs
│   └── enrollment_code.go        # Certificate-bound endpoint config and installation-code issuance
├── internal/console/              # Administrator auth, sessions, CSRF and HTTP wrapper
│   └── assets/                    # Embedded Korean console, feature modules and JS tests
├── packaging/
│   ├── rpm/xe-antishell-central.spec
│   ├── systemd/sentinel-central.service
│   └── install_test.sh            # Installer command-mock checks
├── scripts/
│   ├── build-rpm.sh               # Isolated source selection and RPM build
│   ├── build_rpm_test.sh          # Mocked build and archive checks
│   ├── check-source.py            # Source privacy and document link checks
│   └── check_source_test.py       # Source-check regressions
├── .github/workflows/ci.yml       # Go 1.22 and stable verification
├── devdocs/
│   ├── plans/independent-central.md
│   └── analysis/managed-v1-operations.md
├── third_party/licenses/          # Preserved upstream license texts
├── install.sh                    # Explicit source/local-RPM installation
├── Makefile
├── go.mod
├── go.sum
├── README.md
├── LICENSE
└── THIRD_PARTY_NOTICES.md
```

## Main Execution Flow

```text
Explicit init → private CA, TLS and signing material + central SQLite database
Agent enrollment token + CSR → scoped certificate and enrollment generation
Agent mTLS batch → authenticated transaction → durable ACK
Loopback operator API → signed policy / removal grant / revocation
Console session + CSRF → group/template editor → preview → atomic signed deployment
Authenticated console → installation code with public CA → agent wizard → verified TLS enrollment
```

## Architecture Notes

- The shared `github.com/mkjang2000/Xe-AntiShell/protocol` module owns wire and
  cryptographic contracts; central does not import agent implementation.
- Protocol v0.1.1 adds bounded installation-code envelopes without changing
  managed-v1 wire schemas or signed policy bytes. Offline recovery plaintext and
  client private keys are generated and retained only on the agent side.
- Central owns one binary, service and dedicated account. Its RPM scriptlets
  never call the agent CLI or apply the agent removal approval policy.
- `/var/lib/xe-antishell-central` and existing unit overrides remain stable.
  systemd StateDirectory manages runtime ownership; installation never resets
  keys, enrollment, policies or database state.
- The agent API defaults to loopback HTTPS port 9443; the operator API remains
  loopback HTTP port 9444. Public binding requires explicit opt-in.
- Host configs, runtime state, deployment records and credentials are excluded
  from this source project and distributable archives.
- The optional console defaults to loopback port 9089 and starts only after
  `init-panel`. It never passes the operator bearer token to browsers.
- Explicit HTTPS public origins support TLS-terminating proxies only when the
  actual peer matches configured CIDRs and the request Host matches that origin.
  Forwarded headers remain untrusted; direct localhost access remains supported.
- Versioned templates retain desired integrity settings centrally; wire v1 agents
  receive supported settings only. Pending settings and agent application status
  are displayed separately. Group edits have no automatic policy effects.
