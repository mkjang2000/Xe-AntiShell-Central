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
│   ├── enrollment_code.go        # Certificate-bound endpoint config and installation-code issuance
│   ├── history_filters.go        # Validated date/search filters and condition-bound cursors
│   ├── delivery_receipts.go      # Compact per-stream replay checks and schema 4 cursor migration
│   ├── capacity.go               # On-demand read-only storage and expiry statistics
│   ├── history_retention.go      # Ingest projection, immutable digests and bounded ordinary-history expiry
│   ├── finding_reviews.go       # Append-only per-finding operator decisions and retained evidence
│   ├── finding_reviews_http.go  # Session-bound decision writes, pagination and evidence reads
│   ├── history_read.go           # Separate finding/event/error/audit projections
│   ├── history_query.go          # Literal JSON filters, bounded metadata branches and compatible cursors
│   ├── history_reader.go         # Isolated read-only WAL pool, deadlines and legacy admin reads
│   ├── history_page.go           # Same-snapshot record lookup and bounded response pagination
│   ├── history_audit.go          # Bounded audit metadata/detail reads on the history pool
│   ├── agent_errors.go           # Durable deduplicated error transitions from heartbeats
│   ├── privilege_policy.go        # Current-enrollment engine compatibility gate for opt-in policies
│   ├── privilege_evidence.go      # Paired credential proof validation before ingest
│   └── updates_*.go              # Publisher-verified RPM/GitHub catalog, signed jobs/claims/reports
├── internal/console/              # Authentication, enforced roles, sessions and CSRF
│   ├── password_policy.go        # New password composition, Unicode length and legacy-login compatibility
│   ├── accounts_store.go         # Persistent accounts, final-admin guard and account audit
│   ├── accounts_auth.go          # Per-request identity and role authorization
│   ├── accounts_http.go          # Account/password administration APIs
│   └── assets/                    # Korean fleet, policies, histories and dark/light themes
│       ├── privilege.js          # Root/credential findings and bounded before/after evidence presentation
│       ├── accounts.js           # Compact account list, dialogs and permission help
│       ├── accounts.css          # Account table/dialog/tooltip responsive presentation
│       ├── accounts.test.mjs     # Dialog lifecycle, stale responses and role-help regressions
│       ├── updates.js            # Release catalog, raw upload and guarded update dialogs
│       ├── updates-source.js     # Public signed manifest input and fixed GitHub import
│       ├── updates.css           # Dense light/dark update tables and dialogs
│       └── updates.test.mjs      # Roles, transport, preview, cancellation and terminal outcomes
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
│   ├── plans/privilege-detection-console.md
│   ├── plans/central-privilege-rollout.md
│   ├── plans/compact-delivery-receipts.md
│   ├── plans/minimal-observation-history.md
│   ├── plans/history-query-performance.md
│   ├── plans/password-policy.md
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
Console session → current account/role → CSRF → group/template editor → preview → atomic signed deployment
Heartbeat → latest state + deduplicated error transitions → filtered history views
Authenticated console → installation code with public CA → agent wizard → verified TLS enrollment
```

## Architecture Notes

- The shared `github.com/mkjang2000/Xe-AntiShell/protocol` module owns wire and
  cryptographic contracts; central does not import agent implementation.
- Protocol v0.3.0 adds optional privilege policy fields and paired credential evidence
  with exact uint64 task identity strings, on top of publisher-verified update plans/claims and independent inventory/reports,
  alongside optional typed execution/file/network evidence, while
  preserving managed-v1 signed policy bytes and legacy omitted-field JSON.
  Its installation-code envelopes remain compatible. Offline recovery plaintext and
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
- `internal/central/detection_policy_support.go` checks current-enrollment
  heartbeat support for signed privilege and file/TCP service policy extensions.
- Versioned templates retain desired integrity settings centrally; wire v1 agents
  receive supported settings only. Pending settings and agent application status
  are displayed separately. Group edits have no automatic policy effects.

- Console accounts persist in a separate private `panel-accounts.db`; the legacy
  auth file seeds the initial administrator only once. Password/role changes
  rotate account session keys. All API mutations enforce roles and CSRF.
- Central validates canonical wire payloads before storing minimal observations.
  Per-spool sequence receipts and expired ID digests protect replay integrity.
  Finding/event views project individual items before filtering/pagination. Operational error history
  stores categories and transitions, preserving no historical raw diagnostics.
- History uses one dedicated read-only WAL connection with a three-second deadline.
  Literal event-type expression indexes and branch-local filters/limits select only
  metadata before fetching immutable payloads by primary key in the same snapshot.
  Eight-MiB response budgets preserve the last returned item's continuation cursor;
  legacy admin endpoints keep their original ordering and upper-limit semantics.
- Browser modules separate account administration, history filters, permission
  presentation, capability editing and theme preferences. No frontend build or
  third-party browser runtime dependency is required.
- `assets/model.js` presents bounded typed observation fields and independent
  receipt freshness. `assets/history.js` labels execution options, file-write
  returns and TCP initiation without claiming code success or connection completion.
- Update inventory and per-enrollment revision heads use additive tables without
  changing legacy database version 2 or heartbeat JSON. RPM blobs remain outside
  SQLite; slow uploads/downloads hold no database transaction. Admins publish
  releases, operators schedule exact reviewed targets, and agents request short
  install authorization only after verified download. Terminal outcomes stay
  fixed when late reports arrive, and failed campaigns stop unclaimed targets.
- Release publisher keys are embedded public anchors independent of central policy
  signing keys. Admins import a signed RPM/manifest pair manually or from the fixed
  public GitHub repository; no endpoint changes trust keys or accepts arbitrary URLs.
