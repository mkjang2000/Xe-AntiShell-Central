# Purpose

Provide a Korean operator console for central fleet monitoring, policy/group editing,
explicit policy deployment, enrollment credentials and one-use removal approvals.

# Design

- A third HTTP listener serves the embedded console. Default `127.0.0.1:9089`;
  non-loopback requires `--allow-non-loopback-panel`. It starts only when
  `panel-auth.json` exists, so existing installations remain compatible.
- `internal/console` owns Argon2id login, signed sessions, CSRF, request limits,
  static assets and browser presentation. `central.Server.ConsoleHandler()` supplies
  authenticated business routes under `/api/`; the CLI wires both together.
- Browser sessions never receive the existing operator bearer credential or keys.
- Additive SQLite schema v2 stores versioned groups and policy templates. Group
  membership changes never deploy policies. Deployment previews bind template,
  membership, enrollment and current revisions; deployment is transactional.
- Full desired policies include integrity settings. Current managed-v1 agents only
  receive supported wire fields; integrity stays explicitly pending, never reported
  applied. Blocking still respects agent capability and local termination opt-in.
- Monitoring uses latest authenticated heartbeat and retained event history. Missing
  heartbeat metrics and stale capability reports remain unknown/stale.
- Enrollment secrets and signed removal approvals are returned only at issuance,
  never included in subsequent state responses or logs. Existing removal deny and
  enrollment checks are reused. Revocation is explicit and confirmed.

# Shared Browser API Contract

All routes below require session auth; mutations require `X-CSRF-Token` obtained
from `GET /api/session` in the console wrapper. JSON, no-store, bounded requests.

- `GET /api/state`: `{server_time, agents:[], groups:[], templates:[], defaults:{...}}`.
  Agents retain the existing Agent JSON fields (including heartbeat).
- `GET /api/history?agent_id=&kind=&limit=` and `/api/audit?limit=`: existing arrays.
- `POST /api/groups`: `{id,name,description,agent_ids,version}`; new version=0.
- `DELETE /api/groups/{id}?version=N`: optimistic concurrency, no deployment.
- `POST /api/templates`: `{id,name,description,version,settings}`; new version=0.
- `DELETE /api/templates/{id}?version=N`.
- Template settings: `{detection,response,uninstall_mode,monitoring,integrity,validity_hours}`.
  First four use existing managed-v1 Policy field shapes. `integrity` is
  `{enabled,mode,require_tpm,paths}`; mode `observe` or `enforce`; validity 1..8760h.
- `POST /api/deploy/preview`: `{template_id,agent_ids,group_ids}` returns
  `{preview_token,template:{id,name,version,settings},targets:[{agent_id,enrollment_id,current_revision,next_revision,warnings:[]}],pending_features:[]}`.
  Preview presentation must use this server snapshot, never a locally cached draft.
- `POST /api/deploy`: `{preview_token,confirm:true}` returns deployment result;
  expired or changed previews return 409; no implicit deployment.
- `POST /api/enrollment`: `{agent_id,ttl_seconds}` returns `{agent_id,token,expires_at}` once.
- `POST /api/removal`: existing `{agent_id,enrollment_id,challenge,ttl_seconds}`
  returns existing SignedRemovalGrant JSON once.
- `POST /api/revoke`: `{agent_id,confirm:true}`; invalidate authenticated agent.

# Failure Handling and Compatibility

Keep existing agent/operator APIs, PKI, enrollment IDs and signed policy bytes
unchanged. Draft-only settings must not alter wire protocol v0.1.0. Reject invalid
policies, stale edits/previews, invalid identities and cross-origin mutations.
Expose useful Korean validation errors without database internals or secret values.
Save/deploy actions need explicit feedback; polling must not erase unsaved forms.

# Validation

Meaningful Go tests cover schema upgrade, optimistic edits, atomic multi-agent
deployment, stale previews, pending integrity, one-use grants and auth/CSRF/rate
limits. Browser/JS checks cover forms, escaping, capability mapping, compact layout
and keyboard access. Run existing installer/source/archive/Go checks and an isolated
old-agent/new-central integration. Deployment preserves the current observe policy.
