# Scope

Browser review of the agent-update console after the publisher-signature and
fixed GitHub import implementation, November 18, 2026. The maintained static
binary served its embedded assets from an independent temporary state directory
with newly generated fixture PKI, accounts and loopback ports. Every fixture
server was stopped after its run. Production services and state were untouched.

Login, sessions, account roles and unauthorized RPM-upload denial used the real
isolated backend. Update inventories, releases, previews, campaigns, artifact
upload responses and GitHub responses were injected synthetic fixtures. Their
successful results do not establish publisher cryptographic verification, native
RPM inspection, external GitHub availability or a real remote installation. No
production publisher private key was read or supplied to the browser.

# Browser Results

- Chrome checked dark/light themes at widths 1440, 720 and 375 for all three
  update tabs and upload, release, preview preparation, GitHub and rollout dialogs.
  The page stayed within the viewport; wide tables scrolled inside their regions.
- WCAG 2 A/AA, 2.1 A/AA and 2.2 AA axe scans covered 63 states, with zero
  violations. No page script errors or document horizontal overflows occurred.
- Native modal opening, keyboard movement, Escape and opener focus restoration
  worked. Focus did not enter background page controls. Chrome's normal Tab
  movement to browser chrome was distinguished from background document focus.
- Empty catalogs could not deploy. Unverified releases remained distinguishable
  and unavailable for deployment. Catalog search used the displayed release rows.
- Synthetic PEM, unknown-field JSON, duplicate-key JSON, malformed JSON and a
  non-RPM filename were rejected before an RPM network request. Both selected
  files cleared on success, close and hash navigation. Valid-shaped synthetic
  pairs sent the public manifest header with raw RPM bytes.
- GitHub list/import failures preserved explicit retry and confirmation. The
  manifest selection and fixed repository were visible. A successful synthetic
  import did not claim deployment to an agent.
- Mixed eligible/excluded groups required a preview and separate root-install
  confirmation. A changed concurrency/selection invalidated confirmation.
- Paused campaigns, unconfirmed physical installation outcomes, late reports and
  verified/not-applicable/failed/missing collection checks remained distinct.
  Cancellation stated that already-authorized installations continue.
- Real admin/operator/viewer fixture sessions matched the visible privileges.
  Operators/viewers received HTTP 403 for actual direct RPM-upload attempts.
  Closing and immediately reopening a native dialog, and a late upload response
  after switching dialogs, did not close or overwrite the new dialog.

# Follow-up Changes

Review identified two small presentation issues: bootstrap-required and exhausted
revision exclusions needed actionable fixed text, and narrow result-table cells
created excessive wrapping. Their explanations are now explicit; table cells
keep a minimum width inside the existing scroll container. JavaScript regression
tests cover both exclusion reasons. The final browser run included the changed
static assets and a mobile result-row readability check.

# Actual Signed RPM Integration

A subsequent run used the actual public bootstrap RPM 0.1.0-23.el9.x86_64 and
its publisher-signed public manifest against a fresh isolated backend. There was
no route interception or injected response for this run. Seven checks passed,
with five axe scans reporting zero violations and no page script errors:

- The browser uploaded real RPM bytes. The backend verified the embedded
  publisher signature, signed hash/size and native RPM metadata, returned 201,
  and exposed matching verified provenance in the catalog and details.
- A duplicate upload returned 200 and kept one immutable catalog entry.
- A one-byte RPM mutation returned 400 and did not replace the stored artifact.
- Unknown manifest fields failed locally without upload. Direct API attempts
  independently rejected unknown fields and changed signed package metadata
  with 400 responses, preserving the verified catalog entry.
- A real operator session received 403 even with a valid signed release pair.

The separate run read only the two supplied public release files and its own
temporary fixture credentials. It performed no installation and never accessed
the publisher private key, production services or production APIs.

# Remaining Integration Work

A public GitHub manifest/artifact fetch and agent/helper installation still
require separate end-to-end checks. Browser verification does not approve
publication or operational deployment.
