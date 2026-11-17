# Purpose

Extract central management as an independent MIT Go module and RPM without
changing wire signatures, persisted data, service paths or existing identity.

# Current Structure

The source originates from Xe-AntiShell's central CLI and internal central
package. Shared protocol and domain definitions live in the agent repository's
separately versioned protocol submodule.

# Requirements and Design

- Module: `github.com/mkjang2000/Xe-AntiShell-Central`.
- Pin protocol v0.1.0 and the existing SQLite v1.36.0 dependency graph.
- Preserve the existing central implementation and tests; change imports only.
- Produce only `sentinel-central`, `sentinel-central.service` and the dedicated
  `xe-antishell-central` account. Keep the existing state directory and ports.
- Installation accepts an explicit local RPM or source build. Initialization is
  a separate operator command; an uninitialized service is not started.
- RPM service hooks reference central only. No agent package dependency,
  uninstall-approval invocation, firewall change or automatic PKI operation.
- Select maintained source files explicitly for isolated builds; include MIT,
  upstream notices and all 39 preserved upstream license/notice files.

# Data Flow and Failure Handling

Existing state loads without transformation. Installation and upgrade preserve
keys and SQLite files. Source checks fail before packaging if credentials,
runtime artifacts, symlinks or broken documentation links enter the candidate
set. Build output is published only as one complete RPM. A conflicting legacy
bundled package is migrated through a separately coordinated RPM transaction;
this installer does not erase or replace the agent package.

# Compatibility / Impact

Binary, account, state paths, HTTP schemas, signing domains and DB schema stay
unchanged. Source imports point to the canonical public modules. Release
go.mod has no replace directive or sibling-folder dependency.

# Validation Plan

Run format/source checks, installer/build command-mock and archive regressions,
vet, race tests and a static build. Inspect independent RPM payload/scriptlets.
Before protocol publication use only an external temporary Go workspace; repeat
release builds with GOWORK=off after the pinned protocol release is available.
Live deployment migration and public publication are handled separately.
