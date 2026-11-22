Name:           xe-antishell-central
Version:        0.1.0
Release:        27%{?dist}
Summary:        Independent Xe-AntiShell central management service
License:        MIT AND Apache-2.0 AND BSD-3-Clause AND BSD-2-Clause AND BSD-1-Clause AND SunPro
URL:            https://github.com/mkjang2000/Xe-AntiShell-Central
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  golang >= 1.22
BuildRequires:  make
BuildRequires:  systemd
Requires(pre):  shadow-utils
Requires:       rpm
Requires:       tar

%global debug_package %{nil}

%description
Xe-AntiShell-Central provides authenticated agent enrollment, mTLS event
delivery, signed policy distribution and a loopback operator API. It is
independent of the Xe-AntiShell host agent package. An optional authenticated
web console provides fleet monitoring and explicit policy/group administration.

%prep
%autosetup

%build
GOTOOLCHAIN=local GOWORK=off %{__make} static CENTRAL_VERSION=%{version}-%{release}.%{_arch}

%install
install -D -m 0755 build/sentinel-central %{buildroot}%{_sbindir}/sentinel-central
install -D -m 0644 packaging/systemd/sentinel-central.service %{buildroot}%{_unitdir}/sentinel-central.service
install -D -m 0644 packaging/systemd/sentinel-central-updater.service %{buildroot}%{_unitdir}/sentinel-central-updater.service
install -D -m 0644 packaging/systemd/sentinel-central-updater.socket %{buildroot}%{_unitdir}/sentinel-central-updater.socket
install -d -m 0700 %{buildroot}%{_localstatedir}/lib/xe-antishell-central

%files
%doc README.md
%license LICENSE THIRD_PARTY_NOTICES.md third_party/licenses
%{_sbindir}/sentinel-central
%{_unitdir}/sentinel-central.service
%{_unitdir}/sentinel-central-updater.service
%{_unitdir}/sentinel-central-updater.socket
# Preserve the legacy root-owned directory; systemd StateDirectory sets runtime ownership.
%dir %attr(0700,root,root) %{_localstatedir}/lib/xe-antishell-central

%pre
getent group xe-antishell-central >/dev/null || groupadd -r xe-antishell-central
getent passwd xe-antishell-central >/dev/null || useradd -r -g xe-antishell-central -d /var/lib/xe-antishell-central -s /sbin/nologin -c "Xe-AntiShell central server" xe-antishell-central

%post
%systemd_post sentinel-central.service

%preun
%systemd_preun sentinel-central.service sentinel-central-updater.socket sentinel-central-updater.service

%postun
%systemd_postun_with_restart sentinel-central.service

%changelog
* Sun Nov 22 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-27
- Redesign site access with a per-site account role matrix and change preview
- Group role permissions, duplicate built-in roles and show where roles are assigned
- Move several agents between sites with per-agent results
- Show account grants as read-only without the role assignment permission

* Sun Nov 22 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-26
- Add site access, custom roles and scoped agent operations
- Preview and authorize batch RPM removal with per-agent results
- Manage signed agent operating settings and improve the fleet console

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-25
- Show listening service inventory in agent details and the policy editor
- Preview and pin per-agent service scopes in the signed policy

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-23
- Order update catalogs by numeric version and keep matching EL packages together
- Mark installed and older Central releases in the update selector

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-22
- Manage per-application policy versions and verify active policy reports
- Organize the policy workspace around editing, applied policies and deployment

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-21
- Allow the dedicated update worker to run RPM scriptlets with SELinux enforcing

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-20
- Update the central server from verified GitHub releases or locally supplied packages
- Back up state before installation and report the outcome through the CLI and console

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-19
- Gate service rule controls and staged policy trials on per-agent capabilities
- Compare agent measurements with signed RPM and approved configuration baselines
- Preserve operator dispositions with their original finding evidence

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-18
- Edit and deploy signed file and TCP service scopes to compatible agents

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-17
- Store compact receipts for new deliveries while preserving legacy replay validation
- Reuse free pages ahead of bounded incremental vacuum
- Add an on-demand read-only storage capacity report

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-16
- Minimize normalized observations after validation and retain durable delivery digests
- Expire ordinary unreferenced events after one hour
- Reuse SQLite pages and perform bounded incremental vacuum where enabled

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-15
- Accept eight-character composed passwords with uppercase additionally required below ten
- Match account dialogs and server policy while retaining legacy credential login
- Preserve initial-password entropy, account keys and session continuity during upgrade

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-14
- Push history filters into bounded metadata branches with event-type expression indexes
- Isolate all console and legacy admin history reads from agent writes using a read-only WAL pool
- Bound active searches and pool waits to three seconds with controlled JSON timeout errors
- Cap history responses at eight MiB and retain exact continuation cursors without losing records
- Preserve legacy admin ordering and immutable payloads through indexed same-snapshot reads

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-13
- Add guided opt-in global root execution and credential-change policy controls
- Require a fresh compatible engine report before issuing privilege policies
- Validate paired credential evidence and distinguish root recovery and capability activation
- Preserve exact uint64 task identity strings in credential history details
- Keep all new privilege findings detection-only without changing agent termination settings
- Pin published shared protocol v0.3.0 with no workspace build dependency
- Separate unknown namespace scope from missing paired credential proof in history

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-12
- Manage bounded immutable agent RPM releases and explicit server/group update rollouts
- Bind mTLS update plans, short install claims and durable reports to each enrollment
- Stop remaining targets after failed or expired updates and retain late report history
- Verify independent publisher manifests for manual RPM upload and fixed GitHub import
- Require post-restart collection verification before update success
- Pin shared protocol v0.2.0 without changing legacy heartbeat or policy contracts

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-11
- Explain typed interpreter, file-write and TCP-initiation observations
- Require fresh per-feature receipts before reporting live observation support
- Pin shared protocol v0.1.2 while retaining legacy managed-v1 compatibility

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-10
- Separate permission help into readable role paragraphs

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-9
- Present accounts in a compact searchable list with focused editing dialogs
- Explain permissions with hover, keyboard and touch help

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-8
- Skip absent and null findings in projected detection history
- Index retained detection bundles for bounded history lookup

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-7
- Add persistent console accounts, enforced roles and session revocation
- Separate filtered findings, execution and agent error transition histories
- Add guided capability gates, shared angular branding and dark/light themes

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-6
- Distinguish fresh heartbeat snapshots from expiring live observation proof
- Retain actual passive probe times without marking current settings stale

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-5
- Present live collector evidence independently of passive environment discovery
- Explain mismatched diagnostics and limit eBPF confirmation to process hooks

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-4
- Issue complete installation codes from an explicit certificate-matched enrollment URL
- Preserve legacy enrollment token and managed-v1 agent compatibility
* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-3
- Support explicit HTTPS public origins behind trusted local tunnel/proxy peers
- Preserve direct HTTP access and validate origin/secure cookies without trusting forwarded headers
* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-2
- Add the authenticated Korean central operations console and versioned policy/group storage
- Preserve existing observation policy and enable the console only after init-panel
* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-1
- Separate the central binary, dedicated account, service and RPM from the agent
- Preserve existing PKI, policy, enrollment and database paths without initialization
