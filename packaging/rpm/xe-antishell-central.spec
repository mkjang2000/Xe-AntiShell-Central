Name:           xe-antishell-central
Version:        0.1.0
Release:        6%{?dist}
Summary:        Independent Xe-AntiShell central management service
License:        MIT AND Apache-2.0 AND BSD-3-Clause AND BSD-2-Clause AND BSD-1-Clause AND SunPro
URL:            https://github.com/mkjang2000/Xe-AntiShell-Central
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  golang >= 1.22
BuildRequires:  make
BuildRequires:  systemd
Requires(pre):  shadow-utils

%global debug_package %{nil}

%description
Xe-AntiShell-Central provides authenticated agent enrollment, mTLS event
delivery, signed policy distribution and a loopback operator API. It is
independent of the Xe-AntiShell host agent package. An optional authenticated
web console provides fleet monitoring and explicit policy/group administration.

%prep
%autosetup

%build
GOTOOLCHAIN=local GOWORK=off %{__make} static

%install
install -D -m 0755 build/sentinel-central %{buildroot}%{_sbindir}/sentinel-central
install -D -m 0644 packaging/systemd/sentinel-central.service %{buildroot}%{_unitdir}/sentinel-central.service
install -d -m 0700 %{buildroot}%{_localstatedir}/lib/xe-antishell-central

%files
%doc README.md
%license LICENSE THIRD_PARTY_NOTICES.md third_party/licenses
%{_sbindir}/sentinel-central
%{_unitdir}/sentinel-central.service
# Preserve the legacy root-owned directory; systemd StateDirectory sets runtime ownership.
%dir %attr(0700,root,root) %{_localstatedir}/lib/xe-antishell-central

%pre
getent group xe-antishell-central >/dev/null || groupadd -r xe-antishell-central
getent passwd xe-antishell-central >/dev/null || useradd -r -g xe-antishell-central -d /var/lib/xe-antishell-central -s /sbin/nologin -c "Xe-AntiShell central server" xe-antishell-central

%post
%systemd_post sentinel-central.service

%preun
%systemd_preun sentinel-central.service

%postun
%systemd_postun_with_restart sentinel-central.service

%changelog
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
