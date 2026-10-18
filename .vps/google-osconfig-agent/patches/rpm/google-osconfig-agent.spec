# Downstream package containing only the OS Config inventory repair.
%global goipath         github.com/GoogleCloudPlatform/osconfig
Version:                %{upstream_version}
%global tag             %{upstream_version}
%gometa -L -f

Name:           google-osconfig-agent
Release:        %{vps_release}%{?dist}
Summary:        Google OS Config Agent with inventory corrections

License:        Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND GPL-2.0-only AND ISC AND LicenseRef-Fedora-Public-Domain AND MIT AND MPL-2.0 AND Sleepycat AND (Apache-2.0 OR GPL-2.0-or-later)
URL:            %{gourl}
Source0:        osconfig-%{version}.tar.gz
Source1:        osconfig-%{version}-vendor.tar.bz2
Source2:        go-vendor-tools.toml
Patch0:         osconfig-inventory.patch

BuildRequires:  go-vendor-tools
BuildRequires:  systemd
BuildRequires:  systemd-rpm-macros

ExcludeArch:    ppc64le s390x

%description
Google OS Config Agent. This downstream build contains the minimal inventory
serialization and DNF5 update-list corrections maintained in this repository.

%prep
%goprep -p1
tar -xf %{SOURCE1}
rm -rf examples e2e_tests

%generate_buildrequires
%go_vendor_license_buildrequires -c %{SOURCE2}

%build
%global gomodulesmode GO111MODULE=on
%gobuild -o %{gobuilddir}/bin/google_osconfig_agent %{goipath}

%install
%go_vendor_license_install -c %{SOURCE2}
install -m 0755 -vd                     %{buildroot}%{_bindir}
install -m 0755 -vp %{gobuilddir}/bin/* %{buildroot}%{_bindir}/
install -m 0644 -Dp %{name}.service     %{buildroot}%{_unitdir}/%{name}.service

%check
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-count=1 -timeout=5m"
%go_vendor_license_check -c %{SOURCE2}
%gocheck2 -t agentendpoint -t config -t policies -t packages

%files -f %{go_vendor_license_filelist}
%doc CONTRIBUTING.md README.md
%{_bindir}/google_osconfig_agent
%{_unitdir}/%{name}.service

%post
%systemd_post %{name}

%preun
%systemd_preun %{name}

%postun
%systemd_postun_with_restart %{name}
