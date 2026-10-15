# Built by contrib/build-rpm.sh, which defines:
#   strongswan_src  configured and compiled source tree of the strongSwan package
#   strongswan_evr  version-release of that package, e.g. 6.0.6-1.el9
#   strongswan_ver  its version, e.g. 6.0.6
# strongSwan has no stable plugin ABI: the package requires exactly the
# strongSwan it was built against, which also refuses any other build.

Name:           strongswan-psk-radius
Version:        0.1.1
Release:        1.strongswan%{strongswan_ver}%{?dist}
Summary:        strongSwan plugin that looks up IKE pre-shared keys and virtual IPs in RADIUS
License:        GPL-2.0-or-later
URL:            https://github.com/flozano/strongswan-psk-radius
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
Requires:       strongswan%{?_isa} = %{strongswan_evr}

%description
When charon needs the IKE pre-shared key of a peer, the psk-radius plugin asks
a RADIUS server for it with an Access-Request (Service-Type Authorize-Only,
User-Name = the peer identity, no password). The Access-Accept carries the key
in Tunnel-Password and, optionally, the peer's virtual IPs and DNS servers,
which connections assign with "pools = psk-radius".

%prep
%autosetup

%build
%make_build STRONGSWAN_SRC=%{strongswan_src} LIBDIR=%{_libdir}/strongswan

%install
%make_install LIBDIR=%{_libdir}/strongswan
install -D -m 0644 packaging/psk-radius.conf \
	%{buildroot}%{_sysconfdir}/strongswan/strongswan.d/charon/psk-radius.conf

%files
%license LICENSE
%doc README.md examples
%{_libdir}/strongswan/plugins/libstrongswan-psk-radius.so
%config(noreplace) %{_sysconfdir}/strongswan/strongswan.d/charon/psk-radius.conf
