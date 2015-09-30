Name:                   iptables-zorp-addons
Version:                6.0.1
Release:                2
Source:                 iptables-addons_%{version}.tar.gz
Summary:                Iptables addons for zone and service matches
Group:                  Productivity/Networking/Security
URL:                    https://www.balabit.com/network-security/zorp-gpl
License:                GPL-2.0
BuildRequires:          automake
BuildRequires:          autoconf
BuildRequires:          libtool
BuildRequires:          pkg-config
BuildRequires:          gcc

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
BuildRequires:          iptables-devel
%else
BuildRequires:          libxtables-devel
%endif

BuildRoot:              %{_tmppath}/zorp-iptables-addons-%{version}-build

%prep
%setup -q -n zorp-iptables-addons

%build
./autogen.sh
%configure --prefix=/usr

%install
make DESTDIR=${RPM_BUILD_ROOT} install

%post
ldconfig

%postun
ldconfig

%description
Iptables addons for zone and service matches.

%files
%defattr(644,root,root)
%dir %{_libdir}/xtables
%{_libdir}/xtables/libxt_zone.so
%{_libdir}/xtables/libxt_rule.so
%{_libdir}/xtables/libxt_service.so
%{_libdir}/xtables/libxt_socket_kzorp.so

%package -n iptables-kzorp-addon
Summary:        Iptables addon for kZorp target
Group:          Productivity/Networking/Security

%description -n iptables-kzorp-addon
Iptables addon for kZorp target

%files -n iptables-kzorp-addon
%defattr(644,root,root)
%dir %{_libdir}/xtables
%{_libdir}/xtables/libxt_KZORP.so

%changelog
* Wed Feb 25 2015 BalaBit Zorp GPL Team <zorp@lists.balabit.hu> - 6.0.0-1
- Initial packaging</zorp>
