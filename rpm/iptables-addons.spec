Name:                   iptables-zorp-addons
Version:                7.0.1~alpha1
Release:                0.1%{?dist}
Source:                 iptables-addons_%{version}.tar.xz
Summary:                Iptables addons for zone and service matches
Group:                  Productivity/Networking/Security
URL:			https://balasys.github.io/zorp/
License:                GPL-2.0
BuildRequires:          automake
BuildRequires:          autoconf
BuildRequires:          libtool
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
autoreconf -if
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
%{_libdir}/xtables/libxt_zone.la
%{_libdir}/xtables/libxt_rule.la
%{_libdir}/xtables/libxt_service.la
%{_libdir}/xtables/libxt_socket_kzorp.la
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
%{_libdir}/xtables/libxt_KZORP.la
%{_libdir}/xtables/libxt_KZORP.so

%changelog
* Thu Sep 27 2018 Balasys Development Team <devel@balasys.hu> - 7.0.1-0.1
  - New upstream release 7.0.1~alpha1
* Mon May 14 2018 Balasys Development Team <devel@balasys.hu> - 6.0.12
  - New upstream release 6.0.12
* Wed Sep 13 2017 Balasys Development Team <devel@balasys.hu> - 6.0.11
  - New upstream release 6.0.11
* Wed Feb 25 2015 BalaBit Zorp GPL Team <zorp@lists.balabit.hu> - 6.0.0-1
  - Initial packaging</zorp>
