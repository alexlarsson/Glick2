Name:		glick2
Version:	0.0.1
Release:	1%{?dist}
Summary:	An application bundle runtime

License:	GPLv2+
URL:		http://people.gnome.org/~alexl/glick2/
Source0:	http://people.gnome.org/~alexl/glick2/releases/glick2-%{version}.tar.gz

BuildRequires:	glib2-devel, fuse-devel

%description
Glick2 is a runtime and a set of tools to create
application bundles for Linux. An application bundle is a single file
that contains all the data and files needed to run an application. The
bundle can be run without installation, or be installed by just
putting the file in a known directory.

%package tools
Summary:        Tools to create glick2 bundles
Group:          System Environment/Libraries
License:        GPLv2+

%description tools
This package contains tools needed to create glick2
bundles.

%prep
%setup -q

%build
%configure --disable-setuid-install
make V=1 %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc README
%{_bindir}/glick-fs
%{_bindir}/glick-runner
%attr(4755,root,root) %{_bindir}/glick-session
%attr(4755,root,root) %{_libexecdir}/glick-helper
%{_datadir}/mime/packages/glick2.xml
%config %{_sysconfdir}/binfmt.d/glick2.conf
%{_sysconfdir}/xdg/autostart/glick.desktop
%dir /opt/bundle
%dir /opt/session

%post
/usr/bin/update-mime-database %{_datadir}/mime &> /dev/null || :

%postun
/usr/bin/update-mime-database %{_datadir}/mime &> /dev/null || :
   
%files tools
%{_bindir}/glick-mkbundle

%changelog
* Thu Oct 13 2011 Alexander Larsson <alexl@redhat.com> - 0.0.1-1
- Initial version

