%global srcname keycloak-httpd-client-install
%global summary Tools to configure Apache HTTPD as Keycloak client

%if 0%{?fedora}
%global with_python3 1
%endif

Name:           %{srcname}
Version:        0.1
Release:        1%{?dist}
Summary:        %{summary}

%global git_tag RELEASE_%(r=%{version}; echo $r | tr '.' '_')

License:        MIT
URL:            https://github.com/jdennis/keycloak-httpd-client-install
Source0:        https://github.com/jdennis/keycloak-httpd-client-install/archive/%{git_tag}.tar.gz#/%{srcname}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python2-devel
%if 0%{?with_python3}
BuildRequires:  python3-devel
%endif

%description
Keycloak is a federated Identity Provider (IdP). Apache HTTPD supports
a variety of authentication modules which can be configured to utilize
a Keycloak IdP to perform authentication. This package contains
libraries and tools which can automate and simplify configuring an
Apache HTTPD authentication module and registering as a client of a
Keycloak IdP.

%package -n python2-%{srcname}
Summary:        %{summary}

%{?python_provide:%python_provide python2-%{srcname}}

Requires:       python-requests
Requires:       python-requests-oauthlib
Requires:       python-jinja2

%description -n python2-%{srcname}
Keycloak is an authentication server. This package contains libraries and
programs which can invoke the Keycloak REST API and configure clients
of a Keycloak server.

%if 0%{?with_python3}
%package -n python3-%{srcname}
Summary:        %{summary}

%{?python_provide:%python_provide python3-%{srcname}}

Requires:       python3-requests
Requires:       python3-requests-oauthlib
Requires:       python3-jinja2

%description -n python3-%{srcname}
Keycloak is an authentication server. This package contains libraries and
programs which can invoke the Keycloak REST API and configure clients
of a Keycloak server.

%endif

%prep
%autosetup -n %{srcname}-%{version}

%build
%py2_build
%if 0%{?with_python3}
%py3_build
%endif

%install
# Must do the python2 install first because the scripts in /usr/bin are
# overwritten with every setup.py install, and in general we want the
# python3 version to be the default.
%py2_install
%if 0%{?with_python3}
# py3_install won't overwrite files if they have a timestamp greater-than
# or equal to the py2 installed files. If both the py2 and py3 builds execute
# quickly the files end up with the same timestamps thus leaving the py2
# version in the py3 install. Therefore remove any files susceptible to this.
rm %{buildroot}/usr/bin/keycloak-httpd-client-install
%py3_install
%endif

install -d -m 755 %{buildroot}/%{_mandir}/man8
install -c -m 644 doc/keycloak-httpd-client-install.8 %{buildroot}/%{_mandir}/man8

# Note that there is no %%files section for the unversioned python module if we are building for several python runtimes
%files -n python2-%{srcname}
%license LICENSE.txt
%doc README.md
%doc doc/keycloak-httpd-client-install.md
%doc %{_mandir}/man8/*
%{python2_sitelib}/*
%{_bindir}/*
%{_datadir}/python-%{srcname}/*

%if 0%{?with_python3}
%files -n python3-%{srcname}
%license LICENSE.txt
%doc README.md
%doc doc/keycloak-httpd-client-install.md
%{python3_sitelib}/*
%{_bindir}/*
%{_datadir}/python-%{srcname}/*
%endif

%changelog
* Fri May 13 2016 John Dennis <jdennis@redhat.com> - 0.1-1
- Initial version

