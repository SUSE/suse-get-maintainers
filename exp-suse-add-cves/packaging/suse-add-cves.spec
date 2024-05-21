Name:           suse-add-cves
Version:        0.9
Release:        0
Summary:        A tool to update CVE in a patch
License:        GPL-3.0-or-later
Group:          Development/Libraries/C and C++
URL:            https://gitlab.suse.de/mfranc/tracking-fixes
Source:         %{name}-%{version}.tar.xz
BuildRequires:  libgit2-devel
%if 0%{?suse_version} < 1550 && 0%{?sle_version} <= 150600
BuildRequires:  gcc13-c++
%else
BuildRequires:  gcc-c++
%endif

%description
suse-add-cves utility takes a series of patches either as arguments or
one per line on stdin with --from_stdin (-f) option and updates CVE
number metadata in the patches.  It needs upstream vulnerability repo
that can be cloned with: suse-add-cves -i -v /path. Existing repo is
accessed via via -v option or better via VULNS_GIT environment
variable.  The vulnerability repo is kept up-to-date automatically and
is never older than 15 minutes.



%prep
%autosetup

%build
%if 0%{?suse_version} < 1550 && 0%{?sle_version} <= 150600
%make_build CXX=g++-13 %{name}
%else
%make_build %{name}
%endif

%check

%install
install -b -D -m 755 %{name} %{buildroot}/%{_bindir}/%{name}

%files
%{_bindir}/%{name}

%changelog
