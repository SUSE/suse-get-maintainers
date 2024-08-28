Name:           suse-get-maintainers
Version:        1.0.8
Release:        0
Summary:        A tool to identify SUSE maintainers responsible for particular kernel code
License:        GPL-3.0-or-later
Group:          Development/Libraries/C and C++
URL:            https://gitlab.suse.de/mfranc/tracking-fixes
Source:         %{name}-%{version}.tar.xz
BuildRequires:  libgit2-devel
BuildRequires:  libcurl-devel
%if 0%{?suse_version} < 1550 && 0%{?sle_version} <= 150600
BuildRequires:  gcc13-c++
%else
BuildRequires:  gcc-c++
%endif

%description
suse-get-maintainers utility takes either a kernel path, an upstream
commmit hash, a unified patch produced by git or a CVE number and
produces contacts for SUSE maintainers responsible for the relevant
code.  It can also work in a batch mode where the input is provided on
the standard input one item per a line and the results are presented
in CSV or JSON formats on stdout.  For advanced functionality
(upstream hashs, CVE numbers) it requires access to a git kernel tree
and git kernel vulnerability database.

%prep
%autosetup

%build
%if 0%{?suse_version} < 1550 && 0%{?sle_version} <= 150600
%make_build CXX=g++-13 SGM_VERSION=%{version} %{name}
%else
%make_build SGM_VERSION=%{version} %{name}
%endif

%check

%install
install -b -D -m 755 %{name} %{buildroot}/%{_bindir}/%{name}
install -b -D -m 644 %{name}.1.gz %{buildroot}/%{_mandir}/man1/%{name}.1.gz

%files
%{_bindir}/%{name}
%doc %{_mandir}/man1/%{name}.1.gz

%changelog
