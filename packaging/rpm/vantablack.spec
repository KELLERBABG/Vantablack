Name:           vantablack
Version:        2.1.0
Release:        1%{?dist}
Summary:        Post-quantum, cryptographically layered WAN mesh routing node
License:        MIT
URL:            https://github.com/KELLERBABG/Vantablack
BuildArch:      x86_64

%description
Vantablack is an autonomous peer-to-peer mesh routing daemon written in pure Rust,
featuring hybrid ML-KEM-768 / X25519 cryptography, Reed-Solomon RS(2,1) multi-path
sharding, ShardSec authentication, and built-in DNS/SNI/CNAME ad & tracker blocking.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/usr/share/icons/hicolor/scalable/apps
install -m 0755 %{_sourcedir}/ggn %{buildroot}/usr/bin/ggn
install -m 0755 %{_sourcedir}/ggn %{buildroot}/usr/bin/vantablack
install -m 0644 %{_sourcedir}/vantablack.desktop %{buildroot}/usr/share/applications/vantablack.desktop
install -m 0644 %{_sourcedir}/vantablack.service %{buildroot}/lib/systemd/system/vantablack.service
install -m 0644 %{_sourcedir}/icon.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/vantablack.svg

%files
/usr/bin/ggn
/usr/bin/vantablack
/usr/share/applications/vantablack.desktop
/lib/systemd/system/vantablack.service
/usr/share/icons/hicolor/scalable/apps/vantablack.svg
