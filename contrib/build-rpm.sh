#!/bin/bash
#
# Build the plugin RPM. Run inside an EL9 container (AlmaLinux, Rocky, RHEL
# UBI with EPEL), as the CI does; contrib/build-el9-epel.sh runs it locally.
#
# Configures and compiles EPEL's strongSwan source package as EPEL does, then
# builds the plugin against that tree and packages it.
#
# Usage:
#     contrib/build-rpm.sh [strongswan version-release]   # e.g. 6.0.6-1.el9
#     -> out/*.rpm, out/BUILT_AGAINST
#
# Without a version, builds against EPEL's current strongswan package.
#
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-}"
NAME=strongswan-psk-radius
PLUGIN_VERSION=$(sed -n 's/^Version:[[:space:]]*//p' "$SRC/packaging/$NAME.spec")

dnf -y -q install epel-release dnf-plugins-core rpm-build gcc make
dnf config-manager --set-enabled crb

WORK=$(mktemp -d)
cd "$WORK"
dnf -y -q download --source --enablerepo=epel-source "strongswan${VERSION:+-$VERSION}"
SRPM=$(ls strongswan-*.src.rpm)
dnf -y -q builddep "./$SRPM"
rpm -i "./$SRPM"

# %build only: the configured and compiled tree provides config.h and the libraries.
SPECS=$(rpm --eval '%{_specdir}')
rpmbuild -bc --nocheck "$SPECS/strongswan.spec" > "$WORK/rpmbuild-strongswan.log" 2>&1 ||
	{ tail -50 "$WORK/rpmbuild-strongswan.log"; exit 1; }
TREE=$(dirname "$(find "$(rpm --eval '%{_builddir}')" -maxdepth 3 -name config.h -path '*strongswan*' | head -1)")

EVR=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "./$SRPM" 2>/dev/null)
VER=$(rpm -qp --qf '%{VERSION}' "./$SRPM" 2>/dev/null)

tar -czf "$(rpm --eval '%{_sourcedir}')/$NAME-$PLUGIN_VERSION.tar.gz" \
	--transform "s,^,$NAME-$PLUGIN_VERSION/," -C "$SRC" \
	Makefile LICENSE README.md src packaging examples
rpmbuild -bb "$SRC/packaging/$NAME.spec" \
	--define "strongswan_src $TREE" \
	--define "strongswan_evr $EVR" \
	--define "strongswan_ver $VER"

mkdir -p "$SRC/out"
find "$(rpm --eval '%{_rpmdir}')" -name "$NAME-*.rpm" -exec cp {} "$SRC/out/" \;
echo "strongswan-$EVR" > "$SRC/out/BUILT_AGAINST"
ls -la "$SRC/out"
