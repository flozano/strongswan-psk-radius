#!/bin/bash
#
# Sign RPMs with the release key and check them against the public key in the
# repository. Run inside an EL9 container, as the CI release does.
#
# Usage:
#     RPM_SIGNING_KEY="$(cat secret-key.asc)" contrib/sign-rpms.sh out/*.rpm
#
# RPM_SIGNING_KEY is the armored secret key, without a passphrase.
#
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
PUBKEY="$SRC/RPM-GPG-KEY-strongswan-psk-radius"

[ -n "${RPM_SIGNING_KEY:-}" ] || { echo "RPM_SIGNING_KEY is not set"; exit 1; }
[ $# -gt 0 ] || { echo "usage: $0 file.rpm..."; exit 1; }

dnf -y -q install rpm-sign gnupg2 >/dev/null

export GNUPGHOME=$(mktemp -d)
trap 'gpgconf --kill gpg-agent; rm -rf "$GNUPGHOME"' EXIT
printf '%s\n' "$RPM_SIGNING_KEY" | gpg --batch --quiet --import
FPR=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr:/ { print $10; exit }')

rpmsign --define "_gpg_name $FPR" --addsign "$@"

# The signatures must verify with the key users import, not just the one in
# the secret.
rpmkeys --import "$PUBKEY"
for rpm in "$@"; do
	out=$(rpmkeys --checksig "$rpm" 2>&1) || true
	echo "$out"
	[[ "$out" == *": digests signatures OK" ]] || { echo "bad signature: $rpm"; exit 1; }
done
