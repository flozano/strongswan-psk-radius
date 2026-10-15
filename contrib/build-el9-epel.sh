#!/bin/bash
#
# Build the plugin RPM for EL9 with EPEL's strongSwan, in a local container.
#
# Usage:
#     contrib/build-el9-epel.sh [strongswan version-release]   # e.g. 6.0.6-1.el9
#     -> out/*.rpm, out/BUILT_AGAINST
#
# Uses podman, or docker if podman is not installed.
#
set -euo pipefail

cd "$(dirname "$0")/.."
ENGINE=$(command -v podman || command -v docker)
"$ENGINE" run --rm -v "$PWD:/src:Z" docker.io/library/almalinux:9 \
	/src/contrib/build-rpm.sh "$@"
