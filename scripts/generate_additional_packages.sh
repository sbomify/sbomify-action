#!/bin/bash
# Thin wrapper kept so existing callers keep working.
#
# The versions themselves now live in sbomify_action/tools.toml -- see
# scripts/additional_packages.py. This script used to scrape them back out of
# the Dockerfile with sed, which meant a tool could be removed from the image
# and still be declared in our own SBOM (or, as happened, break every workflow
# the moment an ARG disappeared).
#
#   sourced   exports <TOOL>_VERSION for each pinned tool
#   executed  prints the PURLs for tools the image actually contains
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

eval "$(cd "$SCRIPT_DIR/.." && "$PY" scripts/additional_packages.py --env)"
for var in $(cd "$SCRIPT_DIR/.." && "$PY" scripts/additional_packages.py --env | cut -d= -f1); do
  export "${var?}"
done

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  (cd "$SCRIPT_DIR/.." && "$PY" scripts/additional_packages.py --stage image)
fi
