#!/usr/bin/env bash
# Fail unless action.yml and pipe.yml run the image released as VERSION,
# pinned to the digest GHCR and Docker Hub serve for that tag. Run from the
# repo root by the CI/CD Pipeline on every v* tag push.
#
# Usage: scripts/verify_release_pin.sh VERSION
set -euo pipefail

version=$1
ghcr=ghcr.io/sbomify/sbomify-action
hub=sbomifyhub/sbomify-action

image_of() { # every `image:` value in a YAML file, quotes dropped
  awk '$1 == "image:" { print $2 }' "$1" | tr -d "'\""
}

action=$(image_of action.yml)
pipe=$(image_of pipe.yml)
digest=${action##*@}

if [ "$action" != "docker://${ghcr}:${version}@${digest}" ] ||
  [ "$pipe" != "${hub}:${version}@${digest}" ]; then
  echo "::error::v${version} must pin its image by digest: action.yml needs" \
    "docker://${ghcr}:${version}@sha256:<digest> (has '${action}') and pipe.yml" \
    "${hub}:${version}@ the same digest (has '${pipe}'). Release with" \
    ".github/workflows/release.yml, not by tagging by hand."
  exit 1
fi

for image in "${ghcr}:${version}" "${hub}:${version}"; do
  if ! served=$(docker buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}'); then
    echo "::error::Could not inspect ${image}; release.yml should have pushed it."
    exit 1
  fi
  if [ "$served" != "$digest" ]; then
    echo "::error::${image} is ${served}, but v${version} pins ${digest}."
    exit 1
  fi
done

echo "v${version} pins ${digest}, which ${ghcr}:${version} and ${hub}:${version} serve."
