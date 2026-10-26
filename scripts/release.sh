#!/usr/bin/env bash
# Cut a release from origin/master, after the version bump has merged.
#
# action.yml is read from the tag, and on master it says :latest. So the tag
# goes on a commit one step off master that pins the image to :<version>;
# only the tag is pushed. The sbom-tools release is already pinned in
# tools.toml and goes at the top of the release notes.
#
# Usage: scripts/release.sh [--dry-run]
set -euo pipefail

IMAGE="ghcr.io/sbomify/sbomify-action"
cd "$(git rev-parse --show-toplevel)"
git fetch --quiet --tags origin master

VERSION=$(git show origin/master:pyproject.toml | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1)
TAG="v${VERSION}"
TOOLS_RELEASE=$(git show origin/master:sbomify_action/tools.toml | sed -n 's/^tools_release = "\(.*\)"$/\1/p')

if git rev-parse --quiet --verify "refs/tags/${TAG}" >/dev/null; then
    echo "error: ${TAG} already exists; merge a version bump first" >&2
    exit 1
fi

WORKTREE=$(mktemp -d)
trap 'git worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true' EXIT
git worktree add --quiet --detach "$WORKTREE" origin/master
sed -i "s#docker://${IMAGE}:latest#docker://${IMAGE}:${VERSION}#" "$WORKTREE/action.yml"
git -C "$WORKTREE" commit --quiet -S -m "Release ${TAG}" action.yml
git -C "$WORKTREE" tag -s "$TAG" -m "sbomify-action ${TAG} (sbom-tools ${TOOLS_RELEASE})"
echo "${TAG}: ${IMAGE}:${VERSION}, sbom-tools ${TOOLS_RELEASE}"

if [[ "${1:-}" == "--dry-run" ]]; then
    git tag -d "$TAG" >/dev/null
    exit 0
fi

git push --quiet origin "refs/tags/${TAG}"
gh release create "$TAG" --verify-tag --title "$TAG" --generate-notes \
    --notes "**sbom-tools:** [\`${TOOLS_RELEASE}\`](https://github.com/sbomify/sbom-tools/releases/tag/${TOOLS_RELEASE})"
