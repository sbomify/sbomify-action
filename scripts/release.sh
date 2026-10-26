#!/usr/bin/env bash
# Cut a release of sbomify-action from origin/master.
#
# Run after the "Bump version to X" PR has merged; the version comes from
# pyproject.toml on origin/master.
#
# A release has to be pinned end to end, and master must not be:
#
#   * sbom-tools: tools.toml pins a cut sbom-tools release on master already,
#     so there is nothing to write -- this only checks the pin is real.
#   * the image: action.yml names the image a `uses:` runs, and is read from
#     the tag. On master it says :latest, which is what @master should run.
#     At a tag it must say :<version>, or `uses: sbomify/sbomify-action@vX`
#     runs the master image and, through it, sbom-tools master.
#
# So the tag points at a commit of its own, one step off master, carrying the
# pinned action.yml. Only the tag is pushed; master never sees the pin. CI
# refuses a tag whose action.yml does not name its own image.
#
# Then the GitHub release is created with the sbom-tools release at the top of
# its notes, which also triggers the PyPI publish.
#
# Usage: scripts/release.sh [--dry-run]
#
# Needs: git with commit/tag signing configured, gh authenticated with push
# access to sbomify/sbomify-action.

set -euo pipefail

REPO="sbomify/sbomify-action"
TOOLS_REPO="sbomify/sbom-tools"
IMAGE="ghcr.io/sbomify/sbomify-action"

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
elif [[ $# -gt 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

git fetch --quiet --tags origin master

VERSION=$(git show origin/master:pyproject.toml | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1)
if [[ -z "$VERSION" ]]; then
    echo "error: could not read the version from pyproject.toml on origin/master" >&2
    exit 1
fi
TAG="v${VERSION}"

if git rev-parse --quiet --verify "refs/tags/${TAG}" >/dev/null; then
    echo "error: ${TAG} already exists. Merge a version bump first." >&2
    exit 1
fi

TOOLS_RELEASE=$(git show origin/master:sbomify_action/tools.toml \
    | python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["tools_release"])')
if [[ "$TOOLS_RELEASE" == "tools-rolling" ]]; then
    echo "error: tools.toml pins tools-rolling; pin a cut sbom-tools release first" >&2
    exit 1
fi
if ! TOOLS_STATE=$(gh release view "$TOOLS_RELEASE" --repo "$TOOLS_REPO" --json isDraft,isPrerelease \
    --jq 'if .isDraft then "draft" elif .isPrerelease then "prerelease" else "ok" end'); then
    echo "error: ${TOOLS_RELEASE} is not a release of ${TOOLS_REPO}" >&2
    exit 1
fi
if [[ "$TOOLS_STATE" != "ok" ]]; then
    echo "error: ${TOOLS_REPO} ${TOOLS_RELEASE} is a ${TOOLS_STATE}" >&2
    exit 1
fi

# Not fatal: master may be fine on the pinned bundles. But anything sbom-tools
# master has that the pin lacks was what master tested against, not this.
AHEAD=$(gh api "repos/${TOOLS_REPO}/compare/${TOOLS_RELEASE}...master" --jq '.ahead_by' 2>/dev/null || echo "?")
if [[ "$AHEAD" != "0" ]]; then
    echo "warning: ${TOOLS_REPO} master is ${AHEAD} commit(s) ahead of ${TOOLS_RELEASE}." >&2
    echo "         If this release needs any of them, cut an sbom-tools release and bump the pin first." >&2
fi

WORKTREE=$(mktemp -d)
trap 'git worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true' EXIT
git worktree add --quiet --detach "$WORKTREE" origin/master

LATEST_LINE="  image: 'docker://${IMAGE}:latest'"
PINNED_LINE="  image: 'docker://${IMAGE}:${VERSION}'"
if ! grep -qxF "$LATEST_LINE" "$WORKTREE/action.yml"; then
    echo "error: action.yml on origin/master does not use the :latest image" >&2
    exit 1
fi
python3 - "$WORKTREE/action.yml" "$LATEST_LINE" "$PINNED_LINE" <<'EOF'
import sys
from pathlib import Path

path, old, new = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
path.write_text(path.read_text().replace(old, new, 1))
EOF

git -C "$WORKTREE" commit --quiet -S -m "Release ${TAG}

Pins the action image to ${IMAGE}:${VERSION}.
Runtime toolchain: ${TOOLS_REPO} ${TOOLS_RELEASE}." action.yml
git -C "$WORKTREE" tag -s "$TAG" -m "sbomify-action ${TAG} (sbom-tools ${TOOLS_RELEASE})"

NOTES="**Runtime toolchain:** [${TOOLS_REPO} \`${TOOLS_RELEASE}\`](https://github.com/${TOOLS_REPO}/releases/tag/${TOOLS_RELEASE})
**Image:** \`${IMAGE}:${VERSION}\`
"

echo "Release ${TAG}"
echo "  commit:   $(git -C "$WORKTREE" rev-parse HEAD) (parent $(git rev-parse --short origin/master))"
echo "  image:    ${IMAGE}:${VERSION}"
echo "  toolchain: ${TOOLS_REPO} ${TOOLS_RELEASE}"

if $DRY_RUN; then
    git tag -d "$TAG" >/dev/null
    echo "Dry run: nothing pushed."
    exit 0
fi

git push --quiet origin "refs/tags/${TAG}"
gh release create "$TAG" --repo "$REPO" --verify-tag --title "$TAG" --notes "$NOTES" --generate-notes
