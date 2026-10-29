#!/usr/bin/env bash
# Commit the image pin to branch release/vVERSION and create draft release
# vVERSION on that commit. Run from the repo root, checked out at the commit
# being released, by .github/workflows/release.yml.
#
# Safe to run again for the same VERSION and DIGEST, so "Re-run failed jobs"
# can finish a run that pushed the branch but did not draft: a branch already
# holding this pin is reused instead of recommitted (the new commit's date
# would make the push non-fast-forward), and so is a draft vVERSION on it.
# Any other release/vVERSION or release vVERSION is refused.
#
# Usage: scripts/draft_release.sh VERSION sha256:DIGEST
set -euo pipefail

version=$1
digest=$2
tag=v${version}
branch=release/${tag}

"$(dirname "$0")/pin_release_image.sh" "$version" "$digest" # validates both, pins the working tree

if [ -z "$(git ls-remote origin "refs/heads/${branch}")" ]; then
  git commit --quiet --all \
    -m "Release ${tag}: pin image to ${digest}" \
    -m "action.yml, pipe.yml and the Bitbucket sample run sbomify-action:${version}@${digest}, so ${tag} keeps running this image after :latest moves on."
  git push --quiet origin "HEAD:refs/heads/${branch}"
  pin_sha=$(git rev-parse HEAD)
else
  git fetch --quiet origin "refs/heads/${branch}"
  # Compare trees, not commits: a re-run's commit differs only in its date.
  if ! git diff --quiet FETCH_HEAD; then
    echo "::error::${branch} exists but is not $(git rev-parse HEAD) pinned to ${version}@${digest}." \
      "If it is left from another run, delete it and any draft ${tag}, then run the Release workflow again."
    exit 1
  fi
  pin_sha=$(git rev-parse FETCH_HEAD)
fi

# Listed rather than looked up by tag: a draft has no tag yet. Only a token
# that can push sees drafts, which is why release.yml's check job cannot.
releases=$(gh api --paginate "repos/{owner}/{repo}/releases" |
  jq -r --arg tag "$tag" '.[] | select(.tag_name == $tag) | "\(.draft) \(.target_commitish) \(.html_url)"')
url=${releases##* }
if [ -z "$releases" ]; then
  url=$(gh release create "$tag" --draft --target "$pin_sha" --title "$tag" --generate-notes)
elif [ "$releases" != "true ${pin_sha} ${url}" ]; then
  echo "::error::Release ${tag} already exists, and is not one draft on ${pin_sha}" \
    "(draft, target, URL: ${releases//$'\n'/; }). Delete any stale draft ${tag}, then re-run the failed jobs."
  exit 1
fi

{
  echo "## Draft release ${tag} is ready to review"
  echo
  echo "- Image: \`ghcr.io/sbomify/sbomify-action:${version}@${digest}\`, mirrored to \`sbomifyhub/sbomify-action\`"
  echo "- Pin commit: \`${pin_sha}\` on branch \`${branch}\`"
  echo "- Draft: ${url}"
  echo
  echo "Review the draft and publish it. Publishing creates tag \`${tag}\`, which runs the CI/CD Pipeline" \
    "(its verify-release-pin job checks this pin), PyPI, license-db and the production SBOMs."
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
