---
name: cut-release
description: Cut a new sbomify-action release and write its release notes. Thin pointer to the org-wide sbomify release skill, plus the facts specific to this repo. Use whenever the user says "cut a release", "ship a release", "tag a release", "make a new release", or asks for release notes.
---

# Cut a release

The release process is shared by every repo in the `sbomify` org and lives in
one place: the **`sbomify-release`** skill, kept in the sbomify knowledge base
under `skills/release/` (`SKILL.md` for the process, `repos.md` for per-repo
profiles). Load and follow it. Do not copy its steps here: copies drift.

If the `sbomify-release` skill is not installed for you, ask a maintainer for
access rather than improvising a process.

## What is specific to this repo

The shared skill's `repos.md` has the full profile. The essentials:

- **Version:** CalVer `YY.MM.MICRO`, mandatory for every sbomify repo
  ([ADR-0002](https://github.com/sbomify/adr/blob/master/0002-adopt-calver-versioning.md)).
- **Release PR** bumps only `pyproject.toml` and the sbomify-action entry in
  `uv.lock`. Branch `chore/release-<version>`, title
  `chore(release): <version>`.
- **`sbomify_action/tools.toml` pins an `sbom-tools` release.** If this
  release should ship new bundled tools, release `sbom-tools` first, then bump
  the pin in the release PR.
- **API changes in sbomify** that the action relies on ship first; release
  the action after them.
- **Tag `v<version>`** on the merge commit, after `master` CI is green. The
  tag uploads this repo's SBOM (`.github/workflows/sbomify.yaml`).
- **Publishing the GitHub release uploads to PyPI**
  (`.github/workflows/pypi.yaml`). Create the release as a draft, get the
  notes right, then publish.
