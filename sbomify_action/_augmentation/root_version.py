"""A root-component version for projects that never state one.

Measured over 500 open source projects, only 27% of generated SBOMs carried a
root version a consumer could do anything with. 35% said ``latest``, 22% were a
bare content hash, and 14% had no version at all. None of those can be matched
against a CVE feed, which is most of what a root version is for.

The generators are not at fault: cdxgen writes ``latest`` because the manifest
it read does not carry a version, and syft writes a digest because a directory
does not have one either. The information is elsewhere -- in the checkout.

Two sources, in order of how much they can be trusted:

1. **A tag.** If the checkout sits on one, that is the version the project
   published, and there is nothing to invent.
2. **A commit.** Otherwise ``0.0.0+g<short-sha>``, which is deliberately not a
   version anyone released. The ``0.0.0`` says "no release claimed" and the
   build metadata says exactly which commit this describes, so the document
   stays traceable without pretending to be something a registry would know.

The second is a real trade-off and worth naming: ``0.0.0+g1a2b3c4`` matches no
CVE feed either. What it buys over ``latest`` is that two SBOMs of two
different commits are no longer indistinguishable, and nobody can mistake it
for a release. An explicitly configured version always wins over both.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from sbomify_action.logging_config import logger

#: Values that carry no information about which build this is.
_PLACEHOLDERS = {"latest", "unknown", "none", "n/a", "0.0.0", ""}

#: syft names a directory by hashing it, which is stable but meaningless to a
#: consumer -- and long enough that nothing else looks like it.
_CONTENT_HASH = re.compile(r"^(sha256:)?[0-9a-f]{32,}$", re.IGNORECASE)

_GIT_TIMEOUT = 15


def is_placeholder_version(version: str | None) -> bool:
    """Whether this version tells a consumer nothing about which build it is."""
    if version is None:
        return True
    v = version.strip()
    return v.lower() in _PLACEHOLDERS or bool(_CONTENT_HASH.match(v))


def _ci_tag() -> str | None:
    """The tag this build is for, according to the CI system running it.

    Preferred over asking git because a CI checkout is frequently a detached
    head or a shallow clone with no tags fetched at all, where `git describe`
    knows nothing while the environment knows exactly.
    """
    if os.getenv("GITHUB_REF_TYPE") == "tag":
        if name := os.getenv("GITHUB_REF_NAME"):
            return name
    if ref := os.getenv("GITHUB_REF", ""):
        if ref.startswith("refs/tags/"):
            return ref[len("refs/tags/") :]
    # GitLab and Bitbucket set these only for tag builds, so their presence is
    # itself the signal.
    return os.getenv("CI_COMMIT_TAG") or os.getenv("BITBUCKET_TAG") or None


def _ci_sha() -> str | None:
    return os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or os.getenv("BITBUCKET_COMMIT") or None


#: Repository-local settings that make git run a program, neutralised before
#: we run anything inside a checkout we did not create.
#:
#: The directory is the *subject* of the scan, not something we authored: for
#: a GitHub Action it is whatever the workflow checked out, and for this
#: project's own evaluation it is a clone of an arbitrary third-party
#: repository. git reads that repository's own `.git/config`, and
#: `core.fsmonitor` names a command git executes.
#:
#: Measured, because the tempting claim here is stronger than the truth: the
#: two commands below do **not** trigger it. `core.fsmonitor` runs when the
#: index is refreshed, which `git status` does and which `rev-parse HEAD` and
#: `describe --exact-match` do not. A payload wired into a test repository
#: fires on `status` and stays cold for both of ours.
#:
#: It is set anyway, because the distance between safe and unsafe here is one
#: plausible edit. `git describe --dirty` -- the obvious way to notice a
#: modified tree -- refreshes the index, and would turn a version lookup into
#: code execution with no other change. `-c` outranks repository config, so
#: this makes that edit safe by construction rather than by review.
#:
#: The user's *global* config is deliberately left alone: wiping it would also
#: discard any safe.directory entries, and without those git refuses to read a
#: checkout owned by another uid -- the normal case in a container -- turning a
#: working lookup into "cannot tell".
_GIT_SAFE_CONFIG = (
    "-c",
    "core.fsmonitor=",
    "-c",
    "core.hooksPath=/dev/null",
)


def _git(source_dir: Path, *args: str) -> str | None:
    """Ask git, and treat every way of not knowing as the same answer.

    A source directory can be a tarball with no .git, a shallow clone with no
    tags, or a checkout git refuses to read because it is owned by another
    uid -- which is the normal case in a container. None of those is an error
    worth surfacing: they all mean "git cannot tell us", and the caller has a
    fallback.

    ``--no-optional-locks`` because this is someone else's working tree and a
    question should not write an index.lock into it.
    """
    try:
        done = subprocess.run(
            ["git", "--no-optional-locks", *_GIT_SAFE_CONFIG, "-C", str(source_dir), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug(f"git {' '.join(args)} failed in {source_dir}: {exc}")
        return None
    if done.returncode != 0:
        return None
    return done.stdout.strip() or None


def resolve_root_version(source_dir: str | Path | None) -> str | None:
    """Derive a root version from the checkout, or None if nothing is knowable.

    Args:
        source_dir: The project directory. May be None when the subject is a
            container image rather than a source tree, in which case only the
            CI environment can answer.

    Returns:
        A tag as-is, ``0.0.0+g<short-sha>`` for an untagged commit, or None.
    """
    if tag := _ci_tag():
        logger.debug(f"Root version from the CI tag: {tag}")
        return tag

    directory = Path(source_dir) if source_dir else None
    if directory and directory.is_dir():
        if tag := _git(directory, "describe", "--exact-match", "--tags", "HEAD"):
            logger.debug(f"Root version from the checkout's tag: {tag}")
            return tag

    sha = _ci_sha()
    if not sha and directory and directory.is_dir():
        sha = _git(directory, "rev-parse", "HEAD")
    if not sha:
        return None

    short = sha[:8]
    if not re.fullmatch(r"[0-9a-f]{8}", short, re.IGNORECASE):
        return None
    # SemVer build metadata: ordered after the release it hangs off, and
    # ignored for precedence, which is right -- this is not a release.
    return f"0.0.0+g{short}"
