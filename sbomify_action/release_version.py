"""The version of the thing being scanned, taken from the release that triggered the build.

On a tag-triggered workflow the tag is already in the environment, and until
now nothing read it: ``COMPONENT_VERSION`` was the only source, so a release
build that did not set it got whatever version the generator guessed from the
manifest -- frequently ``latest``, a content hash, or nothing.

The conventions below are not invented. They come from resolving 500 popular
open source projects to their releases, which is the only way to find out that
curl tags ``curl-8_21_0``, Hadoop tags ``rel/release-3.5.0``, ZooKeeper tags
``release-3.9.5``, Netty tags ``netty-4.2.17.Final`` and Svelte tags
``svelte@5.56.8``. Of 446 projects with a usable release tag, 403 tag a clean
version and 43 do something a consumer cannot match against a registry or a
CVE feed without help.

Three things happen here, and they are deliberately separable:

* **Reading the tag.** No invention: if the build is not tag-triggered there is
  no version to take, and this returns nothing rather than fabricating one.
* **Normalising it.** ``curl-8_21_0`` into ``8.21.0``. Opt-in, because it
  rewrites what the project itself called the release, and some users would
  rather their SBOM say exactly what the tag said.
* **Noticing the tag names something else.** A monorepo that tags per package
  -- ``meta-v1.3.0`` in dart-lang/sdk -- would otherwise stamp one package's
  version onto the whole repository's SBOM. That is always warned about and
  never guessed at.
"""

from __future__ import annotations

import os
import re

from .logging_config import logger

#: Prefixes that carry no information about which project this is, so a tag
#: wearing one is still a release of the repository it lives in.
_GENERIC_PREFIXES = ("releases", "release", "rel", "version", "ver", "tags", "tag", "v")


def tag_from_ci() -> str | None:
    """The tag this build was triggered by, according to the CI system.

    Only a tag counts. A branch build has no released version to claim, and
    saying otherwise would be worse than saying nothing.
    """
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        if name := os.environ.get("GITHUB_REF_NAME"):
            return name
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        return ref[len("refs/tags/") :]
    # GitLab and Bitbucket set these only on a tag build, so their presence is
    # itself the signal.
    return os.environ.get("CI_COMMIT_TAG") or os.environ.get("BITBUCKET_TAG") or None


#: One parse for both questions: what is the version, and whose release is it?
#:
#: The prefix is non-greedy so it stops at the first place a version can start,
#: and the optional ``v`` is consumed outside the prefix so ``v1.2.3`` has no
#: prefix at all rather than a prefix of ``v``. Everything after the numeric
#: core is kept, because a suffix a project chose -- ``.Final``, ``-stable`` --
#: is part of how it names the artifact.
_TAG = re.compile(
    r"^(?P<prefix>.*?)v?(?P<core>\d+(?:[._]\d+)*)(?P<suffix>.*)$",
    re.IGNORECASE,
)


def _squash(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def _parse(tag: str) -> tuple[str, str, str] | None:
    """Split a tag into (prefix, numeric core, suffix), or None if it has no version."""
    if not tag:
        return None
    match = _TAG.match(tag.split("/")[-1])
    if not match:
        return None
    prefix = match.group("prefix").rstrip("-_@./")
    return prefix, match.group("core"), match.group("suffix")


def names_another_package(tag: str, repo_name: str | None) -> bool:
    """Whether this tag looks like a release of something other than this repo.

    A monorepo that tags per package produces ``meta-v1.3.0`` or
    ``xdg_directories-v1.1.0``. Stamping one of those onto the repository's
    SBOM would claim the whole project is at a version only one package ever
    had, which is worse than having no version at all.

    Only decidable when the repository name is known, and deliberately
    conservative: a prefix matching the repository, or a generic one, is not
    another package.
    """
    if not repo_name:
        return False
    parsed = _parse(tag)
    if not parsed:
        return False
    prefix = parsed[0]
    if not prefix:
        return False
    return prefix.lower() not in _GENERIC_PREFIXES and _squash(prefix) != _squash(repo_name)


def normalize_release_version(tag: str, repo_name: str | None = None) -> str | None:
    """Reduce a release tag to the version a registry would recognise.

    ``curl-8_21_0`` becomes ``8.21.0``; ``rel/release-3.5.0`` becomes ``3.5.0``;
    ``svelte@5.56.8`` becomes ``5.56.8``; ``netty-4.2.17.Final`` keeps its
    finality suffix, because that is part of how Netty names the artifact.

    Returns None when the tag holds no version at all, so the caller can fall
    back to the tag itself rather than to something invented.
    """
    parsed = _parse(tag)
    if not parsed:
        return None
    _prefix, core, suffix = parsed
    # curl writes 8_21_0 for 8.21.0; nothing else uses underscores this way.
    return core.replace("_", ".") + suffix


def version_from_release_tag(repo_name: str | None, normalize: bool) -> tuple[str | None, str | None]:
    """The component version for this build, and a warning if one is warranted.

    Returns ``(version, warning)``. A version of None means the build is not
    tag-triggered, or the tag names a different package; in both cases the
    caller should leave whatever the generator produced alone.
    """
    tag = tag_from_ci()
    if not tag:
        return None, None

    if names_another_package(tag, repo_name):
        return None, (
            f"This build is tagged {tag!r}, which looks like a release of a different package "
            f"rather than of {repo_name!r}. The SBOM's version has been left as the generator "
            "produced it; set COMPONENT_VERSION if that is wrong."
        )

    if not normalize:
        return tag, None

    normalized = normalize_release_version(tag, repo_name)
    if normalized is None:
        logger.debug(f"No version could be extracted from the tag {tag!r}; using it as-is")
        return tag, None
    if normalized != tag:
        logger.info(f"Normalised the release tag {tag!r} to version {normalized!r}")
    return normalized, None
