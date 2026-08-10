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
* **Normalizing it.** ``curl-8_21_0`` into ``8.21.0``. Opt-in, because it
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
#:
#: ``parent`` is here for Maven, which tags a project's aggregator POM
#: ``<project>-parent-<version>``. Gson's newer tags are all
#: ``gson-parent-2.9.1``, and without it every one of them reads as a release
#: of some other package.
_GENERIC_PREFIXES = ("releases", "release", "rel", "version", "ver", "tags", "tag", "v", "parent")

#: A prerelease marker separated from the number: -rc.1, .dev, -alpha2,
#: +preview. The separator matters -- without it, "beta" would match the "b"
#: in a hash and "m" would match half the words in English.
#: ``\d*(?![A-Za-z])`` rather than ``\b``: there is no word boundary between
#: "preview" and the 3 in ``v1.0.0-preview3``, so a plain ``\b`` misses every
#: numbered marker. The trailing lookahead is what keeps "beta" from matching
#: inside a longer word.
_PRERELEASE = re.compile(
    r"(?:^|[-._+])(?:alpha|beta|rc|dev|pre|preview|snapshot|nightly|canary|milestone"
    r"|unstable|experimental|next|edge|insiders?)\d*(?![A-Za-z])",
    re.IGNORECASE,
)

#: The same thing welded to the number, which is the form that gets missed.
#: Django tags alphas ``6.1a1`` and Hadoop tagged ``0.92RC0``; both sort above
#: every stable release of their project under a numeric comparison, and both
#: read as stable to anything checking for a hyphen.
_WELDED_PRERELEASE = re.compile(r"\d(?:a|b|rc|m)\d+$", re.IGNORECASE)


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


#: Separators a project may put between its name and the version.
_SEPARATORS = "-_@./"

#: A version, once we know where it starts: an optional ``v``, a numeric core,
#: and whatever the project chose to append -- ``.Final``, ``-stable``.
_VERSION_AT = re.compile(r"^v?(?P<core>\d+(?:[._]\d+)*)(?P<suffix>.*)$", re.IGNORECASE)


def _squash(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def _parse(tag: str) -> tuple[str, str, str] | None:
    """Split a tag into (prefix, numeric core, suffix), or None if it has no version.

    A version may only begin at the start of the tag or immediately after a
    separator, and the earliest such position wins.

    Both halves of that rule were learned the hard way. A single regex with a
    non-greedy prefix stopped at the *first digit anywhere*, so ``bzip2-1.0.8``
    parsed as prefix "bzip", core "2", suffix "-1.0.8" -- which normalized to
    "2-1.0.8" and, because "bzip" is not "bzip2", was refused as a release of
    a different package. Every project with a digit in its name was affected:
    log4j, libxml2, sqlite3, s2n-tls.

    And the path is kept rather than discarded. Taking only the last segment
    made ``otelhttp/v1.20.0`` look like a bare version with no prefix, so a Go
    submodule's tag sailed past the foreign-package check and stamped its
    version on the whole repository. That is the Go multi-module convention,
    not a corner case.
    """
    if not tag:
        return None

    starts = [0] + [i + 1 for i, ch in enumerate(tag) if ch in _SEPARATORS]
    for start in starts:
        match = _VERSION_AT.match(tag[start:])
        if not match:
            continue
        prefix = tag[:start].rstrip(_SEPARATORS)
        return prefix, match.group("core"), match.group("suffix")
    return None


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

    # The prefix may be several segments -- `rel/release`, `releases/lucene`,
    # `gson-parent`. It names this project only if every segment is either a
    # generic word or the repository itself; one foreign segment is enough to
    # make the tag someone else's, which is what catches `packages/meta`.
    segments = [s for s in re.split(r"[-_@./]", prefix) if s]
    return not all(s.lower() in _GENERIC_PREFIXES or _squash(s) == _squash(repo_name) for s in segments)


def is_prerelease(version: str | None) -> bool:
    """Whether this version names a prerelease rather than a shipped release.

    sbomify's Release model carries ``is_prerelease`` as a first-class,
    indexed field, and the action never set it -- so an alpha tagged into a
    product release was recorded as the product's current release, indexed
    alongside every genuine one.

    Both spellings are checked because only one of them is obvious. A
    separated marker (``v2.0.0-rc.1``) reads as a prerelease to anyone; a
    welded one does not. Django tags alphas ``6.1a1``, Hadoop tagged
    ``0.92RC0``, and Dart ships ``3.14.0-110.0.dev`` -- all prereleases, none
    of them matching a naive check for a hyphen.

    Deliberately conservative about what counts as a marker. Requiring a
    separator or a digit on both sides keeps ``1.2.3b`` out of it: a trailing
    letter with no number after it is a revision suffix in several ecosystems,
    not a beta.
    """
    if not version:
        return False
    text = version.strip()

    # Build metadata is not part of the release identity -- SemVer says it is
    # ignored for precedence -- and it is where hex lives. `1.0.0+build.9a12`
    # and `0.0.0+g1a234` both end in digit-letter-digits and were being
    # recorded as prereleases: a GA release vanishing from any view that
    # filters prereleases out, which is the mirror of the bug this fixes.
    release_part = text.split("+", 1)[0]
    return bool(_PRERELEASE.search(release_part) or _WELDED_PRERELEASE.search(release_part))


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
        logger.info(f"Normalized the release tag {tag!r} to version {normalized!r}")
    return normalized, None
