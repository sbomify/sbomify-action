"""Resolve a git submodule's pinned commit to an SBOM version string.

When the action runs in submodule mode (``SUBMODULE_PATH`` set), the
component's SBOM version must identify the *submodule's* pinned state,
not the parent repo's release version. The submodule's own CI publishes
SBOMs versioned either by a git tag (tag-strategy workflows) or by the
short commit SHA (trunk-strategy workflows use ``git rev-parse --short
HEAD``). To find — or backfill — the matching SBOM, we resolve the pin
the same way:

1. a version-shaped tag (``v1.2.3``, ``1.2.3``, CalVer) pointing at the
   pinned commit, resolved via ``git ls-remote --tags`` against the
   submodule's remote (works without the submodule being initialised);
2. otherwise the 7-char short SHA.

Matching is exact on purpose: a pin that is 14 commits past ``v1.2.3``
must NOT resolve to ``v1.2.3`` — attaching that SBOM would misrepresent
what the release ships. No ``git describe``-style nearest-tag logic.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .logging_config import logger

# Local git plumbing (ls-tree, rev-parse, config) is fast; ls-remote
# talks to the network and gets a generous budget.
_LOCAL_TIMEOUT = 10
_REMOTE_TIMEOUT = 30

# Version-shaped tags, mirroring the tag patterns wizard-emitted
# workflows trigger on (``v*`` + ``[0-9]*``): v-prefixed or bare-numeric
# SemVer / CalVer.
_VERSION_TAG_RE = re.compile(r"^v?\d")

_SHORT_SHA_LEN = 7


@dataclass(frozen=True)
class SubmodulePin:
    """The resolved state of one submodule pin."""

    path: str
    """Submodule path relative to the parent repo root."""

    sha: str
    """Full commit SHA the parent tree pins the submodule to."""

    version: str
    """SBOM version string the submodule's CI would have published
    under: an exact version tag when one points at :attr:`sha`,
    otherwise the short SHA."""

    version_source: Literal["tag", "sha"]


def _run_git(args: list[str], *, cwd: Path, timeout: int = _LOCAL_TIMEOUT) -> str | None:
    """Run ``git <args>``; return stripped stdout, or None on any failure.

    ``-c safe.directory=*`` keeps the commands working when the workspace
    is bind-mounted into a container under a different UID (same
    rationale as the wizard's repo_facts helper). All commands here are
    read-only.
    """
    try:
        result = subprocess.run(
            ["git", "-c", "safe.directory=*", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _gitlink_sha(repo_root: Path, submodule_path: str) -> str | None:
    """The commit SHA the parent tree records for ``submodule_path``.

    Read from the parent's tree (``ls-tree`` mode 160000), so it works
    even when the submodule was never initialised or checked out.
    """
    out = _run_git(["ls-tree", "HEAD", "--", submodule_path], cwd=repo_root)
    if not out:
        return None
    # "<mode> <type> <sha>\t<path>" — a gitlink is mode 160000 / type commit.
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "160000" and parts[1] == "commit":
            return parts[2]
    return None


def _embedded_repo_sha(repo_root: Path, submodule_path: str) -> str | None:
    """HEAD of a vendored clone (its own ``.git``, no gitlink in the tree)."""
    candidate = repo_root / submodule_path
    if not (candidate / ".git").exists():
        return None
    return _run_git(["-C", str(candidate), "rev-parse", "HEAD"], cwd=repo_root)


def _submodule_url(repo_root: Path, submodule_path: str) -> str | None:
    """The remote URL ``.gitmodules`` declares for ``submodule_path``.

    Uses ``git config -f .gitmodules`` so quoting/escaping is handled by
    git itself rather than a hand-rolled parser.
    """
    if not (repo_root / ".gitmodules").is_file():
        return None
    mapping = _run_git(["config", "-f", ".gitmodules", "--get-regexp", r"^submodule\..*\.path$"], cwd=repo_root)
    if not mapping:
        return None
    for line in mapping.splitlines():
        key, _, value = line.partition(" ")
        if value.strip().rstrip("/") == submodule_path.rstrip("/"):
            # key = submodule.<name>.path → submodule.<name>.url
            url_key = key[: -len(".path")] + ".url"
            return _run_git(["config", "-f", ".gitmodules", "--get", url_key], cwd=repo_root)
    return None


def _tags_at_sha_remote(repo_root: Path, url: str, sha: str) -> list[str]:
    """Tags on ``url`` whose target commit is ``sha``.

    Runs with the parent repo as cwd so repo-local auth config (e.g. the
    ``http.<url>.extraheader`` credential actions/checkout installs)
    applies to the remote call. Annotated tags are resolved through
    their peeled (``^{}``) entries, which override the tag-object SHA.

    ``url`` comes from the scanned repo's ``.gitmodules``, so it is
    untrusted input: it is passed after ``--`` so a leading-dash value
    cannot be read as an option (``--upload-pack=...`` would otherwise
    execute a command, silently — ``_run_git`` swallows the failure).
    """
    out = _run_git(["ls-remote", "--tags", "--", url], cwd=repo_root, timeout=_REMOTE_TIMEOUT)
    if not out:
        return []
    targets: dict[str, str] = {}
    for line in out.splitlines():
        line_sha, _, ref = line.partition("\t")
        line_sha = line_sha.strip()
        ref = ref.strip()
        if not ref.startswith("refs/tags/"):
            continue
        tag = ref[len("refs/tags/") :]
        if tag.endswith("^{}"):
            # Peeled entry: the commit an annotated tag points at — this
            # is the SHA that matches the gitlink, so it wins.
            targets[tag[: -len("^{}")]] = line_sha
        else:
            targets.setdefault(tag, line_sha)
    return [tag for tag, target in targets.items() if target == sha]


def _tags_at_sha_local(repo_root: Path, submodule_path: str, sha: str) -> list[str]:
    """Tags in the checked-out submodule's own clone pointing at ``sha``.

    Fallback for when there is no usable remote URL (vendored clones) or
    the remote call failed. Shallow submodule checkouts often carry no
    tags at all, so an empty result here is normal.
    """
    candidate = repo_root / submodule_path
    if not (candidate / ".git").exists():
        return []
    out = _run_git(["-C", str(candidate), "tag", "--points-at", sha], cwd=repo_root)
    if not out:
        return []
    return out.splitlines()


def _pick_version_tag(tags: list[str]) -> str | None:
    """Deterministically choose one version-shaped tag.

    v-prefixed tags win over bare-numeric ones (the dominant convention,
    and the first pattern wizard-emitted workflows trigger on);
    lexicographic order breaks remaining ties.
    """
    candidates = sorted(
        (tag.strip() for tag in tags if _VERSION_TAG_RE.match(tag.strip())),
        key=lambda tag: (0 if tag.startswith("v") else 1, tag),
    )
    return candidates[0] if candidates else None


def resolve_submodule_pin(repo_root: Path, submodule_path: str) -> SubmodulePin | None:
    """Resolve the pinned commit + SBOM version for ``submodule_path``.

    Returns None when the path is neither a gitlink in the parent tree
    nor a vendored clone with its own ``.git`` — the caller treats that
    as a configuration error.
    """
    repo_root = repo_root.resolve()
    normalized = submodule_path.strip().strip("/")

    sha = _gitlink_sha(repo_root, normalized)
    if not sha:
        sha = _embedded_repo_sha(repo_root, normalized)
    if not sha:
        return None

    tags: list[str] = []
    url = _submodule_url(repo_root, normalized)
    if url:
        tags = _tags_at_sha_remote(repo_root, url, sha)
        if not tags:
            logger.debug(f"No remote tags at {sha} for submodule '{normalized}' (url: {url})")
    if not tags:
        tags = _tags_at_sha_local(repo_root, normalized, sha)

    if tag := _pick_version_tag(tags):
        return SubmodulePin(path=normalized, sha=sha, version=tag, version_source="tag")
    return SubmodulePin(path=normalized, sha=sha, version=sha[:_SHORT_SHA_LEN], version_source="sha")
