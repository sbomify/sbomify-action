"""VCS detection by shelling out to ``git``, plus the ownership defence it needs.

This is the fallback that makes the action work on CI systems with no vendor
integration of their own, and on a developer's laptop. Where a vendor exposes
repository details -- GitHub Actions' environment, TeamCity's build properties
-- its platform uses those instead and this module never runs.

``git_safe_directory_env`` lives here rather than in ``_generation`` because
both the platforms and the generators need it and ``_runtime`` must stay free of
imports into the rest of the package: ``console`` resolves a platform while it
is still being imported, so anything a platform reaches would close a cycle.
``_generation.utils`` re-exports it, leaving its existing callers untouched.
"""

import logging
import os
import subprocess
from pathlib import Path

from .protocol import VcsInfo
from .vcs_url import normalize_repo_url

logger = logging.getLogger("sbomify_action")

GIT_TIMEOUT_SECONDS = 10

# Commit-URL layout per forge. Anything unrecognised gets no commit URL rather
# than a guessed one that 404s.
_COMMIT_PATH_BY_HOST: dict[str, str] = {
    "github.com": "commit",
    "gitlab.com": "-/commit",
    "bitbucket.org": "commits",
}

#: Forges whose self-hosted product keeps the same commit path as their cloud
#: one, so recognising them by host name is safe. Bitbucket is absent on
#: purpose -- see :func:`commit_url_for`.
_SELF_HOSTED_KEEPS_LAYOUT: tuple[str, ...] = ("github.com", "gitlab.com")


def git_safe_directory_env() -> dict[str, str]:
    """Environment that lets a *child process* read the bind-mounted workspace.

    The action already defends against git's "detected dubious ownership"
    guard, in ``submodule.py`` and the wizard's ``repo_facts.py``, by passing
    ``-c safe.directory=*`` on its own git commands. That does nothing for the
    generators, which do not run git themselves -- they run tools that do.
    Composer is the clearest case: it establishes the root package's version by
    asking git for the tag at HEAD, and when the workspace is mounted into the
    container under a different UID that call fails, so Composer falls back to
    ``1.0.0+no-version-set`` and any project depending on its own version stops
    resolving. On ``laravel/framework`` v13.24.0 that is the difference between
    0 components and 72.

    Passed through git's environment-based configuration rather than a config
    file, because there is no file to write that would not be either the
    user's own or a new thing to clean up: ``GIT_CONFIG_COUNT`` and its
    numbered key/value pairs are read by every git process in the tree and
    persist nowhere. The user's ``.gitconfig`` is not ours to edit, and the
    repository's belongs to whoever mounted it.

    Appended to any existing ``GIT_CONFIG_COUNT`` rather than assuming zero, so
    a caller who is already configuring git this way keeps their settings
    instead of having them silently dropped.

    Widening ``safe.directory`` does relax a guard whose purpose is to stop git
    from running config -- and therefore hooks -- out of a repository owned by
    someone else. Inside this container that is a workspace the user explicitly
    asked to scan, which is the same judgement the two existing call sites
    already make, and the alternative is a silently empty SBOM.

    The wildcard also sidesteps a trap in naming a concrete path: git matches
    ``safe.directory`` against the repository's *top-level*, not the directory
    the command runs in, so a value computed from the working directory would
    still be refused whenever WORKING_DIR points at a subdirectory.
    """
    try:
        count = int(os.environ.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        # Not a number means nothing downstream can trust it either; git would
        # reject it too. Start fresh rather than propagate the garbage.
        count = 0
    # A negative count is garbage in the same way, but int() accepts it: it
    # would name the pair GIT_CONFIG_KEY_-1 and declare a count of 0, so git
    # would read no settings at all and the guard would stay in force.
    count = max(count, 0)
    return {
        "GIT_CONFIG_COUNT": str(count + 1),
        f"GIT_CONFIG_KEY_{count}": "safe.directory",
        f"GIT_CONFIG_VALUE_{count}": "*",
    }


def _run_git(args: list[str], cwd: Path) -> str | None:
    """Run a git command in ``cwd`` and return its stripped stdout.

    Returns None on any failure -- git missing, not a repository, timeout, or a
    non-zero exit. VCS metadata is best-effort; a build must never fail because
    the checkout looks unusual.
    """
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            env={**os.environ, **git_safe_directory_env()},
        )
    except FileNotFoundError:
        # Raised both for a missing git binary and for a cwd that does not
        # exist. They need different fixes, and this debug line is the only
        # trace of why VCS detection produced nothing, so say which it was.
        if not cwd.is_dir():
            logger.debug(f"git working directory '{cwd}' does not exist; skipping local VCS detection")
        else:
            logger.debug("git executable not found; skipping local VCS detection")
        return None
    except NotADirectoryError:
        logger.debug(f"git working directory '{cwd}' is not a directory; skipping local VCS detection")
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug(f"git {' '.join(args)} failed: {exc}")
        return None

    if result.returncode != 0:
        logger.debug(f"git {' '.join(args)} exited {result.returncode}: {result.stderr.strip()[:200]}")
        return None

    output = result.stdout.strip()
    return output or None


def commit_url_for(vcs_url: str, commit_sha: str | None) -> str | None:
    """Build a browsable commit URL for known forges.

    Returns None for an unknown host, or when there is no commit to link to --
    the path shape differs per forge and guessing wrong is worse than omitting.
    """
    if not commit_sha:
        return None

    host = vcs_url.split("://", 1)[-1].split("/", 1)[0].lower()
    # Strip a port, which normalize_repo_url preserves for http(s) remotes.
    host = host.split(":", 1)[0]
    segment = _COMMIT_PATH_BY_HOST.get(host)
    if segment is None:
        # Self-hosted instances keep the vendor's path layout under a custom
        # host, so fall back on a vendor-name match before giving up -- but only
        # for the vendors whose self-hosted product uses the same layout as
        # their cloud one. Bitbucket is deliberately excluded: Data Center puts
        # commits under /projects/<KEY>/repos/<slug>/commits/<sha>, so matching
        # on the host name alone would emit a URL that 404s, which is worse than
        # emitting none.
        for known_host in _SELF_HOSTED_KEEPS_LAYOUT:
            if known_host.split(".")[0] in host:
                segment = _COMMIT_PATH_BY_HOST[known_host]
                break
    if segment is None:
        return None

    return f"{vcs_url}/{segment}/{commit_sha}"


def _detect_remote_url(cwd: Path) -> str | None:
    """Return the normalised URL of ``origin``, or of the first remote if absent."""
    remote = _run_git(["remote", "get-url", "origin"], cwd)
    if remote is None:
        remotes = _run_git(["remote"], cwd)
        if not remotes:
            return None
        first = remotes.splitlines()[0].strip()
        if not first:
            return None
        remote = _run_git(["remote", "get-url", first], cwd)
    if remote is None:
        return None
    return normalize_repo_url(remote)


def _detect_ref(cwd: Path) -> str | None:
    """Return the current branch, or the tag when HEAD is detached.

    CI systems routinely check out a detached HEAD, so falling back to an exact
    tag match is what makes the ref useful rather than empty.
    """
    branch = _run_git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd)
    if branch:
        return branch
    return _run_git(["describe", "--tags", "--exact-match"], cwd)


def detect_vcs(cwd: Path | None = None) -> VcsInfo | None:
    """Read repository coordinates from the git checkout at ``cwd``.

    Returns None when ``cwd`` is not inside a git work tree, or when no remote
    URL can be resolved -- a repository with no remote has no URL worth
    recording in an SBOM.
    """
    root = cwd or Path.cwd()

    if _run_git(["rev-parse", "--is-inside-work-tree"], root) != "true":
        logger.debug(f"{root} is not a git work tree; skipping local VCS detection")
        return None

    vcs_url = _detect_remote_url(root)
    if not vcs_url:
        logger.debug("git checkout has no usable remote URL; skipping local VCS detection")
        return None

    commit_sha = _run_git(["rev-parse", "HEAD"], root)
    ref = _detect_ref(root)

    return VcsInfo(
        url=vcs_url,
        commit_sha=commit_sha,
        ref=ref,
        commit_url=commit_url_for(vcs_url, commit_sha),
    )
