"""Read-only git + filesystem observations gathered at wizard start.

Populated once during ``App.__init__`` so screens can render accurate
defaults — suggested component name, OIDC binding instructions, tag-
vs-trunk release default — without touching git later.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from sbomify_action.cli.wizard.state import RepoFacts


def gather_repo_facts(repo_root: Path) -> RepoFacts:
    """Snapshot git + filesystem state of ``repo_root``."""
    repo_root = repo_root.resolve()
    is_git = _git(["rev-parse", "--is-inside-work-tree"], cwd=repo_root) == "true"

    remote_url: str | None = None
    suggested_repo_name: str | None = None
    default_branch = "main"
    current_branch: str | None = None
    has_release_tags = False
    owner_repo_slug: str | None = None

    if is_git:
        remote_url = _git(["config", "--get", "remote.origin.url"], cwd=repo_root) or None
        if remote_url:
            owner_repo_slug = _parse_owner_repo_slug(remote_url)
            suggested_repo_name = owner_repo_slug.split("/", 1)[1] if owner_repo_slug else None
        head_ref = _git(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=repo_root)
        if head_ref and "/" in head_ref:
            default_branch = head_ref.split("/", 1)[1]
        current_branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root) or None
        tags = _git(["tag", "--list", "v*"], cwd=repo_root)
        has_release_tags = bool(tags)

    if not suggested_repo_name:
        suggested_repo_name = repo_root.name

    return RepoFacts(
        repo_root=repo_root,
        is_git=is_git,
        remote_url=remote_url,
        suggested_repo_name=suggested_repo_name,
        default_branch=default_branch,
        current_branch=current_branch,
        has_release_tags=has_release_tags,
        owner_repo_slug=owner_repo_slug,
    )


def _git(args: list[str], *, cwd: Path) -> str | None:
    """Run ``git <args>``; return stripped stdout, or None on any failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


# Matches the trailing "owner/repo" segment of a git remote URL.
# Handles both SSH (git@github.com:owner/repo.git) and HTTPS
# (https://github.com/owner/repo.git, https://x:y@…) formats.
_OWNER_REPO_RE = re.compile(r"[:/](?P<owner>[^/:]+)/(?P<repo>[^/:]+?)(?:\.git)?/?$")


def _parse_owner_repo_slug(remote_url: str) -> str | None:
    """Extract ``owner/repo`` from a typical git remote URL."""
    cleaned = remote_url.strip()
    match = _OWNER_REPO_RE.search(cleaned)
    if not match:
        return None
    return f"{match.group('owner')}/{match.group('repo')}"
