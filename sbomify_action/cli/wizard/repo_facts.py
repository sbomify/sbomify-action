"""Read-only filesystem/git observations used to seed the wizard.

These helpers run once during `App.on_mount()` to populate `RepoFacts`,
which is then immutable for the rest of the session.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from sbomify_action.cli.wizard.state import RepoFacts


def gather_repo_facts(repo_root: Path) -> RepoFacts:
    """Snapshot the working tree: git status, remote, default/current branch, tags."""
    repo_root = repo_root.resolve()
    is_git = _git_check(["rev-parse", "--is-inside-work-tree"], cwd=repo_root) == "true"
    remote_url: str | None = None
    suggested_repo_name: str | None = None
    default_branch = "main"
    current_branch: str | None = None
    has_release_tags = False

    if is_git:
        remote_url = _git_check(["config", "--get", "remote.origin.url"], cwd=repo_root) or None
        if remote_url:
            suggested_repo_name = _parse_repo_name(remote_url)
        head_ref = _git_check(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=repo_root)
        if head_ref and "/" in head_ref:
            default_branch = head_ref.split("/", 1)[1]
        current_branch = _git_check(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root) or None
        tags = _git_check(["tag", "--list", "v*"], cwd=repo_root)
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
    )


def _git_check(args: list[str], *, cwd: Path) -> str | None:
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


def _parse_repo_name(remote_url: str) -> str | None:
    """Pull the repo name out of a typical git remote URL."""
    cleaned = remote_url.strip()
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    match = re.search(r"[:/]([^:/]+/[^:/]+)$", cleaned)
    if match:
        slug = match.group(1).split("/")[-1]
        return slug or None
    return None
