"""Utility functions for augmentation providers."""

import os
from typing import Optional

# Repository-URL normalization now lives with the CI platforms that need it
# (see sbomify_action._runtime.vcs_url). Re-exported here so existing callers
# and tests keep importing it from where it has always been.
from .._runtime.vcs_url import (
    is_scp_like_git_url,
    normalize_repo_url,
    strip_ref_prefix,
    truncate_sha,
)

__all__ = [
    "build_vcs_url_with_commit",
    "is_scp_like_git_url",
    "is_vcs_augmentation_disabled",
    "normalize_repo_url",
    "strip_ref_prefix",
    "truncate_sha",
]


def is_vcs_augmentation_disabled() -> bool:
    """
    Check if VCS augmentation is disabled via environment variable.

    Set DISABLE_VCS_AUGMENTATION=true to disable all VCS enrichment
    from CI providers and sbomify.json config.

    Returns:
        True if VCS augmentation should be disabled, False otherwise
    """
    return os.getenv("DISABLE_VCS_AUGMENTATION", "").lower() in ("true", "1", "yes")


def build_vcs_url_with_commit(vcs_url: str, commit_sha: Optional[str]) -> str:
    """
    Build a VCS URL with commit pinning in git+ format.

    This creates URLs compatible with both CycloneDX and SPDX specs:
    - git+https://github.com/owner/repo@abc123def456

    Args:
        vcs_url: Base repository URL (e.g., https://github.com/owner/repo)
        commit_sha: Full commit SHA to pin, or None for unpinned URL

    Returns:
        VCS URL with commit pinning if SHA provided, otherwise the
        URL normalized to git+ format
    """
    # Both http and https are prefixed: TeamCity is the first provider that can
    # emit a plain-http root URL (an internal server), and without the prefix
    # the result "http://host/org/app@<sha>" is not a parseable VCS locator.
    is_http = vcs_url.startswith(("https://", "http://"))

    if not commit_sha:
        # Just normalize to git+ format if no commit
        if is_http:
            return f"git+{vcs_url}"
        return vcs_url

    # Build URL with commit pinning
    if is_http:
        return f"git+{vcs_url}@{commit_sha}"
    return f"{vcs_url}@{commit_sha}"
