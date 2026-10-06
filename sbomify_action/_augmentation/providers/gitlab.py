"""Deprecated home of the GitLab CI provider.

The detection and extraction logic moved to
``sbomify_action._runtime.platforms.gitlab``, where GitLab CI is a CI platform
like any other. The old class name is re-exported here so existing imports
keep working; prefer :class:`~.ci_platform.CIPlatformProvider`.
"""

from .._runtime_shims import GitLabCIProvider

__all__ = ["GitLabCIProvider"]
