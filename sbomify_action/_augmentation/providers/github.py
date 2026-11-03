"""Deprecated home of the GitHub Actions provider.

The detection and extraction logic moved to
``sbomify_action._runtime.platforms.github``, where GitHub Actions is a CI platform
like any other. The old class name is re-exported here so existing imports
keep working; prefer :class:`~.ci_platform.CIPlatformProvider`.
"""

from .._runtime_shims import GitHubActionsProvider

__all__ = ["GitHubActionsProvider"]
