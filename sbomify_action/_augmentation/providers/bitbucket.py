"""Deprecated home of the Bitbucket Pipelines provider.

The detection and extraction logic moved to
``sbomify_action._runtime.platforms.bitbucket``, where Bitbucket Pipelines is a CI platform
like any other. The old class name is re-exported here so existing imports
keep working; prefer :class:`~.ci_platform.CIPlatformProvider`.
"""

from .._runtime_shims import BitbucketPipelinesProvider

__all__ = ["BitbucketPipelinesProvider"]
