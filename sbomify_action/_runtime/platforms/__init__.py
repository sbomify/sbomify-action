"""CI platform implementations.

Adding support for a CI system means adding one module here and one
``register()`` line in ``_runtime.create_default_registry`` -- nothing else in
the codebase needs to learn about it.

Start from :class:`GitCheckoutPlatform` when the system checks out a git
repository and exposes nothing better than that, or from a bare class when it
publishes its own repository details (see ``github.py``) or needs to read them
from somewhere other than the environment (see ``teamcity.py``).
"""

from .base import GitCheckoutPlatform, env_first, env_present, env_truthy
from .bitbucket import BitbucketPlatform
from .generic import GenericCIPlatform
from .github import GitHubOidcProvider, GitHubPlatform
from .gitlab import GitLabPlatform
from .local import LocalPlatform
from .teamcity import TeamCityPlatform

__all__ = [
    "BitbucketPlatform",
    "GenericCIPlatform",
    "GitCheckoutPlatform",
    "GitHubOidcProvider",
    "GitHubPlatform",
    "GitLabPlatform",
    "LocalPlatform",
    "TeamCityPlatform",
    "env_first",
    "env_present",
    "env_truthy",
]
