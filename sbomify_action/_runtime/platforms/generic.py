"""Generic CI platform for systems with no vendor integration.

Azure Pipelines, Buildkite, Drone and friends all check out a git repository
and run a command in it. That is enough: the checkout supplies VCS metadata via
``git``, and the working directory supplies the workspace. What we gain from
recognising the vendor by name is a useful ``ci.platform`` telemetry tag and,
where the vendor publishes one, the checkout path.

Adding a vendor here is a row in :data:`VENDORS`, not a new class. A vendor
graduates to its own platform module only when it needs something structural --
its own log dialect, an OIDC issuer, or repository metadata richer than git's.
"""

import logging
from pathlib import Path

from .base import GitCheckoutPlatform, env_checkout_dir, env_present, env_truthy

logger = logging.getLogger("sbomify_action")

#: (slug, detection variables, checkout-path variables).
#:
#: TeamCity, Jenkins, CircleCI and Travis CI are deliberately absent: each has
#: a platform of its own, because each publishes repository details the git
#: checkout cannot match -- TeamCity's live in a build-properties file and the
#: checkout alone cannot tell a Git VCS root from a Perforce one, while the
#: other three name the branch a build was triggered for, which a detached HEAD
#: does not know. A vendor graduates out of this table exactly when it needs
#: that kind of handling.
VENDORS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "azure-pipelines",
        ("TF_BUILD",),
        ("BUILD_REPOSITORY_LOCALPATH", "SYSTEM_DEFAULTWORKINGDIRECTORY"),
    ),
    ("buildkite", ("BUILDKITE",), ("BUILDKITE_BUILD_CHECKOUT_PATH",)),
    ("drone", ("DRONE",), ("DRONE_WORKSPACE",)),
    ("appveyor", ("APPVEYOR",), ("APPVEYOR_BUILD_FOLDER",)),
    ("aws-codebuild", ("CODEBUILD_BUILD_ID",), ("CODEBUILD_SRC_DIR",)),
)

#: Reported when ``CI`` is set but no vendor in :data:`VENDORS` matched.
UNKNOWN_VENDOR = "generic-ci"


class GenericCIPlatform(GitCheckoutPlatform):
    """A CI system we recognise but do not integrate with specially."""

    priority: int = 90
    is_ci: bool = True

    def __init__(self) -> None:
        """Name this instance after whichever vendor the environment names.

        Resolved once per instance rather than on each access, so ``name``
        stays a plain attribute like every other platform's. The registry
        builds a fresh instance per :func:`get_platform` call, so a process
        that changes its environment still gets the right answer.
        """
        self.name = self._vendor() or UNKNOWN_VENDOR

    def _vendor(self) -> str | None:
        """Return the slug of the first vendor whose detection variables are set."""
        for slug, detection_vars, _ in VENDORS:
            if env_present(*detection_vars):
                return slug
        return None

    def detects(self) -> bool:
        """True for a known vendor, or any build that sets ``CI`` truthily.

        ``CI`` is a boolean, so it must be read as one: some toolchains export
        ``CI=false`` locally, and treating that as a CI run would refuse the
        interactive wizard on a developer's own machine.
        """
        return self._vendor() is not None or env_truthy("CI")

    def workspace(self) -> Path | None:
        """Return the vendor's checkout path, or the process working directory.

        Vendors that mount the checkout as the command's working directory need
        no variable at all -- the fallback is correct for them. The value is
        expanded and checked before it is trusted; see :func:`env_checkout_dir`.
        """
        vendor = self._vendor()
        if vendor:
            for slug, _, workspace_vars in VENDORS:
                if slug == vendor:
                    return env_checkout_dir(vendor, *workspace_vars) or Path.cwd()
        return Path.cwd()
