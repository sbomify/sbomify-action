"""CircleCI platform.

CircleCI publishes the repository it checked out in ``CIRCLE_REPOSITORY_URL``
and the ref in ``CIRCLE_BRANCH`` / ``CIRCLE_TAG``, so those are read rather
than shelled out to ``git``. The ref is the reason: CircleCI checks out a
detached HEAD, so the checkout can name a tag but never the branch a build was
triggered for.

The git checkout stays as the fallback, inherited from
:class:`GitCheckoutPlatform`, for a job whose checkout was done by something
other than the ``checkout`` step.

No repository URL is *constructed* from ``CIRCLE_PROJECT_USERNAME`` and
``CIRCLE_PROJECT_REPONAME``: CircleCI serves GitHub, Bitbucket and GitLab
projects and publishes no variable naming which, so the pair would only produce
a plausible-looking guess pointing at the wrong host.

Environment variables used:
- CIRCLECI: detection
- CIRCLE_WORKING_DIRECTORY: checkout root
- CIRCLE_REPOSITORY_URL: repository URL
- CIRCLE_SHA1: full commit SHA
- CIRCLE_BRANCH / CIRCLE_TAG: ref (only one is set per run)
"""

import logging
from pathlib import Path

from ..git import commit_url_for
from ..protocol import VcsInfo
from ..vcs_url import normalize_repo_url
from .base import GitCheckoutPlatform, env_checkout_dir, env_first, env_truthy

logger = logging.getLogger("sbomify_action")


class CircleCIPlatform(GitCheckoutPlatform):
    """CircleCI executor."""

    name: str = "circleci"
    priority: int = 60
    is_ci: bool = True

    def detects(self) -> bool:
        """True when running in a CircleCI job."""
        return env_truthy("CIRCLECI")

    def workspace(self) -> Path | None:
        """Return ``CIRCLE_WORKING_DIRECTORY``, or the process working directory.

        CircleCI's default is the literal string ``~/project``, which is why
        this goes through :func:`env_checkout_dir` rather than trusting the
        variable as given.
        """
        return env_checkout_dir(self.name, "CIRCLE_WORKING_DIRECTORY") or Path.cwd()

    def vcs(self) -> VcsInfo | None:
        """Read repository coordinates from the job's environment.

        Falls back to the git checkout when the job did not use the ``checkout``
        step and so has no repository URL published.
        """
        # CIRCLE_REPOSITORY_URL is the clone URL, which is SSH for most
        # projects; normalize it to a browse URL.
        vcs_url = normalize_repo_url(env_first("CIRCLE_REPOSITORY_URL"))
        if not vcs_url:
            logger.debug("CircleCI exported no usable CIRCLE_REPOSITORY_URL; reading VCS metadata from the checkout")
            return super().vcs()

        commit_sha = env_first("CIRCLE_SHA1")
        return VcsInfo(
            url=vcs_url,
            commit_sha=commit_sha,
            # Exactly one of the two is set: a tag build leaves CIRCLE_BRANCH
            # empty, and env_first skips an empty value.
            ref=env_first("CIRCLE_BRANCH", "CIRCLE_TAG"),
            commit_url=commit_url_for(vcs_url, commit_sha),
        )

    def telemetry_tags(self) -> dict[str, str]:
        """Platform tags.

        ``ci.platform`` names CircleCI now that it is a platform of its own,
        where the generic fallback used to report ``unknown`` with the vendor
        alongside it in ``ci.vendor``.

        CircleCI exposes no repository visibility, so it is treated as private,
        as on Bitbucket, and nothing identifying is reported.
        """
        return {"ci.platform": self.name, "repo.public": "False"}

    def telemetry_context(self) -> dict[str, str]:
        """No context -- visibility is unknown, so nothing is safe to report."""
        return {}
