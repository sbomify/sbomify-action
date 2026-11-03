"""Travis CI platform.

Travis is the one vendor here that publishes no repository URL -- only
``TRAVIS_REPO_SLUG``, an ``owner/repo`` pair with no host attached. Travis
serves GitHub, Bitbucket, GitLab and Assembla projects, so turning that pair
into a URL means guessing the forge, and a guess that lands on the wrong host
is worse than no link at all.

So this platform reads the repository URL from the checkout, inherited from
:class:`GitCheckoutPlatform`, and layers the job environment on top of it for
the two fields the checkout gets wrong: Travis clones with ``--branch`` and
then checks out the commit, leaving a detached HEAD that can name a tag and
nothing else. ``TRAVIS_BRANCH`` knows the branch, and on a pull request
``TRAVIS_PULL_REQUEST_BRANCH`` knows which branch the request came *from*,
which the checkout cannot know at all.

Environment variables used:
- TRAVIS: detection
- TRAVIS_BUILD_DIR: checkout root
- TRAVIS_COMMIT: full commit SHA
- TRAVIS_TAG / TRAVIS_PULL_REQUEST_BRANCH / TRAVIS_BRANCH: ref
"""

from pathlib import Path

from ..git import commit_url_for
from ..protocol import VcsInfo
from .base import GitCheckoutPlatform, env_checkout_dir, env_first, env_truthy


class TravisPlatform(GitCheckoutPlatform):
    """Travis CI worker."""

    name: str = "travis-ci"
    priority: int = 70
    is_ci: bool = True

    def detects(self) -> bool:
        """True when running in a Travis CI job."""
        return env_truthy("TRAVIS")

    def workspace(self) -> Path | None:
        """Return ``TRAVIS_BUILD_DIR``, or the process working directory."""
        return env_checkout_dir(self.name, "TRAVIS_BUILD_DIR") or Path.cwd()

    def vcs(self) -> VcsInfo | None:
        """Take the repository URL from the checkout and the ref from the job.

        Returns None when the checkout yields no repository URL, since Travis
        publishes none of its own to fall back on -- the same outcome as before
        this platform existed.
        """
        checkout = super().vcs()
        if checkout is None or not checkout.url:
            return checkout

        commit_sha = env_first("TRAVIS_COMMIT") or checkout.commit_sha
        return VcsInfo(
            url=checkout.url,
            commit_sha=commit_sha,
            ref=self._ref() or checkout.ref,
            commit_url=commit_url_for(checkout.url, commit_sha),
        )

    def _ref(self) -> str | None:
        """Return the branch or tag this build is for.

        ``TRAVIS_TAG`` is set only on a tag build, and takes precedence because
        ``TRAVIS_BRANCH`` then repeats the tag name rather than naming a
        branch. ``TRAVIS_PULL_REQUEST_BRANCH`` is the *source* branch of a pull
        request, where ``TRAVIS_BRANCH`` holds the branch being merged into --
        the source is what this build actually built.
        """
        return env_first("TRAVIS_TAG", "TRAVIS_PULL_REQUEST_BRANCH", "TRAVIS_BRANCH")

    def telemetry_tags(self) -> dict[str, str]:
        """Platform tags.

        ``ci.platform`` names Travis now that it is a platform of its own,
        where the generic fallback used to report ``unknown`` with the vendor
        alongside it in ``ci.vendor``.

        Travis exposes no repository visibility, so it is treated as private,
        as on Bitbucket, and nothing identifying is reported.
        """
        return {"ci.platform": self.name, "repo.public": "False"}

    def telemetry_context(self) -> dict[str, str]:
        """No context -- visibility is unknown, so nothing is safe to report."""
        return {}
