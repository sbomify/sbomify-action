"""Bitbucket Pipelines platform.

Covers Bitbucket Cloud; Data Center exposes a different (and undocumented) set
of variables, so operators there configure ``vcs_url`` in ``sbomify.json``.

Environment variables used:
- BITBUCKET_PIPELINE_UUID: detection
- BITBUCKET_CLONE_DIR: checkout root
- BITBUCKET_GIT_HTTP_ORIGIN: repository URL
- BITBUCKET_WORKSPACE + BITBUCKET_REPO_SLUG: fallback repository URL
- BITBUCKET_COMMIT: full commit SHA
- BITBUCKET_BRANCH / BITBUCKET_TAG: ref (only one is set per run)
"""

import logging
from pathlib import Path

from ..formatters import PlainFormatter
from ..protocol import LogFormatter, OidcProvider, VcsInfo
from .base import env_first, env_present

logger = logging.getLogger("sbomify_action")


class BitbucketPlatform:
    """Bitbucket Pipelines runner."""

    name: str = "bitbucket-pipelines"
    priority: int = 30
    is_ci: bool = True
    confines_working_dir: bool = False

    def detects(self) -> bool:
        """True when running in a Bitbucket Pipelines step."""
        return env_present("BITBUCKET_PIPELINE_UUID")

    def workspace(self) -> Path | None:
        """Return ``BITBUCKET_CLONE_DIR``, or the process working directory."""
        clone_dir = env_first("BITBUCKET_CLONE_DIR")
        return Path(clone_dir) if clone_dir else Path.cwd()

    def vcs(self) -> VcsInfo | None:
        """Read repository coordinates from the step's environment."""
        vcs_url = env_first("BITBUCKET_GIT_HTTP_ORIGIN")

        if not vcs_url:
            workspace = env_first("BITBUCKET_WORKSPACE")
            repo_slug = env_first("BITBUCKET_REPO_SLUG")
            if workspace and repo_slug:
                vcs_url = f"https://bitbucket.org/{workspace}/{repo_slug}"
                logger.debug("Constructed Bitbucket URL from workspace/repo slug")

        if not vcs_url:
            logger.warning(
                "Bitbucket Pipelines detected but could not determine repository URL. "
                "For Bitbucket Data Center, configure vcs_url in sbomify.json."
            )
            return None

        commit_sha = env_first("BITBUCKET_COMMIT")
        return VcsInfo(
            url=vcs_url,
            commit_sha=commit_sha,
            ref=env_first("BITBUCKET_BRANCH", "BITBUCKET_TAG"),
            commit_url=f"{vcs_url}/commits/{commit_sha}" if commit_sha else None,
        )

    def log_formatter(self) -> LogFormatter:
        """Plain Rich output -- Bitbucket has no annotation dialect."""
        return PlainFormatter()

    def oidc(self) -> OidcProvider | None:
        """No OIDC provider yet -- the sbomify exchange endpoint is GitHub-only."""
        return None

    def telemetry_tags(self) -> dict[str, str]:
        """Platform tags.

        Bitbucket does not expose repository visibility, so every repository is
        treated as private -- the safest reading when we cannot tell.
        """
        return {"ci.platform": self.name, "repo.public": "False"}

    def telemetry_context(self) -> dict[str, str]:
        """No context -- visibility is unknown, so nothing is safe to report."""
        return {}
