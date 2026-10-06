"""GitLab CI platform.

Supports gitlab.com and self-managed instances via ``CI_PROJECT_URL`` /
``CI_SERVER_URL``.

Environment variables used:
- GITLAB_CI: detection
- CI_PROJECT_DIR: checkout root
- CI_PROJECT_URL: full project URL
- CI_SERVER_URL + CI_PROJECT_PATH: fallback when CI_PROJECT_URL is absent
- CI_COMMIT_SHA / CI_COMMIT_REF_NAME: commit coordinates
- CI_PROJECT_VISIBILITY: gates what telemetry may report
"""

import logging
import os
from pathlib import Path

from ..formatters import PlainFormatter
from ..protocol import LogFormatter, OidcProvider, VcsInfo
from .base import env_first, env_truthy

logger = logging.getLogger("sbomify_action")


class GitLabPlatform:
    """GitLab CI runner."""

    name: str = "gitlab-ci"
    priority: int = 20
    is_ci: bool = True
    confines_working_dir: bool = False

    def detects(self) -> bool:
        """True when running in a GitLab CI job."""
        return env_truthy("GITLAB_CI")

    def workspace(self) -> Path | None:
        """Return ``CI_PROJECT_DIR``, or the process working directory."""
        project_dir = env_first("CI_PROJECT_DIR")
        return Path(project_dir) if project_dir else Path.cwd()

    def vcs(self) -> VcsInfo | None:
        """Read repository coordinates from the job's environment."""
        # CI_PROJECT_URL already includes the server, which is what makes this
        # work unchanged on self-managed instances.
        project_url = env_first("CI_PROJECT_URL")
        if not project_url:
            server_url = os.environ.get("CI_SERVER_URL", "https://gitlab.com").rstrip("/")
            if project_path := env_first("CI_PROJECT_PATH"):
                project_url = f"{server_url}/{project_path}"

        if not project_url:
            logger.warning("GitLab CI detected but could not determine project URL")
            return None

        commit_sha = env_first("CI_COMMIT_SHA")
        return VcsInfo(
            url=project_url,
            commit_sha=commit_sha,
            ref=env_first("CI_COMMIT_REF_NAME"),
            commit_url=f"{project_url}/-/commit/{commit_sha}" if commit_sha else None,
        )

    def log_formatter(self) -> LogFormatter:
        """Plain Rich output.

        GitLab has its own ``section_start`` collapsible syntax; adding it is now
        a matter of writing one formatter rather than editing the console module.
        """
        return PlainFormatter()

    def oidc(self) -> OidcProvider | None:
        """No OIDC provider yet -- the sbomify exchange endpoint is GitHub-only."""
        return None

    def _is_public_project(self) -> bool:
        """True only when GitLab explicitly reports the project as public."""
        return os.environ.get("CI_PROJECT_VISIBILITY", "").strip().lower() == "public"

    def telemetry_tags(self) -> dict[str, str]:
        """Platform tags, with project identifiers only for public projects."""
        tags = {"ci.platform": self.name, "repo.public": str(self._is_public_project())}
        if not self._is_public_project():
            return tags

        if project := env_first("CI_PROJECT_PATH"):
            tags["ci.repository"] = project
        if pipeline_source := env_first("CI_PIPELINE_SOURCE"):
            tags["ci.pipeline_source"] = pipeline_source
        if ref := env_first("CI_COMMIT_REF_NAME"):
            tags["ci.ref"] = ref
        if sha := env_first("CI_COMMIT_SHORT_SHA"):
            tags["ci.sha"] = sha
        return tags

    def telemetry_context(self) -> dict[str, str]:
        """Run context for public projects only."""
        if not self._is_public_project():
            return {}

        context: dict[str, str] = {}
        for key, variable in (
            ("project", "CI_PROJECT_PATH"),
            ("pipeline_source", "CI_PIPELINE_SOURCE"),
            ("ref", "CI_COMMIT_REF_NAME"),
            ("sha", "CI_COMMIT_SHORT_SHA"),
            ("pipeline_id", "CI_PIPELINE_ID"),
            ("job_name", "CI_JOB_NAME"),
        ):
            if value := env_first(variable):
                context[key] = value
        return context
