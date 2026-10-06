"""GitHub Actions platform.

Everything the action knows about GitHub Actions lives here: how to detect the
runner, where it mounts the checkout, how it names repository metadata, its
workflow-command log dialect, and how to mint an OIDC token for trusted
publishing.

Note the distinction this file draws: *GitHub Actions the runtime* is this
platform's concern. *github.com the host* is not -- fetching our license
database from a GitHub release, or recognising a github.com remote URL, happens
for GitLab and TeamCity users too and stays in the modules that need it.

Environment variables used:
- GITHUB_ACTIONS: detection
- GITHUB_WORKSPACE: checkout root inside the runner container
- GITHUB_SERVER_URL: server URL (github.com or a GitHub Enterprise Server host)
- GITHUB_REPOSITORY: repository in owner/repo form
- GITHUB_SHA: full commit SHA
- GITHUB_REF / GITHUB_REF_NAME: git ref
- GITHUB_REPOSITORY_VISIBILITY: gates what telemetry may report
- ACTIONS_ID_TOKEN_REQUEST_URL / _TOKEN: OIDC token endpoint (needs
  ``permissions: id-token: write``)
"""

import logging
import os
from pathlib import Path

import requests

from sbomify_action.exceptions import OIDCExchangeError
from sbomify_action.http_client import get_default_headers

from ..formatters import GitHubActionsFormatter
from ..protocol import LogFormatter, OidcProvider, VcsInfo
from ..redaction import scrub_secrets
from ..vcs_url import strip_ref_prefix
from .base import env_first, env_truthy

logger = logging.getLogger("sbomify_action")

#: Where GitHub Actions mounts the repository in a container action.
DEFAULT_WORKSPACE = Path("/github/workspace")

OIDC_REQUEST_TIMEOUT = 30


class GitHubOidcProvider:
    """Mints GitHub Actions OIDC JWTs.

    The runner exposes a token endpoint only when the workflow declares
    ``permissions: id-token: write``, so :meth:`available` can be false on a
    correctly detected GitHub Actions run.
    """

    exchange_slug: str = "github"

    def available(self) -> bool:
        """True when the runner exposes both OIDC request variables."""
        return bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))

    def request_token(self, audience: str) -> str:
        """Fetch a GitHub Actions OIDC JWT for ``audience``.

        Calls ``${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=<audience>`` with the
        runner's bearer token and returns the JWT from the response's ``value``
        field.

        Raises:
            OIDCExchangeError: if the runner endpoint is unavailable, unreachable
                or returns an unexpected payload. Surfaced as an exchange error
                because to the user it is part of the same "could not
                authenticate via OIDC" failure.
        """
        url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not url or not bearer:
            raise OIDCExchangeError(
                "GitHub Actions OIDC environment is not available. "
                "Ensure the workflow grants `permissions: id-token: write`."
            )

        headers = get_default_headers(token=bearer)
        headers["Accept"] = "application/json"
        try:
            response = requests.get(
                url,
                params={"audience": audience},
                headers=headers,
                timeout=OIDC_REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise OIDCExchangeError(f"Failed to reach GitHub OIDC token endpoint: {exc}") from exc

        if not response.ok:
            raise OIDCExchangeError(
                f"GitHub OIDC token endpoint returned HTTP {response.status_code}: {scrub_secrets(response.text[:200])}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise OIDCExchangeError("GitHub OIDC token endpoint returned non-JSON response") from exc

        token = payload.get("value")
        if not token:
            raise OIDCExchangeError("GitHub OIDC token endpoint response did not contain a 'value' field")
        return str(token)


class GitHubPlatform:
    """GitHub Actions runner."""

    name: str = "github-actions"
    priority: int = 10
    is_ci: bool = True
    # A container action mounts the repository at a fixed path; --working-dir
    # must not escape it.
    confines_working_dir: bool = True

    def detects(self) -> bool:
        """True when running on a GitHub Actions runner."""
        return env_truthy("GITHUB_ACTIONS")

    def workspace(self) -> Path | None:
        """Return the checkout root, falling back to the container mount point."""
        return Path(os.environ.get("GITHUB_WORKSPACE") or DEFAULT_WORKSPACE)

    def vcs(self) -> VcsInfo | None:
        """Read repository coordinates from the runner's environment.

        Supports GitHub Enterprise Server via ``GITHUB_SERVER_URL``.
        """
        server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        repository = env_first("GITHUB_REPOSITORY")
        if not repository:
            logger.warning("GitHub Actions detected but GITHUB_REPOSITORY not set")
            return None

        commit_sha = env_first("GITHUB_SHA")
        ref = strip_ref_prefix(env_first("GITHUB_REF_NAME", "GITHUB_REF"))
        vcs_url = f"{server_url}/{repository}"

        return VcsInfo(
            url=vcs_url,
            commit_sha=commit_sha,
            ref=ref,
            commit_url=f"{vcs_url}/commit/{commit_sha}" if commit_sha else None,
        )

    def log_formatter(self) -> LogFormatter:
        """Workflow commands, so output collapses and annotations reach the summary."""
        return GitHubActionsFormatter()

    def oidc(self) -> OidcProvider | None:
        """Return the OIDC provider, or None when the workflow granted no id-token."""
        provider = GitHubOidcProvider()
        return provider if provider.available() else None

    def _is_public_repo(self) -> bool:
        """True only when GitHub explicitly reports the repository as public."""
        return os.environ.get("GITHUB_REPOSITORY_VISIBILITY", "").strip().lower() == "public"

    def telemetry_tags(self) -> dict[str, str]:
        """Platform tags, with repository identifiers only for public repos."""
        tags = {"ci.platform": self.name, "repo.public": str(self._is_public_repo())}
        if not self._is_public_repo():
            return tags

        if repo := env_first("GITHUB_REPOSITORY"):
            tags["ci.repository"] = repo
        if workflow := env_first("GITHUB_WORKFLOW"):
            tags["ci.workflow"] = workflow
        if ref := env_first("GITHUB_REF"):
            tags["ci.ref"] = ref
        if sha := env_first("GITHUB_SHA"):
            tags["ci.sha"] = sha[:7]
        return tags

    def telemetry_context(self) -> dict[str, str]:
        """Run context for public repositories only."""
        if not self._is_public_repo():
            return {}

        context: dict[str, str] = {}
        for key, variable in (
            ("repository", "GITHUB_REPOSITORY"),
            ("workflow", "GITHUB_WORKFLOW"),
            ("ref", "GITHUB_REF"),
            ("sha", "GITHUB_SHA"),
            ("action", "GITHUB_ACTION"),
            ("run_id", "GITHUB_RUN_ID"),
            ("run_number", "GITHUB_RUN_NUMBER"),
        ):
            if value := env_first(variable):
                context[key] = value
        return context
