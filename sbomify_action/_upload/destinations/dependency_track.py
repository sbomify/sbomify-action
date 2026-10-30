"""Dependency Track destination for SBOM uploads.

Dependency Track only supports CycloneDX format. SPDX uploads will be rejected.

Configuration via environment variables (DTRACK_* prefix):
    DTRACK_API_KEY: API key for authentication (required unless
                    DTRACK_WORKLOAD_IDENTITY_PROVIDER is set)
    DTRACK_API_URL: Full API base URL (required). We append /v1/bom to this.
                    Must be https://, since the API key travels with every
                    request; http:// is accepted only for localhost unless
                    DTRACK_ALLOW_INSECURE_HTTP is set.
                    Examples:
                    - https://dtrack.example.com/api (standard)
                    - https://api.dtrack.example.com (subdomain)
                    - https://proxy.example.com/dtrack/api (reverse proxy)
    DTRACK_PROJECT_ID: UUID of the project to upload to (optional if using name+version)
    DTRACK_AUTO_CREATE: Auto-create project if it doesn't exist (default: false)
    DTRACK_PROJECT_TAGS: Tags to add to the project (comma separated)
    DTRACK_PARENT_ID: UUID of the parent project
    DTRACK_PARENT_NAME: Name of the parent project
    DTRACK_PARENT_VERSION: Version of the parent project
    DTRACK_IS_LATEST: Mark the uploaded BOM as the latest version
    DTRACK_ALLOW_INSECURE_HTTP: Accept an http:// DTRACK_API_URL on a host other
                    than localhost (default: false). Plain http:// sends the
                    API key unencrypted on every upload, where anyone on the
                    network path can read it and use it to upload or alter
                    SBOMs in Dependency-Track. Only for an internal instance
                    on a network you trust.
    DTRACK_WORKLOAD_IDENTITY_PROVIDER: Authenticate with the CI job's own OIDC
                    token instead of DTRACK_API_KEY (Dependency-Track 5.2+, GitHub
                    Actions with `permissions: id-token: write`). The name of the
                    workload identity provider registered in Dependency-Track,
                    e.g. github-actions. Each run gets a short-lived session for
                    a service account, so there is no long-lived API key to store
                    as a CI secret, leak, or rotate.
    DTRACK_SERVICE_ACCOUNT: Service account to act as (required with the above)
    DTRACK_OIDC_AUDIENCE: Audience to request the OIDC token for. Must match the
                    provider's Audience in Dependency-Track (required with the
                    above; Dependency-Track suggests the instance URL)

Note: Project name and version come from the global COMPONENT_NAME and COMPONENT_VERSION
environment variables, not from DTRACK_* prefixed variables.
"""

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from requests.models import REDIRECT_STATI

from sbomify_action._runtime.redaction import scrub_secrets
from sbomify_action.exceptions import ConfigurationError, OIDCExchangeError
from sbomify_action.http_client import validate_endpoint_url
from sbomify_action.logging_config import logger

from ..protocol import DestinationConfig, UploadInput
from ..result import UploadResult

# Upload timeout in seconds
UPLOAD_TIMEOUT = 120

# RFC 8693 token exchange, as Dependency-Track 5.2+ serves it at /api/v2/oauth/token.
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
EXCHANGE_TIMEOUT = 30


@dataclass
class DependencyTrackConfig(DestinationConfig):
    """
    Configuration for Dependency Track destination.

    Loaded from DTRACK_* prefixed environment variables.

    DTRACK_API_URL should be the full API base URL where the Dependency Track
    API is accessible. We append /v1/bom to this URL.

    Project name and version come from global COMPONENT_NAME/COMPONENT_VERSION.

    Examples:
        - https://dtrack.example.com/api (standard install)
        - https://api.dtrack.example.com (API on subdomain)
        - https://dtrack.example.com:8081/api (custom port)
        - https://proxy.example.com/dependency-track/api (behind reverse proxy)
    """

    ENV_PREFIX = "DTRACK"

    api_key: str
    api_url: str  # Full API base URL, we append /v1/bom
    project_id: Optional[str] = None
    auto_create: bool = False
    project_tags: list[str] | None = None
    parent_id: str | None = None
    parent_name: str | None = None
    parent_version: str | None = None
    is_latest: bool = False
    allow_insecure_http: bool = False
    workload_identity_provider: str | None = None
    service_account: str | None = None
    oidc_audience: str | None = None

    @classmethod
    def from_env(cls) -> Optional["DependencyTrackConfig"]:
        """Load configuration from DTRACK_* environment variables."""
        api_key = cls._get_env("API_KEY")
        api_url = cls._get_env("API_URL")
        provider = cls._get_env("WORKLOAD_IDENTITY_PROVIDER")

        # Require the URL and a way to authenticate
        if not api_url or not (api_key or provider):
            return None

        _project_tags = cls._get_env_list("PROJECT_TAGS") if cls._get_env("PROJECT_TAGS") is not None else None

        return cls(
            api_key=api_key or "",
            api_url=api_url.rstrip(
                "/"
            ),  # Only strip trailing "/" so custom paths like /api or /dtrack/api are preserved
            project_id=cls._get_env("PROJECT_ID"),
            auto_create=cls._get_env_bool("AUTO_CREATE", default=False),
            project_tags=_project_tags,
            parent_id=cls._get_env("PARENT_ID"),
            parent_name=cls._get_env("PARENT_NAME"),
            parent_version=cls._get_env("PARENT_VERSION"),
            is_latest=cls._get_env_bool("IS_LATEST", default=False),
            allow_insecure_http=cls._get_env_bool("ALLOW_INSECURE_HTTP", default=False),
            workload_identity_provider=provider or None,
            service_account=cls._get_env("SERVICE_ACCOUNT") or None,
            oidc_audience=cls._get_env("OIDC_AUDIENCE") or None,
        )

    def is_configured(self) -> bool:
        """
        Check if configuration is valid for upload.

        Note: Project name/version come from UploadInput, so we only check
        API credentials here. The full validation happens at upload time.
        """
        return bool(self.api_url and (self.api_key or self.workload_identity_provider))

    def validate(self) -> None:
        """Refuse a DTRACK_API_URL the credentials must not be sent to, and
        workload identity settings that cannot produce a session."""
        validate_endpoint_url(
            self.api_url,
            "DTRACK_API_URL",
            allow_http=self.allow_insecure_http,
            allow_http_setting="DTRACK_ALLOW_INSECURE_HTTP",
        )
        if not self.workload_identity_provider:
            return
        if self.api_key:
            raise ConfigurationError(
                "Set DTRACK_API_KEY or DTRACK_WORKLOAD_IDENTITY_PROVIDER, not both. Once federation "
                "works, remove the API key so a long-lived secret is not left behind."
            )
        missing = [
            name
            for name, value in (
                ("DTRACK_SERVICE_ACCOUNT", self.service_account),
                ("DTRACK_OIDC_AUDIENCE", self.oidc_audience),
            )
            if not value
        ]
        if missing:
            raise ConfigurationError(f"DTRACK_WORKLOAD_IDENTITY_PROVIDER also needs {' and '.join(missing)}.")

        from sbomify_action.oidc import get_oidc_provider

        if get_oidc_provider() is None:
            raise ConfigurationError(
                "DTRACK_WORKLOAD_IDENTITY_PROVIDER needs an OIDC token from the CI platform, and this run "
                "has none. On GitHub Actions, grant the job `permissions: id-token: write`."
            )


def _exchange_for_session_token(config: DependencyTrackConfig) -> str:
    """Trade this CI job's OIDC token for a Dependency-Track service-account session.

    Raises:
        OIDCExchangeError: if no OIDC token can be minted, or Dependency-Track
            refuses it.
    """
    from sbomify_action.oidc import get_oidc_provider

    provider = get_oidc_provider()
    if provider is None:
        raise OIDCExchangeError("No CI OIDC token is available for this run.")
    subject_token = provider.request_token(config.oidc_audience or "")
    try:
        response = requests.post(
            f"{config.api_url}/v2/oauth/token",
            data={
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "subject_token_type": JWT_TOKEN_TYPE,
                "subject_token": subject_token,
                "workload_identity_provider": config.workload_identity_provider,
                "service_account": config.service_account,
            },
            timeout=EXCHANGE_TIMEOUT,
            # A 307/308 would re-post the OIDC token to whatever Location names.
            allow_redirects=False,
        )
    except requests.RequestException as e:
        raise OIDCExchangeError(f"Failed to reach the Dependency-Track token endpoint: {e}") from e

    if response.status_code != 200:
        raise OIDCExchangeError(
            f"Dependency-Track refused the OIDC token exchange (HTTP {response.status_code}): "
            f"{scrub_secrets(response.text[:300])}. Check that DTRACK_WORKLOAD_IDENTITY_PROVIDER, "
            "DTRACK_SERVICE_ACCOUNT and DTRACK_OIDC_AUDIENCE match a provider and a binding in Dependency-Track."
        )
    try:
        return str(response.json()["access_token"])
    except (ValueError, KeyError, TypeError) as e:
        raise OIDCExchangeError("Dependency-Track token response did not contain an access_token") from e


class DependencyTrackDestination:
    """
    Destination for uploading SBOMs to Dependency Track.

    Dependency Track is an open source Component Analysis platform that
    allows organizations to identify and reduce risk in their software
    supply chain.

    Configuration is loaded from DTRACK_* prefixed environment variables.
    Project name/version come from the global COMPONENT_NAME/COMPONENT_VERSION.

    Environment Variables:
        DTRACK_API_KEY: API key for authentication (required unless using workload identity)
        DTRACK_API_URL: Base URL of Dependency Track (required)
        DTRACK_PROJECT_ID: UUID of the project (optional, alternative to name/version)
        DTRACK_AUTO_CREATE: Auto-create project (default: false)
        DTRACK_PROJECT_TAGS: Tags to add to the project (optional, comma separated)
        DTRACK_PARENT_ID: UUID of the parent project (optional)
        DTRACK_PARENT_NAME: Name of the parent project (optional)
        DTRACK_PARENT_VERSION: Version of the parent project (optional)
        DTRACK_IS_LATEST: Mark the uploaded BOM as the latest version (default: false)
        DTRACK_ALLOW_INSECURE_HTTP: Accept http:// to a non-localhost DTRACK_API_URL,
            which sends the API key unencrypted (default: false)
        DTRACK_WORKLOAD_IDENTITY_PROVIDER, DTRACK_SERVICE_ACCOUNT, DTRACK_OIDC_AUDIENCE:
            Authenticate with the CI job's OIDC token instead of an API key (DT 5.2+)
    """

    def __init__(self, config: Optional[DependencyTrackConfig] = None):
        """
        Initialize Dependency Track destination.

        Args:
            config: Configuration object. If None, loads from environment.
        """
        self._config = config or DependencyTrackConfig.from_env()

    @property
    def name(self) -> str:
        return "dependency-track"

    def is_configured(self) -> bool:
        """Check if Dependency Track destination is configured."""
        return self._config is not None and self._config.is_configured()

    def upload(self, input: UploadInput) -> UploadResult:
        """
        Upload SBOM to Dependency Track.

        Uses the /api/v1/bom endpoint to upload the SBOM.

        Args:
            input: UploadInput with file and format

        Returns:
            UploadResult with token if successful
        """
        if not self.is_configured() or self._config is None:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="Dependency Track not configured (check DTRACK_* env vars)",
            )

        try:
            self._config.validate()
        except ConfigurationError as e:
            return UploadResult.failure_result(destination_name=self.name, error_message=str(e))

        # Dependency Track only supports CycloneDX format
        if input.sbom_format != "cyclonedx":
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Dependency Track only supports CycloneDX format, got: {input.sbom_format}",
            )

        # Read SBOM file
        try:
            with Path(input.sbom_file).open("r", encoding="utf-8") as f:
                sbom_data = f.read()
        except FileNotFoundError:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"SBOM file not found: {input.sbom_file}",
            )
        except IOError as e:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Failed to read SBOM file: {e}",
            )

        # Build the upload URL - append /v1/bom to the API base URL
        url = f"{self._config.api_url}/v1/bom"

        # Prepare headers (credentials are added just before sending)
        headers = {"Content-Type": "application/json"}

        # Prepare payload
        # Dependency Track expects base64-encoded BOM
        bom_base64 = base64.b64encode(sbom_data.encode()).decode()

        payload: Dict[str, Any] = {
            "bom": bom_base64,
            "autoCreate": self._config.auto_create,
            "isLatest": self._config.is_latest,
        }

        # Add project identifier
        if self._config.project_id:
            payload["project"] = self._config.project_id
            logger.info(f"Uploading SBOM to Dependency Track project ID: {self._config.project_id}")
        elif input.component_name and input.component_version:
            payload["projectName"] = input.component_name
            payload["projectVersion"] = input.component_version
            logger.info(f"Uploading SBOM to Dependency Track project: {input.component_name}:{input.component_version}")
        else:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=(
                    "Dependency Track requires either DTRACK_PROJECT_ID or both COMPONENT_NAME and COMPONENT_VERSION"
                ),
            )

        # add project tags if set
        if self._config.project_tags is not None:
            payload["projectTags"] = [{"name": t} for t in self._config.project_tags]

        if self._config.parent_id:
            payload["parentUUID"] = self._config.parent_id
        elif self._config.parent_name and self._config.parent_version:
            payload["parentName"] = self._config.parent_name
            payload["parentVersion"] = self._config.parent_version
        # ensure parent settings are coherent
        elif bool(self._config.parent_name) ^ bool(self._config.parent_version):
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=(
                    "Dependency Track parent project configuration requires either DTRACK_PARENT_ID or both DTRACK_PARENT_NAME and DTRACK_PARENT_VERSION"
                ),
            )

        # Authenticate: a service-account session from the CI OIDC token, or the API key
        if self._config.workload_identity_provider:
            try:
                headers["Authorization"] = f"Bearer {_exchange_for_session_token(self._config)}"
            except OIDCExchangeError as e:
                return UploadResult.failure_result(destination_name=self.name, error_message=str(e))
        else:
            headers["X-Api-Key"] = self._config.api_key

        # Execute the upload
        try:
            response = requests.put(
                url,
                headers=headers,
                json=payload,
                timeout=UPLOAD_TIMEOUT,
                # requests drops Authorization on a cross-host or https->http
                # redirect but keeps X-Api-Key, so following one would hand the
                # key to whatever host, over whatever scheme, Location names.
                allow_redirects=False,
            )
        except requests.exceptions.ConnectionError:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Failed to connect to Dependency Track at {self._config.api_url}",
            )
        except requests.exceptions.Timeout:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="SBOM upload to Dependency Track timed out",
            )
        except requests.exceptions.RequestException as e:
            # Any other transport-layer failure (SSLError, ProxyError,
            # TooManyRedirects, …). Return a clean failure result rather than
            # letting it propagate and crash the upload step — the upload
            # destination contract is to report failures, not raise.
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"SBOM upload to Dependency Track failed: {e}",
            )

        # Handle response. A redirect counts as ok to requests, so check first.
        if response.status_code in REDIRECT_STATI:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=(
                    f"Dependency Track answered {response.status_code} redirecting to "
                    f"{response.headers.get('Location')}. Not following it, because the API key would go "
                    "with it. Set DTRACK_API_URL to the URL the server expects."
                ),
            )
        if not response.ok:
            err_msg = f"Failed to upload SBOM to Dependency Track. [{response.status_code}]"
            try:
                response_text = response.text[:500]
                if response_text:
                    err_msg += f" - {response_text}"
            except Exception:
                pass

            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=err_msg,
            )

        # Extract token from response
        token = None
        response_metadata: Dict[str, Any] = {}
        try:
            response_data = response.json()
            token = response_data.get("token")
            response_metadata = response_data
            if token:
                logger.info(f"Dependency Track upload token: {token}")
        except (ValueError, Exception):
            logger.debug("Could not extract token from Dependency Track response")

        logger.info("SBOM uploaded successfully to Dependency Track")

        return UploadResult.success_result(
            destination_name=self.name,
            sbom_id=token,  # Use token as sbom_id for consistency
            validated=False,
            metadata=response_metadata,
        )
