import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import sentry_sdk

# Add cyclonedx imports for proper SBOM handling
from cyclonedx.model.bom import Bom

from .. import format_display_name
from .._upload import VALID_DESTINATIONS
from ..additional_packages import inject_additional_packages
from ..augmentation import augment_sbom_from_file
from ..console import (
    get_audit_trail,
    gha_group,
    gha_notice,
    print_component_not_found_error,
    print_duplicate_sbom_error,
    print_final_success,
    print_step_end,
    print_step_header,
    reset_audit_trail,
)
from ..console import (
    print_banner as console_print_banner,
)
from ..exceptions import (
    APIError,
    ConfigurationError,
    DockerImageNotFoundError,
    FileProcessingError,
    SBOMGenerationError,
    SBOMValidationError,
    ToolNotAvailableError,
)
from ..generation import (
    ALL_LOCK_FILES,
    SBOMFormat,
    generate_sbom,
    process_lock_file,
)
from ..logging_config import logger
from ..serialization import _fix_purl_encoding_bugs_in_json, serialize_cyclonedx_bom
from ..spdx3 import is_spdx3
from ..upload import upload_sbom


# Import version for tool metadata with multiple fallback mechanisms
def _get_package_version() -> str:
    """Get the package version using multiple fallback methods.

    Priority:
    1. SBOMIFY_GITHUB_ACTION_VERSION environment variable (set at Docker build time for release tracking)
    2. importlib.metadata (for installed packages)
    3. pyproject.toml (for development)
    4. Package __version__ attribute
    5. Fallback to "unknown"
    """
    # Method 1: Check for environment variable (set at Docker build time)
    # This takes precedence as it contains the release version (tag or branch-sha)
    env_version = os.getenv("SBOMIFY_GITHUB_ACTION_VERSION")
    if env_version and env_version not in ("dev", "unknown", ""):
        return env_version

    # Method 2: Try importlib.metadata (preferred for installed packages)
    try:
        from importlib.metadata import version

        return version("sbomify-action")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 3: Try reading from pyproject.toml using tomllib when available (Python 3.11+; older versions fall back to other methods)
    try:
        import tomllib

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
            return pyproject_data.get("project", {}).get("version", "unknown")
    except ImportError:
        # Python < 3.11 doesn't have tomllib
        pass
    except Exception:
        pass

    # Method 4: Try toml library as fallback for older Python
    try:
        import toml

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "r") as f:
                pyproject_data = toml.load(f)
            return pyproject_data.get("project", {}).get("version", "unknown")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 5: Try package __version__ attribute
    try:
        from sbomify_action import __version__

        return __version__
    except (ImportError, AttributeError):
        pass

    # Final fallback
    return "unknown"


SBOMIFY_VERSION = _get_package_version()

# Constants for magic strings/numbers
SPDX_LOGICAL_OPERATORS = [" OR ", " AND ", " WITH "]
SBOMIFY_PRODUCTION_API = "https://app.sbomify.com"
SBOMIFY_TOOL_NAME = "sbomify-action"
SBOMIFY_VENDOR_NAME = "sbomify"
LOCALHOST_PATTERNS = ["127.0.0.1", "localhost", "0.0.0.0"]
VALID_SBOM_FORMATS: tuple[str, ...] = ("cyclonedx", "spdx")
NONE_SENTINEL = "none"

# Intermediate SBOM files for pipeline steps
STEP_1_FILE = "step_1.json"  # Output of generation/validation
STEP_2_FILE = "step_2.json"  # Output of augmentation
STEP_3_FILE = "step_3.json"  # Output of enrichment


def _get_current_utc_timestamp() -> str:
    """
    Generate current UTC timestamp in ISO-8601 format.

    Returns:
        Current UTC timestamp as ISO-8601 string (e.g., "2024-12-19T14:30:00Z")
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


"""

There are three steps in our SBOM generation.

# Step 1: Generation / Validation
In this step we either generate an SBOM from a lockfile
or we validate a provided SBOM.

The output of this phase is `step_1.json`.

# Step 2: Augmentation
This step augments the provided SBOM with data about
you as the software provider from sbomify's backend.
This includes merging in information about licensing,
supplier and vendor. This data is required for NTIA
Minimum Elements compliance.

The output of this `step_2.json`.


# Step 3: Enrichment
SBOMs will vary a lot in quality of the components.
As we aspire to reach NTIA Minimum Elements compliants
we will enrich components using the ecosyste.ms API to ensure that
as many of our components in the SBOM as possible have
the required data.

The output of this step is `step_3.json`.

Since both step 2 and 3 are optional, we will only
write `OUTPUT_FILE` at the end of the run.

# Configuration
The tool can be configured via environment variables:
- API_BASE_URL: Override the sbomify API base URL (default: https://app.sbomify.com)
  Useful for testing against development instances (e.g., http://127.0.0.1:8000)

"""


# Configuration dataclass for better organization
@dataclass
class Config:
    """Configuration settings for the SBOM action."""

    token: str
    component_id: str
    sbom_file: Optional[str] = None
    docker_image: Optional[str] = None
    lock_file: Optional[str] = None
    output_file: str = "sbom_output.json"
    upload: bool = True
    upload_destinations: list[str] | None = None
    augment: bool = False
    enrich: bool = False
    override_sbom_metadata: bool = False
    override_name: bool = False
    component_version: Optional[str] = None
    component_name: Optional[str] = None
    component_purl: Optional[str] = None
    product_releases: Optional[str | list[str]] = None
    api_base_url: str = SBOMIFY_PRODUCTION_API
    sbom_format: SBOMFormat = "cyclonedx"
    spec_version: Optional[str] = None

    def __post_init__(self) -> None:
        """Set default values that depend on other fields."""
        if self.upload_destinations is None:
            self.upload_destinations = ["sbomify"]  # Default to sbomify only

    @property
    def is_additional_packages_only(self) -> bool:
        """Check if running in additional-packages-only mode (--lock-file none / --sbom-file none)."""
        return (self.lock_file is not None and self.lock_file.lower() == NONE_SENTINEL) or (
            self.sbom_file is not None and self.sbom_file.lower() == NONE_SENTINEL
        )

    def validate(self) -> None:
        """
        Validate configuration settings.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Check if sbomify API access is required:
        # - Uploading to sbomify destination
        # - Managing releases (uses sbomify API)
        # Note: Augmentation does NOT require API - it can use sbomify.json and VCS metadata
        uploads_to_sbomify = self.upload and "sbomify" in self.upload_destinations
        requires_sbomify_api = uploads_to_sbomify or self.product_releases

        if requires_sbomify_api:
            if not self.token:
                operations = []
                if uploads_to_sbomify:
                    operations.append("uploading to sbomify")
                if self.product_releases:
                    operations.append("PRODUCT_RELEASE is set")
                reason = " or ".join(operations)
                raise ConfigurationError(f"sbomify API token is not defined (required when {reason})")
            if not self.component_id:
                operations = []
                if uploads_to_sbomify:
                    operations.append("uploading to sbomify")
                if self.product_releases:
                    operations.append("PRODUCT_RELEASE is set")
                reason = " or ".join(operations)
                raise ConfigurationError(f"Component ID is not defined (required when {reason})")

        inputs = [self.sbom_file, self.lock_file, self.docker_image]
        if sum(bool(x) for x in inputs) > 1:
            raise ConfigurationError("Please provide only one of: SBOM_FILE, LOCK_FILE, or DOCKER_IMAGE")
        if not any(inputs):
            raise ConfigurationError("Please provide one of: SBOM_FILE, LOCK_FILE, or DOCKER_IMAGE")

        # Validate additional-packages-only mode
        if self.is_additional_packages_only:
            from ..additional_packages import has_additional_packages_configured

            if not has_additional_packages_configured():
                raise ConfigurationError(
                    "Additional packages only mode (--lock-file none / --sbom-file none) requires "
                    "additional packages to be configured via ADDITIONAL_PACKAGES env var, "
                    "ADDITIONAL_PACKAGES_FILE, or additional_packages.txt file."
                )

        # Validate SBOM format
        if self.sbom_format not in VALID_SBOM_FORMATS:
            raise ConfigurationError(
                f"Invalid SBOM_FORMAT: '{self.sbom_format}'. Must be one of: {', '.join(VALID_SBOM_FORMATS)}"
            )

        # Validate spec_version against sbom_format
        if self.spec_version:
            from ..generation import CYCLONEDX_VERSIONS, SPDX_VERSIONS

            if self.sbom_format == "cyclonedx" and self.spec_version not in CYCLONEDX_VERSIONS:
                raise ConfigurationError(
                    f"Invalid spec_version '{self.spec_version}' for CycloneDX. "
                    f"Supported: {', '.join(CYCLONEDX_VERSIONS)}"
                )
            if self.sbom_format == "spdx" and self.spec_version not in SPDX_VERSIONS:
                raise ConfigurationError(
                    f"Invalid spec_version '{self.spec_version}' for SPDX. Supported: {', '.join(SPDX_VERSIONS)}"
                )

        # Validate product releases format
        if self.product_releases:
            try:
                # Parse JSON list format like ["product_id:v1.2.3"]
                product_releases_list = json.loads(self.product_releases)
                if not isinstance(product_releases_list, list):
                    raise ConfigurationError('PRODUCT_RELEASE must be a JSON list like ["product_id:v1.2.3"]')

                for release in product_releases_list:
                    if not isinstance(release, str) or ":" not in release:
                        raise ConfigurationError(
                            f"Invalid PRODUCT_RELEASE format: '{release}'. Expected format: 'product_id:version'"
                        )

                    product_id, version = release.split(":", 1)
                    # Validate that product_id looks like a proper ID (not empty)
                    if not product_id.strip():
                        raise ConfigurationError(
                            f"Invalid product_id in PRODUCT_RELEASE: '{release}'. Product ID cannot be empty."
                        )
                    if not version.strip():
                        raise ConfigurationError(
                            f"Invalid version in PRODUCT_RELEASE: '{release}'. Version cannot be empty."
                        )

                # Store the parsed list back for later use
                self.product_releases = product_releases_list
                logger.info(f"Validated product releases: {self.product_releases}")

            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid JSON format for PRODUCT_RELEASE: {e}")
            except Exception as e:
                if "ConfigurationError" in str(type(e)):
                    raise  # Re-raise ConfigurationError as-is
                raise ConfigurationError(f"Error parsing PRODUCT_RELEASE: {e}")

        # Validate API base URL format with proper parsing
        self._validate_api_url()

    def _validate_api_url(self) -> None:
        """
        Validate and normalize the API base URL.

        Raises:
            ConfigurationError: If URL format is invalid
        """
        from urllib.parse import urlparse

        try:
            parsed = urlparse(self.api_base_url)
        except Exception as e:
            raise ConfigurationError(f"Invalid API base URL format: {e}")

        # Validate scheme
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            raise ConfigurationError("API base URL must start with http:// or https://")

        # Validate hostname
        if not parsed.netloc:
            raise ConfigurationError("API base URL must include a valid hostname")

        # Security warning for HTTP on non-localhost
        if parsed.scheme == "http" and not any(localhost in parsed.netloc for localhost in LOCALHOST_PATTERNS):
            logger.warning("Using HTTP (not HTTPS) for API communication - consider using HTTPS in production")

        # Remove trailing slash if present for consistency
        if self.api_base_url.endswith("/"):
            self.api_base_url = self.api_base_url.rstrip("/")


def _handle_deprecated_version(component_version: Optional[str], sbom_version: Optional[str]) -> Optional[str]:
    """
    Handle component version with deprecation support for SBOM_VERSION.

    Args:
        component_version: Value from COMPONENT_VERSION or --component-version
        sbom_version: Value from deprecated SBOM_VERSION env var

    Returns:
        The resolved component version
    """
    if component_version and sbom_version:
        logger.warning(
            "Both COMPONENT_VERSION and SBOM_VERSION are set. Using COMPONENT_VERSION and ignoring SBOM_VERSION."
        )
        logger.warning("SBOM_VERSION is deprecated. Please use COMPONENT_VERSION instead.")
        return component_version
    elif sbom_version:
        logger.warning("SBOM_VERSION is deprecated. Please use COMPONENT_VERSION instead.")
        return sbom_version
    return component_version


def _handle_deprecated_name(
    component_name: Optional[str], override_name_env: Optional[str]
) -> tuple[Optional[str], bool]:
    """
    Handle component name with deprecation support for OVERRIDE_NAME.

    Args:
        component_name: Value from COMPONENT_NAME or --component-name
        override_name_env: Value from deprecated OVERRIDE_NAME env var

    Returns:
        Tuple of (final_component_name, final_override_name)
    """
    override_name = evaluate_boolean(override_name_env) if override_name_env else False

    if component_name and override_name:
        logger.warning(
            "Both COMPONENT_NAME and OVERRIDE_NAME are set. Using COMPONENT_NAME and ignoring OVERRIDE_NAME."
        )
        logger.warning("OVERRIDE_NAME is deprecated. Please use COMPONENT_NAME instead.")
        return component_name, False
    elif override_name:
        logger.warning("OVERRIDE_NAME is deprecated. Please use COMPONENT_NAME instead.")
        return None, True
    return component_name, False


def _parse_upload_destinations(destinations_str: Optional[str]) -> Optional[list[str]]:
    """
    Parse and validate upload destinations from a comma-separated string.

    Args:
        destinations_str: Comma-separated list of destinations

    Returns:
        List of valid destination names, or None if not specified

    Raises:
        SystemExit: If invalid destinations are specified
    """
    if not destinations_str:
        return None

    destinations = [d.strip() for d in destinations_str.split(",") if d.strip()]
    invalid_destinations = [d for d in destinations if d not in VALID_DESTINATIONS]

    if invalid_destinations:
        logger.error(f"Invalid upload destination(s): {invalid_destinations}")
        logger.error(f"Valid destinations are: {sorted(VALID_DESTINATIONS)}")
        sys.exit(1)

    logger.info(f"Upload destinations: {destinations}")
    return destinations


def build_config(
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    sbom_file: Optional[str] = None,
    docker_image: Optional[str] = None,
    lock_file: Optional[str] = None,
    output_file: str = "sbom_output.json",
    upload: bool = True,
    upload_destinations: Optional[list[str]] = None,
    augment: bool = False,
    enrich: bool = False,
    override_sbom_metadata: bool = False,
    component_version: Optional[str] = None,
    component_name: Optional[str] = None,
    component_purl: Optional[str] = None,
    product_releases: Optional[str] = None,
    api_base_url: str = SBOMIFY_PRODUCTION_API,
    sbom_format: str = "cyclonedx",
    spec_version: Optional[str] = None,
) -> Config:
    """
    Build and validate configuration from provided arguments.

    This function handles deprecation warnings and path expansion.

    Returns:
        Validated configuration object

    Raises:
        SystemExit: If configuration is invalid
    """
    # Handle deprecated SBOM_VERSION env var (only applies when using env vars)
    sbom_version_env = os.getenv("SBOM_VERSION")
    final_component_version = _handle_deprecated_version(component_version, sbom_version_env)

    # Log component version
    if final_component_version:
        logger.info(f"Using component version: {final_component_version}")
    else:
        logger.info("No component version specified (COMPONENT_VERSION not set)")

    # Handle deprecated OVERRIDE_NAME env var
    override_name_env = os.getenv("OVERRIDE_NAME")
    final_component_name, final_override_name = _handle_deprecated_name(component_name, override_name_env)

    # Log component name
    if final_component_name:
        logger.info(f"Using component name: {final_component_name}")
    elif final_override_name:
        logger.info("Using OVERRIDE_NAME mode (deprecated) - will use name from backend metadata")
    else:
        logger.info("No component name specified")

    # Log component PURL
    if component_purl:
        logger.info(f"Using component PURL: {component_purl}")

    # Log product releases
    if product_releases:
        logger.info(f"Raw product release input: {product_releases}")

    # Log SBOM format
    sbom_format_lower = sbom_format.lower()
    logger.info(f"SBOM format: {format_display_name(sbom_format_lower)}")

    # Expand paths if provided (skip expansion for "none" sentinel)
    expanded_sbom_file = (
        sbom_file
        if (sbom_file and sbom_file.lower() == NONE_SENTINEL)
        else (path_expansion(sbom_file) if sbom_file else None)
    )
    expanded_lock_file = (
        lock_file
        if (lock_file and lock_file.lower() == NONE_SENTINEL)
        else (path_expansion(lock_file) if lock_file else None)
    )

    config = Config(
        token=token or "",
        component_id=component_id or "",
        sbom_file=expanded_sbom_file,
        docker_image=docker_image,
        lock_file=expanded_lock_file,
        output_file=output_file,
        upload=upload,
        upload_destinations=upload_destinations,
        augment=augment,
        enrich=enrich,
        override_sbom_metadata=override_sbom_metadata,
        override_name=final_override_name,
        component_version=final_component_version,
        component_name=final_component_name,
        component_purl=component_purl,
        product_releases=product_releases,
        api_base_url=api_base_url,
        sbom_format=sbom_format_lower,
        spec_version=spec_version,
    )

    try:
        config.validate()
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    return config


def load_config() -> Config:
    """
    Load and validate configuration from environment variables.

    This is the legacy function for backward compatibility.
    New code should use build_config() or the CLI directly.

    Returns:
        Validated configuration object

    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Parse upload destinations from env var
    upload_destinations = _parse_upload_destinations(os.getenv("UPLOAD_DESTINATIONS"))

    return build_config(
        token=os.getenv("TOKEN"),
        component_id=os.getenv("COMPONENT_ID"),
        sbom_file=os.getenv("SBOM_FILE"),
        docker_image=os.getenv("DOCKER_IMAGE"),
        lock_file=os.getenv("LOCK_FILE"),
        output_file=os.getenv("OUTPUT_FILE", "sbom_output.json"),
        upload=evaluate_boolean(os.getenv("UPLOAD", "True")),
        upload_destinations=upload_destinations,
        augment=evaluate_boolean(os.getenv("AUGMENT", "False")),
        enrich=evaluate_boolean(os.getenv("ENRICH", "False")),
        override_sbom_metadata=evaluate_boolean(os.getenv("OVERRIDE_SBOM_METADATA", "False")),
        component_version=os.getenv("COMPONENT_VERSION"),
        component_name=os.getenv("COMPONENT_NAME"),
        component_purl=os.getenv("COMPONENT_PURL"),
        product_releases=os.getenv("PRODUCT_RELEASE"),
        api_base_url=os.getenv("API_BASE_URL", SBOMIFY_PRODUCTION_API),
        sbom_format=os.getenv("SBOM_FORMAT", "cyclonedx"),
    )


def setup_dependencies() -> None:
    """
    Check available SBOM generation tools and log their status.

    This function no longer auto-installs tools. Instead, it logs
    which tools are available and provides guidance when tools are missing.
    """
    from ..tool_checks import get_available_tools, get_missing_tools

    # Check all tools and log status
    available = get_available_tools()
    missing = get_missing_tools()

    if available:
        logger.info(f"Available SBOM generators: {', '.join(available)}")
    else:
        logger.warning("No external SBOM generators found.")
        logger.warning("SBOM generation may fail. Install trivy, syft, or cdxgen for full functionality.")
        logger.warning("The Docker image (sbomifyhub/sbomify-action) includes all tools pre-installed.")

    if missing and available:
        # Some tools available, some missing - just log for information
        logger.debug(f"Additional tools not installed: {', '.join(missing)}")


def initialize_sentry() -> None:
    """Initialize Sentry for error tracking.

    Can be disabled by setting TELEMETRY to 'false', '0', or 'no'.
    """
    # Allow users to opt-out of telemetry
    telemetry_enabled = os.getenv("TELEMETRY", "true").lower()
    if telemetry_enabled in ("false", "0", "no", "off", "disabled"):
        logger.debug("Sentry telemetry disabled via TELEMETRY environment variable")
        return

    sentry_dsn = os.getenv("SENTRY_DSN", "https://84e8d6d0a7d0872a4bba8add571a554c@sentry.vikpire.com/4")

    def before_send(event, hint):
        """
        Filter events before sending to Sentry.
        Don't send user input validation errors - these are expected user errors.
        """
        # Filter exceptions
        if "exc_info" in hint:
            exc_type, exc_value, tb = hint["exc_info"]
            # Don't send validation or configuration errors - these are user errors
            # SBOMGenerationError and APIError should still be sent (tool/system bugs)
            # DockerImageNotFoundError is a user configuration error (image doesn't exist)
            if isinstance(
                exc_value, (SBOMValidationError, ConfigurationError, DockerImageNotFoundError, ToolNotAvailableError)
            ):
                return None

        # Filter log messages for user configuration errors
        # These come through the logging integration, not as exceptions
        message = event.get("message") or event.get("logentry", {}).get("formatted", "")
        if message.startswith("Configuration error:"):
            return None

        return event

    sentry_sdk.init(
        dsn=sentry_dsn,
        send_default_pii=True,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        before_send=before_send,
        release=f"sbomify-action@{SBOMIFY_VERSION}",
    )

    # Set the action version as a tag (always safe to send)
    sentry_sdk.set_tag("action.version", SBOMIFY_VERSION)

    # Detect CI/CD platform
    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
    is_gitlab_ci = os.getenv("GITLAB_CI") == "true"
    is_bitbucket = os.getenv("BITBUCKET_PIPELINE_UUID") is not None

    # Determine if we should send context based on repository visibility
    # GitHub Actions
    if is_github_actions:
        github_visibility = os.getenv("GITHUB_REPOSITORY_VISIBILITY", "").lower()
        is_public_repo = github_visibility == "public"
        sentry_sdk.set_tag("ci.platform", "github-actions")
        sentry_sdk.set_tag("repo.public", str(is_public_repo))

        if is_public_repo:
            # Add GitHub context tags for public repos only
            ci_context = {}
            if repo := os.getenv("GITHUB_REPOSITORY"):
                sentry_sdk.set_tag("ci.repository", repo)
                ci_context["repository"] = repo
            if workflow := os.getenv("GITHUB_WORKFLOW"):
                sentry_sdk.set_tag("ci.workflow", workflow)
                ci_context["workflow"] = workflow
            if ref := os.getenv("GITHUB_REF"):
                sentry_sdk.set_tag("ci.ref", ref)
                ci_context["ref"] = ref
            if sha := os.getenv("GITHUB_SHA"):
                sentry_sdk.set_tag("ci.sha", sha[:7])
                ci_context["sha"] = sha
            if action := os.getenv("GITHUB_ACTION"):
                ci_context["action"] = action
            if run_id := os.getenv("GITHUB_RUN_ID"):
                ci_context["run_id"] = run_id
            if run_number := os.getenv("GITHUB_RUN_NUMBER"):
                ci_context["run_number"] = run_number

            if ci_context:
                sentry_sdk.set_context("ci", ci_context)
        else:
            logger.debug("Skipping CI context for Sentry (private repository or visibility not set)")

    # GitLab CI
    elif is_gitlab_ci:
        gitlab_visibility = os.getenv("CI_PROJECT_VISIBILITY", "").lower()
        is_public_repo = gitlab_visibility == "public"
        sentry_sdk.set_tag("ci.platform", "gitlab-ci")
        sentry_sdk.set_tag("repo.public", str(is_public_repo))

        if is_public_repo:
            # Add GitLab context tags for public projects only
            ci_context = {}
            if project := os.getenv("CI_PROJECT_PATH"):
                sentry_sdk.set_tag("ci.repository", project)
                ci_context["project"] = project
            if pipeline_source := os.getenv("CI_PIPELINE_SOURCE"):
                sentry_sdk.set_tag("ci.pipeline_source", pipeline_source)
                ci_context["pipeline_source"] = pipeline_source
            if ref := os.getenv("CI_COMMIT_REF_NAME"):
                sentry_sdk.set_tag("ci.ref", ref)
                ci_context["ref"] = ref
            if sha := os.getenv("CI_COMMIT_SHORT_SHA"):
                sentry_sdk.set_tag("ci.sha", sha)
                ci_context["sha"] = sha
            if pipeline_id := os.getenv("CI_PIPELINE_ID"):
                ci_context["pipeline_id"] = pipeline_id
            if job_name := os.getenv("CI_JOB_NAME"):
                ci_context["job_name"] = job_name

            if ci_context:
                sentry_sdk.set_context("ci", ci_context)
        else:
            logger.debug("Skipping CI context for Sentry (private repository or visibility not set)")

    # Bitbucket Pipelines
    elif is_bitbucket:
        # Bitbucket doesn't expose repository visibility, so we treat all repos as private by default
        # This is the safest approach for privacy
        sentry_sdk.set_tag("ci.platform", "bitbucket-pipelines")
        sentry_sdk.set_tag("repo.public", "False")
        logger.debug("Skipping CI context for Sentry (Bitbucket repository visibility unknown, treating as private)")

    # Unknown/Local environment
    else:
        sentry_sdk.set_tag("ci.platform", "unknown")
        logger.debug("Skipping CI context for Sentry (not running in a recognized CI/CD platform)")


def path_expansion(path: str) -> str:
    """
    Takes a path/file and returns an absolute path.
    This function is needed to handle GitHub Action's
    somewhat custom path management inside Docker.

    Args:
        path: Input path to expand

    Returns:
        Absolute path string

    Raises:
        FileProcessingError: If file is not found or path looks like a CLI flag
    """
    # Check if the path looks like a CLI flag (common mistake when forgetting to provide a value)
    if path.startswith("-"):
        raise FileProcessingError(
            f"Invalid file path '{path}' - this looks like a CLI flag. "
            f"Did you forget to specify a file path? "
            f"Example: --lock-file requirements.txt or set the LOCK_FILE environment variable."
        )

    current_dir = Path.cwd()
    relative_path = current_dir / path
    workspace_relative_path = Path("/github/workspace") / path

    # Log which paths we're checking for debugging
    logger.debug(f"Searching for file '{path}'...")
    logger.debug(f"  Checking direct path: {Path(path)}")
    logger.debug(f"  Checking relative to cwd: {relative_path}")
    logger.debug(f"  Checking workspace path: {workspace_relative_path}")

    if Path(path).is_file():
        logger.info(f"Using input file '{path}'.")
        return str(current_dir / path)
    elif relative_path.is_file():
        logger.info(f"Using input file '{relative_path}'.")
        return str(relative_path)
    elif workspace_relative_path.is_file():
        logger.info(f"Using input file '{workspace_relative_path}'.")
        return str(workspace_relative_path)
    else:
        raise FileProcessingError(
            f"Specified input file '{path}' not found. Searched in: '{relative_path}', '{workspace_relative_path}'"
        )


def get_last_sbom_from_last_step() -> Optional[str]:
    """
    Helper function to get the SBOM from the previous step.

    Returns:
        Path to the most recent SBOM file, or None if not found
    """
    steps = [STEP_3_FILE, STEP_2_FILE, STEP_1_FILE]
    for file in steps:
        if Path(file).is_file():
            return file
    return None


def evaluate_boolean(value: str) -> bool:
    """
    Evaluate string values as boolean.

    Args:
        value: String value to evaluate

    Returns:
        Boolean result
    """
    return value.lower() in ["true", "yes", "yeah", "1"]


def validate_sbom(file_path: str) -> str:
    """
    Validate and detect the format of an SBOM file.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        Format string: 'cyclonedx' or 'spdx'

    Raises:
        SBOMValidationError: If SBOM is invalid or unsupported format
    """
    try:
        with Path(file_path).open("r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except FileNotFoundError:
        raise SBOMValidationError(f"SBOM file not found: {file_path}")

    # Detect artifact type (only log once during initial validation)
    if data.get("bomFormat") == "CycloneDX":
        logger.info("Detected CycloneDX SBOM.")
        return "cyclonedx"
    elif data.get("spdxVersion") is not None or is_spdx3(data):
        logger.info("Detected SPDX SBOM.")
        return "spdx"
    else:
        raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")


def _detect_sbom_format_silent(file_path: str) -> str:
    """
    Silently detect the format of an SBOM file without logging.
    Used for internal format checks after initial detection.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        Format string: 'cyclonedx' or 'spdx'

    Raises:
        SBOMValidationError: If SBOM is invalid or unsupported format
    """
    try:
        with Path(file_path).open("r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except FileNotFoundError:
        raise SBOMValidationError(f"SBOM file not found: {file_path}")

    # Detect artifact type without logging
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    elif data.get("spdxVersion") is not None or is_spdx3(data):
        return "spdx"
    else:
        raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")


def load_sbom_from_file(file_path: str) -> tuple[str, dict, object]:
    """
    Load SBOM from JSON file using appropriate library based on format.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        Tuple of (format, original_json, parsed_object)
        - format: 'cyclonedx' or 'spdx'
        - original_json: Original JSON dict
        - parsed_object: Parsed object (Bom for CycloneDX, future SPDX object)

    Raises:
        SBOMValidationError: If SBOM cannot be parsed
    """
    try:
        with Path(file_path).open("r") as f:
            sbom_json = json.load(f)

        # Detect format silently (format should already be known at this point)
        if sbom_json.get("bomFormat") == "CycloneDX":
            sbom_format = "cyclonedx"
            # Use cyclonedx deserializer
            parsed_object = Bom.from_json(sbom_json)
            logger.debug(f"Successfully loaded CycloneDX SBOM from {file_path}")
        elif sbom_json.get("spdxVersion") is not None or is_spdx3(sbom_json):
            sbom_format = "spdx"
            # Return the JSON dict for both SPDX 2.x and 3.x
            parsed_object = sbom_json
            logger.debug(f"Successfully loaded SPDX SBOM from {file_path}")
        else:
            raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")

        return sbom_format, sbom_json, parsed_object

    except Exception as e:
        raise SBOMValidationError(f"Failed to load SBOM from {file_path}: {e}")


def enrich_sbom(input_file: str, output_file: str) -> None:
    """
    Takes a path to an SBOM as input and returns an enriched SBOM as the output
    using the plugin-based enrichment system.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Raises:
        SBOMGenerationError: If enrichment fails
    """
    from ..enrichment import enrich_sbom as _enrich_impl

    try:
        _enrich_impl(input_file, output_file)
    except FileNotFoundError as e:
        raise SBOMGenerationError(f"Input file not found: {e}")
    except ValueError as e:
        raise SBOMValidationError(f"Invalid SBOM format: {e}")
    except Exception as e:
        raise SBOMGenerationError(f"Enrichment failed: {e}")


def print_banner() -> None:
    """Print the sbomify banner with gradient colors."""
    console_print_banner(SBOMIFY_VERSION)


def _log_step_header(step_num: int | float, title: str, emoji: str = "") -> None:
    """
    Log a nicely formatted step header optimized for GitHub Actions.

    Args:
        step_num: Step number (e.g., 1, 2, or substeps like 1.4, 1.5)
        title: Step title
        emoji: Optional emoji to include (deprecated, will be ignored)
    """
    print_step_header(step_num, title)


def _log_step_end(step_num: int | float, success: bool = True) -> None:
    """
    Log step completion and close GitHub Actions group if applicable.

    Args:
        step_num: Step number (e.g., 1, 2, or substeps like 1.4, 1.5)
        success: Whether the step completed successfully
    """
    print_step_end(step_num, success)


def run_pipeline(config: Config) -> None:
    """
    Run the SBOM pipeline with the given configuration.

    This is the core business logic, separated from CLI/config handling.

    Args:
        config: Validated configuration object
    """
    # Initialize audit trail with input file info
    audit_trail = get_audit_trail()
    if config.is_additional_packages_only:
        audit_trail.input_file = "additional-packages-only"
    elif config.sbom_file:
        audit_trail.input_file = config.sbom_file
    elif config.lock_file:
        audit_trail.input_file = config.lock_file
    elif config.docker_image:
        audit_trail.input_file = f"docker:{config.docker_image}"

    # Log the API base URL being used for transparency
    if config.api_base_url != SBOMIFY_PRODUCTION_API:
        logger.info(f"Using custom API base URL: {config.api_base_url}")
    else:
        logger.info(f"Using production API: {config.api_base_url}")

    # Step 1: SBOM Generation/Validation
    _log_step_header(1, "SBOM Generation/Input Processing")

    # Check if either SBOM_FILE or LOCK_FILE exists
    if config.is_additional_packages_only:
        FILE_TYPE = "ADDITIONAL_ONLY"
    elif config.sbom_file:
        FILE = config.sbom_file
        FILE_TYPE = "SBOM"
    elif config.lock_file:
        FILE = config.lock_file
        FILE_TYPE = "LOCK_FILE"
    elif config.docker_image:
        FILE_TYPE = None
        pass
    else:
        logger.error("Neither SBOM file, Docker image nor lockfile found.")
        sys.exit(1)

    # Process input based on type
    if FILE_TYPE == "ADDITIONAL_ONLY":
        from ..additional_packages import create_empty_sbom

        logger.info("Additional packages only mode: creating empty SBOM")
        try:
            FORMAT = create_empty_sbom(STEP_1_FILE, config.sbom_format, config.spec_version)
        except Exception as e:
            logger.error(f"Failed to create empty SBOM: {e}")
            _log_step_end(1, success=False)
            sys.exit(1)
    else:
        try:
            if FILE_TYPE == "SBOM":
                logger.info(f"Processing existing SBOM file: {FILE}")
                FORMAT = validate_sbom(FILE)
                shutil.copy(FILE, STEP_1_FILE)
            elif config.docker_image:
                logger.info(f"Generating SBOM from Docker image: {config.docker_image}")
                result = generate_sbom(
                    docker_image=config.docker_image,
                    output_file=STEP_1_FILE,
                    output_format=config.sbom_format,
                    spec_version=config.spec_version,
                )
                if not result.success:
                    raise SBOMGenerationError(result.error_message or "SBOM generation failed")
            elif FILE_TYPE == "LOCK_FILE":
                logger.info(f"Generating SBOM from lock file: {FILE}")
                result = process_lock_file(
                    FILE,
                    output_file=STEP_1_FILE,
                    output_format=config.sbom_format,
                    spec_version=config.spec_version,
                )
                if not result.success:
                    raise SBOMGenerationError(result.error_message or "SBOM generation failed")
            else:
                logger.error("Unrecognized FILE_TYPE.")
                sys.exit(1)
        except SBOMValidationError as e:
            # User-provided SBOM validation errors - don't send to Sentry
            logger.error(f"Step 1 failed: {e}")
            if FILE_TYPE == "SBOM":
                file_name = Path(FILE).name
                logger.error(f"The provided SBOM file '{FILE}' appears to be invalid.")
                logger.error("Please ensure the file is a valid CycloneDX or SPDX JSON document.")

                # Check if user accidentally provided a lock file instead of an SBOM
                if file_name in ALL_LOCK_FILES:
                    logger.error(f"'{file_name}' is a lock file, not an SBOM.")
                    logger.error(f"Please use LOCK_FILE instead of SBOM_FILE for '{file_name}'.")
            _log_step_end(1, success=False)
            sys.exit(1)
        except (FileProcessingError, SBOMGenerationError, ValueError) as e:
            logger.error(f"Step 1 failed: {e}")
            _log_step_end(1, success=False)
            sys.exit(1)

    # Set the SBOM format based on the output (silent detection for generated SBOMs)
    try:
        if FILE_TYPE not in ("SBOM", "ADDITIONAL_ONLY"):  # Only detect format if we generated the SBOM
            FORMAT = _detect_sbom_format_silent(STEP_1_FILE)
            logger.info(f"Generated SBOM format: {format_display_name(FORMAT)}")
    except SBOMValidationError as e:
        logger.error(f"Generated SBOM validation failed: {e}")
        logger.error("The SBOM generation tool produced an invalid output file.")

        # Re-raise with better context for Sentry (but don't include file contents for privacy)
        if config.docker_image:
            raise SBOMGenerationError(
                f"Trivy generated invalid SBOM for Docker image '{config.docker_image}': {e}"
            ) from e
        elif FILE_TYPE == "LOCK_FILE":
            lock_file_name = Path(FILE).name
            raise SBOMGenerationError(
                f"SBOM generation tool produced invalid output for lock file '{lock_file_name}': {e}"
            ) from e
        else:
            raise SBOMGenerationError(f"Generated SBOM validation failed: {e}") from e

    _log_step_end(1)

    # Apply component version override if specified (regardless of augmentation settings)
    if config.component_version:
        logger.info(f"Applying component version override: {config.component_version}")
        _apply_sbom_version_override(STEP_1_FILE, config)

    # Apply component name override if specified (regardless of augmentation settings)
    if config.component_name:
        logger.info(f"Applying component name override: {config.component_name}")
        _apply_sbom_name_override(STEP_1_FILE, config)

    # Apply component PURL override if specified (regardless of augmentation settings)
    if config.component_purl:
        logger.info(f"Applying component PURL override: {config.component_purl}")
        _apply_sbom_purl_override(STEP_1_FILE, config)

    # Inject additional packages if specified (file or environment variables)
    try:
        injected_count = inject_additional_packages(STEP_1_FILE)
        if injected_count > 0:
            logger.info(f"Successfully injected {injected_count} additional package(s) into SBOM")
        elif config.is_additional_packages_only:
            logger.error("Additional packages only mode: no packages were injected")
            sys.exit(1)
    except Exception as e:
        if config.is_additional_packages_only:
            logger.error(f"Additional packages only mode: injection failed: {e}")
            sys.exit(1)
        logger.warning(
            f"Failed to inject additional packages into SBOM: {e}. "
            f"Verify that the SBOM file '{STEP_1_FILE}' exists and is readable, and that any "
            "additional package configuration (ADDITIONAL_PACKAGES env var or "
            "additional_packages.txt file) is present and correctly formatted."
        )

    # Step 1.4: Transitive Dependency Discovery (for lockfiles that support expansion)
    # Note: Steps 1.x are substeps of the main SBOM generation step (Step 1).
    # These run after initial generation but before Step 2 (Validation/Augmentation).
    # Uses registry pattern to check if any expander supports the lockfile
    if config.lock_file:
        from sbomify_action._dependency_expansion import supports_dependency_expansion

        if supports_dependency_expansion(config.lock_file):
            _log_step_header(1.4, "Transitive Dependency Discovery")
            try:
                from sbomify_action._dependency_expansion import expand_sbom_dependencies

                logger.info("Discovering transitive dependencies...")

                result = expand_sbom_dependencies(
                    sbom_file=STEP_1_FILE,
                    lock_file=config.lock_file,
                )

                if result.added_count > 0:
                    logger.info(
                        f"Added {result.added_count} transitive dependencies (discovered {result.discovered_count} total)"
                    )
                    # Log discovered packages in collapsible group
                    with gha_group("Discovered Transitive Dependencies"):
                        for dep in result.dependencies[:50]:
                            parent_info = f" (via {dep.parent})" if dep.parent else ""
                            print(f"  {dep.purl}{parent_info}")
                        if len(result.dependencies) > 50:
                            print(f"  ... and {len(result.dependencies) - 50} more")
                else:
                    if result.discovered_count > 0:
                        logger.info(
                            f"No new dependencies to add ({result.discovered_count} discovered were already in SBOM)"
                        )
                    else:
                        logger.info(
                            "No transitive dependencies discovered (packages may not be installed, or all deps are direct)"
                        )

                _log_step_end(1.4)

            except Exception as e:
                logger.warning(f"Transitive dependency discovery failed (non-fatal): {e}")
                _log_step_end(1.4, success=False)
                # Don't fail the entire process - this is an enhancement

    # Step 1.5: Hash Enrichment from Lockfile (if lockfile was used for generation)
    if config.lock_file and not config.is_additional_packages_only:
        _log_step_header(1.5, "Hash Enrichment from Lockfile")
        try:
            from sbomify_action._hash_enrichment import enrich_sbom_with_hashes

            logger.info(f"Extracting hashes from lockfile: {config.lock_file}")

            stats = enrich_sbom_with_hashes(
                sbom_file=STEP_1_FILE,
                lock_file=config.lock_file,
                overwrite_existing=False,
            )

            if stats["hashes_added"] > 0:
                logger.info(
                    f"Added {stats['hashes_added']} hash(es) to "
                    f"{stats['components_matched']}/{stats['sbom_components']} component(s)"
                )
            else:
                logger.info("No additional hashes to add from lockfile")

            _log_step_end(1.5)

        except Exception as e:
            logger.warning(f"Hash enrichment failed (non-fatal): {e}")
            _log_step_end(1.5, success=False)
            # Don't fail the entire process for hash enrichment issues

    # Step 2: Augmentation
    if config.augment:
        _log_step_header(2, "SBOM Augmentation with Backend Metadata")

        # Inform user if API augmentation is unavailable
        if not config.token or not config.component_id:
            gha_notice(
                "sbomify API augmentation skipped (TOKEN or COMPONENT_ID not set). "
                "To add metadata, create a sbomify.json file in your project root "
                "or configure sbomify API credentials.",
                title="API Augmentation Skipped",
            )

        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            logger.info("Augmenting SBOM with backend metadata")

            # Use augmentation module's file-based function
            # Note: PURL override is applied separately via _apply_sbom_purl_override()
            sbom_format = augment_sbom_from_file(
                input_file=sbom_input_file,
                output_file=STEP_2_FILE,
                api_base_url=config.api_base_url,
                token=config.token,
                component_id=config.component_id,
                override_sbom_metadata=config.override_sbom_metadata,
                component_name=config.component_name,
                component_version=config.component_version,
            )

            logger.info(f"{format_display_name(sbom_format)} SBOM augmentation completed")
            _log_step_end(2)

        except (FileProcessingError, APIError, SBOMValidationError) as e:
            logger.error(f"Step 2 (augmentation) failed: {e}")
            _log_step_end(2, success=False)
            sys.exit(1)
    else:
        _log_step_header(2, "SBOM Augmentation - SKIPPED")
        logger.info("SBOM augmentation disabled (AUGMENT=false)")
        _log_step_end(2)

    # Step 3: Enrichment
    if config.enrich:
        _log_step_header(3, "SBOM Enrichment with Ecosystem Data")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            logger.info("Enriching SBOM components with metadata from multiple data sources")
            enrich_sbom(sbom_input_file, STEP_3_FILE)
            _detect_sbom_format_silent(STEP_3_FILE)  # Silent validation
            _log_step_end(3)
        except (FileProcessingError, SBOMGenerationError, SBOMValidationError) as e:
            logger.error(f"Step 3 (enrichment) failed: {e}")
            _log_step_end(3, success=False)
            sys.exit(1)
    else:
        _log_step_header(3, "SBOM Enrichment - SKIPPED")
        logger.info("SBOM enrichment disabled (ENRICH=false)")
        _log_step_end(3)

    # Step 4: Finalize output
    _log_step_header(4, "Finalizing SBOM Output")
    try:
        final_sbom_file = get_last_sbom_from_last_step()
        if not final_sbom_file:
            raise FileProcessingError("No SBOM file found to finalize")

        # Get the parent directory of the file path
        parent_dir = Path(config.output_file).parent

        # Check if the parent directory exists; if not, create it recursively
        if parent_dir != Path(".") and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

        # Read, fix any PURL encoding bugs, and write final SBOM
        # This fixes double-encoded %40%40 or double @@ issues
        # Note: We preserve canonical %40 encoding per PURL spec
        with open(final_sbom_file, "r") as f:
            content = f.read()

        # Detect format and fix any PURL encoding bugs in CycloneDX
        if '"bomFormat"' in content and '"CycloneDX"' in content:
            content = _fix_purl_encoding_bugs_in_json(content)

        with open(config.output_file, "w") as f:
            f.write(content)

        # Clean up temporary files
        while get_last_sbom_from_last_step():
            temp_file = get_last_sbom_from_last_step()
            Path(temp_file).unlink()

        logger.info(f"Final SBOM saved to: {config.output_file}")
        _log_step_end(4)

    except (FileProcessingError, OSError) as e:
        logger.error(f"Failed to finalize output: {e}")
        _log_step_end(4, success=False)
        sys.exit(1)

    # Step 5: Upload SBOM to configured destinations
    sbom_id = None  # Store SBOM ID for potential release tagging (from sbomify)
    if config.upload:
        _log_step_header(5, "Uploading SBOM")
        try:
            # Upload to each configured destination
            logger.info(f"Upload destinations: {config.upload_destinations}")

            failed_destinations: list[str] = []
            for destination in config.upload_destinations:
                logger.info(f"Uploading to: {destination}")

                result = upload_sbom(
                    sbom_file=config.output_file,
                    sbom_format=FORMAT,
                    token=config.token,
                    component_id=config.component_id,
                    api_base_url=config.api_base_url,
                    component_name=config.component_name,
                    component_version=config.component_version,
                    destination=destination,
                    validate_before_upload=(FORMAT == "cyclonedx"),
                )

                if not result.success:
                    if result.error_code == "DUPLICATE_ARTIFACT":
                        logger.error(
                            f"Upload to {destination} failed with duplicate SBOM: "
                            f"component_id={config.component_id}, format={FORMAT}, "
                            f"version={config.component_version}"
                        )
                        print_duplicate_sbom_error(config.component_id, FORMAT, config.component_version)
                    elif result.error_code == "COMPONENT_NOT_FOUND":
                        logger.error(
                            f"Upload to {destination} failed: component not found (component_id={config.component_id})"
                        )
                        print_component_not_found_error(config.component_id)
                    else:
                        logger.error(f"Upload to {destination} failed: {result.error_message}")
                    failed_destinations.append(destination)
                else:
                    logger.info(f"Upload to {destination} succeeded")
                    # Store sbom_id from sbomify for release tagging
                    if destination == "sbomify" and result.sbom_id:
                        sbom_id = result.sbom_id

            # Fail if any upload failed
            if failed_destinations:
                raise APIError(f"Upload failed for destination(s): {', '.join(failed_destinations)}")

            _log_step_end(5)

        except (APIError, FileProcessingError) as e:
            logger.error(f"Step 5 (upload) failed: {e}")
            _log_step_end(5, success=False)
            sys.exit(1)
    else:
        _log_step_header(5, "SBOM Upload - SKIPPED")
        logger.info("SBOM upload disabled (UPLOAD=false)")
        _log_step_end(5)

    # Step 6: Post-upload Processing (releases, signing, etc.)
    if sbom_id:
        _log_step_header(6, "Post-upload Processing")
        try:
            from sbomify_action._processors import ProcessorInput, ProcessorOrchestrator

            orchestrator = ProcessorOrchestrator(
                api_base_url=config.api_base_url,
                token=config.token,
            )
            processor_input = ProcessorInput(
                sbom_id=sbom_id,
                sbom_file=config.output_file,
                product_releases=config.product_releases,
                api_base_url=config.api_base_url,
                token=config.token,
            )

            # Check if any processors are enabled
            enabled_processors = orchestrator.get_enabled_processors(processor_input)
            if enabled_processors:
                logger.info(f"Running {len(enabled_processors)} processor(s): {enabled_processors}")
                results = orchestrator.process_all(processor_input)

                # Log results
                for result in results.enabled_processors:
                    if result.success:
                        logger.info(
                            f"Processor '{result.processor_name}' completed: {result.processed_items} item(s) processed"
                        )
                    else:
                        logger.error(f"Processor '{result.processor_name}' failed: {result.error_message}")

                if results.any_failures:
                    _log_step_end(6, success=False)
                else:
                    _log_step_end(6)
            else:
                logger.info("No processors enabled for this run")
                _log_step_end(6)
        except Exception as e:
            logger.error(f"Step 6 (post-upload processing) failed: {e}")
            _log_step_end(6, success=False)
            # Don't exit here - post-upload processing is optional
    elif config.product_releases and not sbom_id:
        _log_step_header(6, "Post-upload Processing - SKIPPED")
        logger.warning("Product releases specified but no SBOM ID available (upload may have been disabled or failed)")
        _log_step_end(6, success=False)

    # Finalize audit trail
    audit_trail = get_audit_trail()
    audit_trail.output_file = config.output_file

    # Write audit trail file
    audit_trail_path = Path(config.output_file).parent / "audit_trail.txt"
    try:
        audit_trail.write_audit_file(str(audit_trail_path))
        logger.info(f"Audit trail written to: {audit_trail_path}")
    except Exception as e:
        logger.warning(f"Failed to write audit trail file: {e}")

    # Print summary and full audit trail for attestation
    audit_trail.print_summary()
    audit_trail.print_to_stdout_for_attestation()

    # Final success message
    print_final_success()


def _validate_cyclonedx_sbom(sbom_file_path: str) -> bool | None:
    """
    Validate CycloneDX SBOM using cyclonedx-py tool.

    Args:
        sbom_file_path: Path to the SBOM JSON file to validate

    Returns:
        True if valid, False if invalid, None if validation tool not available
    """
    import json

    try:
        # Basic JSON validation - ensure it's valid JSON and has required CycloneDX fields
        with Path(sbom_file_path).open("r") as f:
            sbom_data = json.load(f)

        # Check for basic CycloneDX structure
        if sbom_data.get("bomFormat") == "CycloneDX" and sbom_data.get("specVersion"):
            logger.debug("SBOM basic validation successful")
            return True
        else:
            logger.warning("SBOM basic validation failed: missing bomFormat or specVersion")
            return False

    except json.JSONDecodeError as e:
        logger.warning(f"SBOM validation failed: Invalid JSON - {e}")
        return False
    except FileNotFoundError:
        logger.warning(f"SBOM validation failed: File not found - {sbom_file_path}")
        return False
    except Exception as e:
        logger.warning(f"SBOM validation error: {e}")
        return False


def _update_spdx_json_purl_version(package_json: dict, new_version: str) -> bool:
    """
    Update the version in an SPDX package's PURL external reference in JSON format.

    This function operates on the raw JSON dict, not the SPDX model objects,
    because it's used in the version override path which manipulates JSON directly.

    Args:
        package_json: The SPDX package dict with optional externalRefs
        new_version: The new version to set in the PURL

    Returns:
        True if PURL was updated, False if package has no PURL ref or update failed
    """
    from packageurl import PackageURL

    external_refs = package_json.get("externalRefs", [])
    for ref in external_refs:
        if ref.get("referenceType") == "purl":
            try:
                old_purl = PackageURL.from_string(ref.get("referenceLocator", ""))
                new_purl = PackageURL(
                    type=old_purl.type,
                    namespace=old_purl.namespace,
                    name=old_purl.name,
                    version=new_version,
                    qualifiers=old_purl.qualifiers,
                    subpath=old_purl.subpath,
                )
                ref["referenceLocator"] = str(new_purl)
                logger.debug(f"Updated SPDX package PURL version in JSON: {old_purl} -> {ref['referenceLocator']}")
                return True
            except Exception as e:
                logger.warning(f"Failed to update SPDX package PURL version in JSON: {e}")
                return False
    return False


def _apply_sbom_version_override(sbom_file: str, config: "Config") -> None:
    """
    Apply component version override based on configuration.
    This function ensures that COMPONENT_VERSION (or deprecated SBOM_VERSION) is applied regardless of augmentation settings.

    Args:
        sbom_file: Path to the SBOM file to modify
        config: Configuration with version override settings

    Raises:
        SBOMValidationError: If SBOM cannot be processed
        FileProcessingError: If file operations fail
    """
    if not config.component_version:
        return  # No version override specified

    audit_trail = get_audit_trail()

    try:
        # Load SBOM from file
        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)
        old_version = None

        if sbom_format == "cyclonedx":
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType

            from ..augmentation import _update_component_purl_version

            if isinstance(parsed_object, Bom):
                # Apply version override to CycloneDX BOM object
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    old_version = parsed_object.metadata.component.version
                    parsed_object.metadata.component.version = config.component_version
                    # Also update the PURL version to maintain consistency
                    _update_component_purl_version(parsed_object.metadata.component, config.component_version)
                else:
                    # Create component if it doesn't exist
                    component_name = original_json.get("metadata", {}).get("component", {}).get("name", "unknown")
                    parsed_object.metadata.component = Component(
                        name=component_name, type=ComponentType.APPLICATION, version=config.component_version
                    )

                # Record to audit trail
                audit_trail.record_component_version_override(config.component_version, old_version)

                # Serialize the BOM back to JSON using version-aware serializer
                spec_version = original_json.get("specVersion")
                if spec_version is None:
                    raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
                serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                with Path(sbom_file).open("w") as f:
                    f.write(serialized)

        elif sbom_format == "spdx":
            if is_spdx3(original_json):
                # SPDX 3 - use parser/writer
                from ..spdx3 import get_spdx3_root_package, parse_spdx3_file, write_spdx3_file

                payload = parse_spdx3_file(sbom_file)
                root_pkg = get_spdx3_root_package(payload)
                if root_pkg:
                    old_version = root_pkg.package_version
                    root_pkg.package_version = config.component_version
                    audit_trail.record_component_version_override(config.component_version, old_version)
                    write_spdx3_file(payload, sbom_file)
                else:
                    logger.warning("SPDX 3 SBOM has no root package - cannot set version override")
            else:
                # SPDX 2.x - apply version override to packages[0].versionInfo in JSON
                if "packages" in original_json and original_json["packages"]:
                    main_package = original_json["packages"][0]
                    old_version = main_package.get("versionInfo")
                    main_package["versionInfo"] = config.component_version
                    # Also update PURL in externalRefs if present
                    _update_spdx_json_purl_version(main_package, config.component_version)

                    # Record to audit trail
                    audit_trail.record_component_version_override(config.component_version, old_version)
                else:
                    logger.warning("SPDX SBOM has no packages - cannot set version override")

                with Path(sbom_file).open("w") as f:
                    json.dump(original_json, f, indent=2)

    except Exception as e:
        logger.warning(f"Failed to apply component version override: {e}")
        # Don't fail the entire process for version override issues


def _apply_sbom_name_override(sbom_file: str, config: "Config") -> None:
    """
    Apply component name override based on configuration.
    This function ensures that COMPONENT_NAME is applied regardless of augmentation settings.

    Args:
        sbom_file: Path to the SBOM file to modify
        config: Configuration with name override settings

    Raises:
        SBOMValidationError: If SBOM cannot be processed
        FileProcessingError: If file operations fail
    """
    if not config.component_name:
        return  # No name override specified

    audit_trail = get_audit_trail()

    try:
        # Load SBOM from file
        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)

        if sbom_format == "cyclonedx":
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType

            if isinstance(parsed_object, Bom):
                # Apply name override to CycloneDX BOM object
                needs_update = False
                old_name = None
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    old_name = parsed_object.metadata.component.name or "unknown"
                    if old_name != config.component_name:
                        parsed_object.metadata.component.name = config.component_name
                        needs_update = True
                else:
                    # Create component if it doesn't exist
                    component_version = original_json.get("metadata", {}).get("component", {}).get("version", "unknown")
                    parsed_object.metadata.component = Component(
                        name=config.component_name, type=ComponentType.APPLICATION, version=component_version
                    )
                    needs_update = True

                if needs_update:
                    # Record to audit trail
                    audit_trail.record_component_name_override(config.component_name, old_name)

                    # Serialize the BOM back to JSON using version-aware serializer
                    spec_version = original_json.get("specVersion")
                    if spec_version is None:
                        raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
                    serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                    with Path(sbom_file).open("w") as f:
                        f.write(serialized)

        elif sbom_format == "spdx":
            if is_spdx3(original_json):
                # SPDX 3 - use parser/writer
                from ..spdx3 import get_spdx3_document, get_spdx3_root_package, parse_spdx3_file, write_spdx3_file

                payload = parse_spdx3_file(sbom_file)
                doc = get_spdx3_document(payload)
                root_pkg = get_spdx3_root_package(payload)
                if not doc and not root_pkg:
                    logger.warning("SPDX 3 SBOM has no document or root package - cannot set name override")
                else:
                    old_name = (doc.name if doc else None) or "unknown"
                    if old_name != config.component_name:
                        if doc:
                            doc.name = config.component_name
                        if root_pkg:
                            root_pkg.name = config.component_name
                        audit_trail.record_component_name_override(config.component_name, old_name)
                        write_spdx3_file(payload, sbom_file)
            else:
                # SPDX 2.x - apply name override to the top-level "name" field
                old_name = original_json.get("name", "unknown")
                if old_name != config.component_name:
                    original_json["name"] = config.component_name

                    # Record to audit trail
                    audit_trail.record_component_name_override(config.component_name, old_name)

                    with Path(sbom_file).open("w") as f:
                        json.dump(original_json, f, indent=2)

    except Exception as e:
        logger.warning(f"Failed to apply component name override: {e}")
        # Don't fail the entire process for name override issues


def _apply_sbom_purl_override(sbom_file: str, config: "Config") -> None:
    """
    Apply component PURL override based on configuration.
    This function ensures that COMPONENT_PURL is applied regardless of augmentation settings.

    Args:
        sbom_file: Path to the SBOM file to modify
        config: Configuration with PURL override settings

    Raises:
        SBOMValidationError: If SBOM cannot be processed
        FileProcessingError: If file operations fail
    """
    if not config.component_purl:
        return  # No PURL override specified

    # Validate PURL format before applying
    try:
        from packageurl import PackageURL

        purl_obj = PackageURL.from_string(config.component_purl)
    except ValueError as e:
        logger.warning(
            f"Invalid COMPONENT_PURL '{config.component_purl}': {e}. Expected format: pkg:type/namespace/name@version"
        )
        return  # Skip invalid PURLs

    audit_trail = get_audit_trail()

    try:
        # Load SBOM from file
        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)

        if sbom_format == "cyclonedx":
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType

            if isinstance(parsed_object, Bom):
                # Apply PURL override to CycloneDX BOM object
                needs_update = False
                old_purl = None
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    old_purl = (
                        str(parsed_object.metadata.component.purl) if parsed_object.metadata.component.purl else None
                    )
                    if old_purl != config.component_purl:
                        parsed_object.metadata.component.purl = purl_obj
                        needs_update = True
                else:
                    # Create component if it doesn't exist
                    component = original_json.get("metadata", {}).get("component", {})
                    component_name = component.get("name", "unknown")
                    component_version = component.get("version", "unknown")
                    parsed_object.metadata.component = Component(
                        name=component_name, type=ComponentType.APPLICATION, version=component_version, purl=purl_obj
                    )
                    needs_update = True

                if needs_update:
                    # Record to audit trail
                    audit_trail.record_component_purl_override(config.component_purl, old_purl)

                    # Serialize the BOM back to JSON using version-aware serializer
                    spec_version = original_json.get("specVersion")
                    if spec_version is None:
                        raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
                    serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                    with Path(sbom_file).open("w") as f:
                        f.write(serialized)

        elif sbom_format == "spdx":
            if is_spdx3(original_json):
                # SPDX 3 - use parser/writer
                from ..spdx3 import get_spdx3_root_package, parse_spdx3_file, write_spdx3_file

                payload = parse_spdx3_file(sbom_file)
                root_pkg = get_spdx3_root_package(payload)
                if root_pkg:
                    old_purl = root_pkg.package_url
                    if old_purl != config.component_purl:
                        root_pkg.package_url = config.component_purl
                        audit_trail.record_component_purl_override(config.component_purl, old_purl)
                        write_spdx3_file(payload, sbom_file)
                else:
                    logger.warning("SPDX 3 SBOM has no root package - cannot set PURL override")
            else:
                # SPDX 2.x - apply PURL override to external references
                packages = original_json.get("packages", [])
                if packages:
                    main_package = packages[0]
                    external_refs = main_package.get("externalRefs", [])

                    # Find existing PURL reference
                    existing_purl_ref = None
                    existing_purl_idx = None
                    for idx, ref in enumerate(external_refs):
                        if ref.get("referenceType") == "purl":
                            existing_purl_ref = ref
                            existing_purl_idx = idx
                            break

                    old_purl = None
                    if existing_purl_ref:
                        old_purl = existing_purl_ref.get("referenceLocator", "unknown")
                        if old_purl != config.component_purl:
                            external_refs[existing_purl_idx]["referenceLocator"] = config.component_purl
                    else:
                        # Add new PURL reference
                        purl_category = "PACKAGE-MANAGER"
                        if config.component_purl.startswith("pkg:docker/") or config.component_purl.startswith(
                            "pkg:oci/"
                        ):
                            purl_category = "OTHER"
                        new_purl_ref = {
                            "referenceCategory": purl_category,
                            "referenceType": "purl",
                            "referenceLocator": config.component_purl,
                        }
                        external_refs.append(new_purl_ref)
                        main_package["externalRefs"] = external_refs

                    # Record to audit trail
                    audit_trail.record_component_purl_override(config.component_purl, old_purl)

                    with Path(sbom_file).open("w") as f:
                        json.dump(original_json, f, indent=2)
                else:
                    logger.warning("SPDX SBOM has no packages - cannot set PURL override")

    except Exception as e:
        logger.warning(f"Failed to apply component PURL override: {e}")
        # Don't fail the entire process for PURL override issues


# =============================================================================
# Click CLI
# =============================================================================


def _make_bool_envvar_callback(envvar: str, default: bool):
    """
    Create a callback for boolean flags with environment variable fallback.

    Click's boolean flags (--flag/--no-flag) don't automatically convert
    environment variable strings like "true"/"false" to booleans. This
    callback factory creates a callback that properly handles string env vars.

    Args:
        envvar: Environment variable name to check
        default: Default value if neither CLI nor env var is provided

    Returns:
        Callback function for Click option
    """

    def callback(ctx: click.Context, param: click.Parameter, value: Optional[bool]) -> bool:
        # Check if the flag was explicitly provided on command line
        # by looking at the source of the value
        if ctx.get_parameter_source(param.name) == click.core.ParameterSource.COMMANDLINE:
            return value

        # Check environment variable with string-to-bool conversion
        env_value = os.getenv(envvar)
        if env_value is not None:
            return evaluate_boolean(env_value)

        # Fall back to default
        return default

    return callback


def _validate_sbom_format(ctx: click.Context, param: click.Parameter, value: Optional[str]) -> Optional[str]:
    """Validate and normalize SBOM format value."""
    if value is None:
        return None
    value_lower = value.lower()
    if value_lower not in VALID_SBOM_FORMATS:
        valid_formats_str = "', '".join(VALID_SBOM_FORMATS)
        raise click.BadParameter(f"Invalid format '{value}'. Must be one of: '{valid_formats_str}'.")
    return value_lower


def _parse_upload_destinations_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[tuple[str, ...]]
) -> Optional[list[str]]:
    """Parse upload destinations from CLI (multiple values) or fall back to env var."""
    if value:
        # CLI provided values as tuple from multiple=True
        return list(value)

    # Fall back to environment variable (comma-separated)
    env_value = os.getenv("UPLOAD_DESTINATIONS")
    if env_value:
        return _parse_upload_destinations(env_value)

    return None


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--token",
    envvar="TOKEN",
    help="sbomify API token (required for upload/augment).",
)
@click.option(
    "--component-id",
    envvar="COMPONENT_ID",
    help="sbomify component ID (required for upload/augment).",
)
@click.option(
    "--sbom-file",
    envvar="SBOM_FILE",
    type=click.Path(exists=False),
    help="Path to existing SBOM file to process.",
)
@click.option(
    "--docker-image",
    envvar="DOCKER_IMAGE",
    help="Docker image to generate SBOM from (e.g., nginx:latest).",
)
@click.option(
    "--lock-file",
    envvar="LOCK_FILE",
    type=click.Path(exists=False),
    help="Path to lock file (requirements.txt, Cargo.lock, etc.).",
)
@click.option(
    "-o",
    "--output-file",
    envvar="OUTPUT_FILE",
    default="sbom_output.json",
    show_default=True,
    help="Output path for the generated SBOM.",
)
@click.option(
    "--upload/--no-upload",
    default=True,
    show_default=True,
    callback=_make_bool_envvar_callback("UPLOAD", True),
    is_eager=True,
    help="Upload SBOM to configured destinations. [env: UPLOAD]",
)
@click.option(
    "--upload-destination",
    "upload_destinations",
    multiple=True,
    type=click.Choice(sorted(VALID_DESTINATIONS), case_sensitive=False),
    callback=_parse_upload_destinations_callback,
    help="Upload destination (can be specified multiple times). [env: UPLOAD_DESTINATIONS]",
)
@click.option(
    "--augment/--no-augment",
    default=False,
    show_default=True,
    callback=_make_bool_envvar_callback("AUGMENT", False),
    is_eager=True,
    help="Augment SBOM with metadata from sbomify API. [env: AUGMENT]",
)
@click.option(
    "--enrich/--no-enrich",
    default=False,
    show_default=True,
    callback=_make_bool_envvar_callback("ENRICH", False),
    is_eager=True,
    help="Enrich SBOM with metadata from package registries. [env: ENRICH]",
)
@click.option(
    "--override-sbom-metadata/--no-override-sbom-metadata",
    default=False,
    show_default=True,
    callback=_make_bool_envvar_callback("OVERRIDE_SBOM_METADATA", False),
    is_eager=True,
    help="Override existing SBOM metadata with values from augmentation. [env: OVERRIDE_SBOM_METADATA]",
)
@click.option(
    "--component-version",
    envvar="COMPONENT_VERSION",
    help="Override the component version in the SBOM.",
)
@click.option(
    "--component-name",
    envvar="COMPONENT_NAME",
    help="Override the component name in the SBOM.",
)
@click.option(
    "--component-purl",
    envvar="COMPONENT_PURL",
    help="Add or override the component PURL in the SBOM.",
)
@click.option(
    "--product-release",
    "product_releases",  # Map to plural name for internal consistency
    envvar="PRODUCT_RELEASE",
    help="Tag SBOM with product releases (JSON array: '[\"product_id:v1.0.0\"]').",
)
@click.option(
    "--api-base-url",
    envvar="API_BASE_URL",
    default=SBOMIFY_PRODUCTION_API,
    show_default=True,
    help="sbomify API base URL (for self-hosted instances).",
)
@click.option(
    "-f",
    "--sbom-format",
    envvar="SBOM_FORMAT",
    type=click.Choice(["cyclonedx", "spdx"], case_sensitive=False),
    default="cyclonedx",
    show_default=True,
    callback=_validate_sbom_format,
    help="Output SBOM format.",
)
@click.option(
    "--spec-version",
    envvar="SPEC_VERSION",
    default=None,
    help="Override the spec version for SBOM generation (e.g., '1.6', '2.3', '3.0.1').",
)
@click.option(
    "--telemetry/--no-telemetry",
    envvar="TELEMETRY",
    default=True,
    show_default=True,
    help="Enable/disable error telemetry (Sentry).",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose/debug logging.",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress non-essential output.",
)
@click.version_option(version=SBOMIFY_VERSION, prog_name="sbomify Action")
@click.pass_context
def cli(
    ctx: click.Context,
    token: Optional[str],
    component_id: Optional[str],
    sbom_file: Optional[str],
    docker_image: Optional[str],
    lock_file: Optional[str],
    output_file: str,
    upload: bool,
    upload_destinations: Optional[list[str]],
    augment: bool,
    enrich: bool,
    override_sbom_metadata: bool,
    component_version: Optional[str],
    component_name: Optional[str],
    component_purl: Optional[str],
    product_releases: Optional[str],
    api_base_url: str,
    sbom_format: str,
    spec_version: Optional[str],
    telemetry: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Generate, augment, enrich, and manage SBOMs in your CI/CD pipeline.

    Provide one of: --sbom-file, --lock-file, or --docker-image as input.

    \b
    Commands:
      init    Interactive wizard to create sbomify.json configuration

    \b
    Examples:
      # Generate SBOM from lock file
      sbomify-action --lock-file requirements.txt --enrich --no-upload

      # Process existing SBOM and upload to sbomify
      sbomify-action --sbom-file sbom.json --token <your-token> --component-id abc123

      # Generate from Docker image with SPDX format
      sbomify-action --docker-image nginx:latest -f spdx -o sbom.spdx.json

      # Create sbomify.json configuration interactively
      sbomify-action init
    """
    # If a subcommand was invoked, don't run the default pipeline
    if ctx.invoked_subcommand is not None:
        return

    # Show help with banner if no input source is provided
    if not any([sbom_file, docker_image, lock_file]):
        # Check if additional packages are configured — user likely forgot --lock-file none
        from ..additional_packages import has_additional_packages_configured

        if has_additional_packages_configured():
            print_banner()
            logger.error(
                "Additional packages are configured but no input source is provided. "
                "Use '--lock-file none' to create an SBOM from additional packages only."
            )
            ctx.exit(1)
        print_banner()
        click.echo(ctx.get_help())
        ctx.exit(0)

    # Configure logging level
    if verbose and quiet:
        raise click.UsageError("Cannot use both --verbose and --quiet")

    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    elif quiet:
        logger.setLevel(logging.WARNING)

    # Reset audit trail for this run
    reset_audit_trail()

    print_banner()

    # Setup dependencies
    try:
        setup_dependencies()
    except SBOMGenerationError as e:
        logger.error(f"Dependency setup failed: {e}")
        sys.exit(1)

    # Initialize Sentry (respecting telemetry flag)
    if telemetry:
        initialize_sentry()
    else:
        logger.debug("Telemetry disabled via --no-telemetry flag")

    # Build configuration from CLI arguments
    config = build_config(
        token=token,
        component_id=component_id,
        sbom_file=sbom_file,
        docker_image=docker_image,
        lock_file=lock_file,
        output_file=output_file,
        upload=upload,
        upload_destinations=upload_destinations,
        augment=augment,
        enrich=enrich,
        override_sbom_metadata=override_sbom_metadata,
        component_version=component_version,
        component_name=component_name,
        component_purl=component_purl,
        product_releases=product_releases,
        api_base_url=api_base_url,
        sbom_format=sbom_format,
        spec_version=spec_version,
    )

    # Run the pipeline
    run_pipeline(config)


@cli.command("yocto")
@click.argument("sbom_input", type=click.Path(exists=True))
@click.option(
    "--release",
    required=True,
    help="Product release in product_id:version format.",
)
@click.option("--component-id", default=None, help="Component ID for SPDX 3 single-file upload.")
@click.option("--augment/--no-augment", default=False, help="Run augmentation per SBOM.")
@click.option("--enrich/--no-enrich", default=False, help="Run enrichment per SBOM.")
@click.option("--dry-run", is_flag=True, default=False, help="Show what would happen without API calls.")
@click.option(
    "--visibility",
    type=click.Choice(["public", "private", "gated"], case_sensitive=False),
    default=None,
    help="Set visibility for newly created components.",
)
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
@click.pass_context
def yocto_cmd(
    ctx: click.Context,
    sbom_input: str,
    release: str,
    component_id: str | None,
    augment: bool,
    enrich: bool,
    dry_run: bool,
    visibility: str | None,
    verbose: bool,
) -> None:
    """Process Yocto/OpenEmbedded SPDX SBOMs.

    \b
    Supports two input modes:

    \b
    1. SPDX 2.2 archive (.spdx.tar.zst or .tar.gz) — extracts per-package
       SBOMs, creates components, uploads, and tags with a release.

    \b
    2. SPDX 3 single JSON-LD file (Yocto 5.0+) — uploads the entire file
       as one SBOM to the component specified by --component-id.

    \b
    SBOM_INPUT is a Yocto SPDX archive (.spdx.tar.zst/.tar.gz) or a single SPDX 3 JSON-LD file.

    \b
    Examples:
      sbomify-action --token $TOKEN yocto build/deploy/images/image.spdx.tar.zst \\
        --release "product-id:1.0.0"

    \b
      sbomify-action --token $TOKEN yocto image.spdx.json \\
        --release "product-id:1.0.0" --component-id "comp-abc123"
    """
    # Enable debug logging if requested either on this command or the root CLI group
    effective_verbose = verbose or (ctx.parent and ctx.parent.params.get("verbose"))
    if effective_verbose:
        import logging

        logging.getLogger("sbomify_action").setLevel(logging.DEBUG)

    # Get token from parent CLI group (--token on the root command or TOKEN env var)
    yocto_token = ctx.parent.params.get("token") if ctx.parent else None
    if not yocto_token:
        # Also check env var directly as fallback
        yocto_token = os.getenv("TOKEN")
    if not yocto_token:
        raise click.UsageError("Missing required option '--token' (provide via root command or TOKEN env var).")

    # Get api-base-url from parent CLI group (--api-base-url on the root command or API_BASE_URL env var)
    api_base_url = (ctx.parent.params.get("api_base_url") if ctx.parent else None) or SBOMIFY_PRODUCTION_API

    # Parse release format
    if ":" not in release:
        raise click.BadParameter(
            "Must be in product_id:version format (e.g., 'my-product:1.0.0').", param_hint="--release"
        )

    product_id, release_version = release.split(":", 1)
    if not product_id or not release_version:
        raise click.BadParameter("Both product_id and version must be non-empty.", param_hint="--release")

    from sbomify_action._yocto.models import YoctoConfig
    from sbomify_action._yocto.pipeline import run_yocto_pipeline

    config = YoctoConfig(
        input_path=sbom_input,
        token=yocto_token,
        product_id=product_id,
        release_version=release_version,
        api_base_url=api_base_url.rstrip("/"),
        augment=augment,
        enrich=enrich,
        dry_run=dry_run,
        component_id=component_id,
        visibility=visibility,
    )

    result = run_yocto_pipeline(config)

    if result.has_errors:
        sys.exit(1)


@cli.command("init")
@click.option(
    "-o",
    "--output",
    default="sbomify.json",
    show_default=True,
    help="Output path for the configuration file.",
)
def init_cmd(output: str) -> None:
    """Interactive wizard to create sbomify.json configuration.

    This wizard helps you create a sbomify.json file that provides metadata
    for SBOM augmentation. All fields are optional.

    \b
    The configuration includes:
      - Organization info (supplier, manufacturer)
      - Authors
      - Licenses (SPDX identifiers)
      - Security contact (CRA compliance)
      - Lifecycle phase and dates
      - VCS overrides (for self-hosted git servers)
    """
    from sbomify_action.cli.wizard import run_wizard

    sys.exit(run_wizard(output))


def main() -> None:
    """Main entry point for the sbomify action.

    This function provides backward compatibility with environment variable-based
    configuration while also supporting the new CLI interface.

    When called without arguments, it will use environment variables for configuration.
    When called with CLI arguments, those take precedence over environment variables.
    """
    cli(standalone_mode=True)


if __name__ == "__main__":
    main()
