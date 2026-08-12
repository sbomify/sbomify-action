import json
import logging
import os
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, TypeVar, cast

if TYPE_CHECKING:
    import io

    from sbomify_action._processors import AggregateResult

import click
import sentry_sdk

# Add cyclonedx imports for proper SBOM handling
from cyclonedx.model.bom import Bom

from .. import format_display_name
from .._upload import VALID_BOM_TYPES, VALID_DESTINATIONS
from ..additional_packages import inject_additional_packages
from ..augmentation import augment_sbom_from_file
from ..console import (
    get_audit_trail,
    gha_group,
    gha_notice,
    gha_warning,
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
    DuplicateArtifactError,
    FileProcessingError,
    OIDCError,
    SBOMGenerationError,
    SBOMValidationError,
    ToolNotAvailableError,
)
from ..generation import (
    ALL_LOCK_FILES,
    GenerationResult,
    SBOMFormat,
    generate_sbom,
    process_lock_file,
)
from ..logging_config import logger
from ..release_version import (
    names_another_package,
    normalize_release_version,
    tag_from_ci,
    version_from_release_tag,
)
from ..serialization import (
    _add_compositions_if_missing,
    _fix_purl_encoding_bugs_in_json,
    sanitize_spdx_licenses,
    serialize_cyclonedx_bom,
)
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
            return str(pyproject_data.get("project", {}).get("version", "unknown"))
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
            return str(pyproject_data.get("project", {}).get("version", "unknown"))
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

    # repr=False so any incidental f"{config}" / pytest assertion diff /
    # debug log doesn't dump the token. OIDC-minted tokens are short-lived
    # but CI log lines persist much longer.
    token: str = field(repr=False)
    component_id: str
    sbom_file: Optional[str] = None
    docker_image: Optional[str] = None
    lock_file: Optional[str] = None
    source_dir: Optional[str] = None
    output_file: str = "sbom_output.json"
    upload: bool = True
    upload_destinations: list[str] | None = None
    augment: bool = False
    enrich: bool = False
    override_sbom_metadata: bool = False
    override_name: bool = False
    component_version: Optional[str] = None
    component_version_source: Optional[str] = None
    """Where ``component_version`` came from, when it was not simply
    configured -- ``"release tag"``, or the same with a note that it was
    normalized or that the tag names another package.

    Carried rather than recorded at the point of decision because that point
    is ``build_config``, which is pure construction: it runs in tests and in
    ``--dry-run``, and an audit trail filled during config building would
    describe runs that never happened. ``run_sbom_workflow`` records it."""
    component_name: Optional[str] = None
    component_purl: Optional[str] = None
    product_releases: Optional[str | list[str]] = None
    submodule_path: Optional[str] = None
    api_base_url: str = SBOMIFY_PRODUCTION_API
    sbom_format: SBOMFormat = "cyclonedx"
    bom_type: Optional[str] = None
    spec_version: Optional[str] = None
    oidc_audience: str | None = None
    # Set to True at runtime when config.token was obtained via OIDC exchange;
    # signals that the token is short-lived (default TTL 15 min) and should be
    # re-minted before long-running post-upload work (e.g. processors).
    token_is_oidc_minted: bool = field(default=False, repr=False)

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

    @property
    def uploads_to_sbomify(self) -> bool:
        """True iff the configured upload destinations include sbomify."""
        return self.upload and self.upload_destinations is not None and "sbomify" in self.upload_destinations

    @property
    def requires_sbomify_api(self) -> bool:
        """True iff this run MUST authenticate to the sbomify API.

        Used by validate() to decide whether credentials are mandatory,
        and by run_pipeline() to decide whether to attempt OIDC exchange.
        Augmentation does NOT mandate credentials (it can fall back to
        sbomify.json + VCS providers) — see :py:attr:`will_use_sbomify_api`.
        """
        return self.uploads_to_sbomify or bool(self.product_releases)

    @property
    def will_use_sbomify_api(self) -> bool:
        """True iff this run will call the sbomify API if credentials exist.

        Superset of :py:attr:`requires_sbomify_api`: also covers augmentation,
        which uses the API opportunistically when a token is present but
        falls back to local providers otherwise. The OIDC exchange in
        run_pipeline() uses this so users who enable AUGMENT with
        ``id-token: write`` get backend metadata via trusted publishing.
        """
        return self.requires_sbomify_api or self.augment

    def validate(self) -> None:
        """
        Validate configuration settings.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Check if sbomify API access is required:
        # - Uploading to sbomify destination
        # - Managing releases (uses sbomify API)
        # Augmentation is opportunistic — handled separately at runtime.
        if self.requires_sbomify_api:
            if not self.token:
                # Allow missing token when GitHub OIDC trusted publishing is available —
                # the pipeline will exchange the OIDC JWT for a short-lived token at runtime.
                from ..oidc import is_github_oidc_available

                if not is_github_oidc_available():
                    operations = []
                    if self.uploads_to_sbomify:
                        operations.append("uploading to sbomify")
                    if self.product_releases:
                        operations.append("PRODUCT_RELEASE is set")
                    reason = " or ".join(operations)
                    raise ConfigurationError(
                        f"sbomify API token is not defined (required when {reason}). "
                        "Either set SBOMIFY_TOKEN (or TOKEN), pass --token, or in GitHub Actions "
                        "enable trusted publishing by granting `permissions: id-token: write` in "
                        "the workflow (and create an OIDC binding for the component in the "
                        "sbomify UI)."
                    )
            if not self.component_id:
                operations = []
                if self.uploads_to_sbomify:
                    operations.append("uploading to sbomify")
                if self.product_releases:
                    operations.append("PRODUCT_RELEASE is set")
                reason = " or ".join(operations)
                raise ConfigurationError(f"Component ID is not defined (required when {reason})")

        inputs = [self.sbom_file, self.lock_file, self.source_dir, self.docker_image]
        if sum(bool(x) for x in inputs) > 1:
            raise ConfigurationError("Please provide only one of: SBOM_FILE, LOCK_FILE, SOURCE_DIR, or DOCKER_IMAGE")
        if not any(inputs):
            raise ConfigurationError("Please provide one of: SBOM_FILE, LOCK_FILE, SOURCE_DIR, or DOCKER_IMAGE")
        if self.source_dir and not Path(self.source_dir).is_dir():
            raise ConfigurationError(f"SOURCE_DIR '{self.source_dir}' is not a directory")

        # Submodule mode: attach-or-backfill against the submodule's
        # component. Needs a lockfile to backfill from, and only makes
        # sense when talking to sbomify.
        if self.submodule_path:
            if not self.lock_file or self.is_additional_packages_only:
                raise ConfigurationError(
                    "SUBMODULE_PATH requires LOCK_FILE (the submodule's lockfile) so the SBOM "
                    "can be generated when no existing one is found for the pinned version."
                )
            if not self.uploads_to_sbomify:
                raise ConfigurationError(
                    "SUBMODULE_PATH requires uploading to sbomify (UPLOAD=true with the 'sbomify' "
                    "destination) — submodule mode looks up and attaches SBOMs via the sbomify API."
                )

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

        # Validate bom_type (artifact kind recorded on upload)
        if self.bom_type is not None and self.bom_type not in VALID_BOM_TYPES:
            raise ConfigurationError(
                f"Invalid BOM_TYPE: '{self.bom_type}'. Must be one of: {', '.join(VALID_BOM_TYPES)}"
            )

        # Non-SBOM artifacts (VEX/CBOM/HBOM) are authored elsewhere and uploaded verbatim; the
        # action does not synthesize them. Reject any generation source so a generated SBOM can't
        # be uploaded mislabeled as a non-SBOM artifact.
        if self.bom_type and self.bom_type != "sbom":
            # SPDX goes through a json.load/json.dump license sanitization that rewrites the
            # bytes, which would break the verbatim upload. Non-SBOM artifacts are CycloneDX.
            if self.sbom_format and self.sbom_format.lower() != "cyclonedx":
                raise ConfigurationError(
                    f"BOM_TYPE='{self.bom_type}' is only supported for CycloneDX; SBOM_FORMAT="
                    f"'{self.sbom_format}' would be re-serialized and break the verbatim upload."
                )
            # Only the sbomify backend records bom_type; other destinations re-encode the
            # payload and would ingest the artifact as a plain SBOM.
            if self.upload:
                non_sbomify = [d for d in (self.upload_destinations or []) if d != "sbomify"]
                if non_sbomify:
                    raise ConfigurationError(
                        f"BOM_TYPE='{self.bom_type}' can only be uploaded to sbomify; remove "
                        f"{', '.join(non_sbomify)} from UPLOAD_DESTINATIONS."
                    )
            # A release holds one SBOM per component and format; tagging a non-SBOM artifact
            # would either collide with the component's SBOM or wrongly occupy its slot.
            if self.product_releases:
                raise ConfigurationError(
                    f"BOM_TYPE='{self.bom_type}' cannot be tagged into a product release; remove PRODUCT_RELEASE."
                )
            has_real_sbom_file = bool(self.sbom_file and self.sbom_file.lower() != NONE_SENTINEL)
            if self.lock_file or self.docker_image or not has_real_sbom_file:
                raise ConfigurationError(
                    f"BOM_TYPE='{self.bom_type}' uploads a pre-authored artifact verbatim and cannot be "
                    "generated: provide it via SBOM_FILE (a real path), and do not set LOCK_FILE, "
                    "DOCKER_IMAGE, or SBOM_FILE=none."
                )
            # Component overrides rewrite the document, which breaks the verbatim contract.
            if self.component_name or self.component_version or self.component_purl or self.override_name:
                logger.warning(
                    f"BOM_TYPE={self.bom_type} is uploaded verbatim; ignoring "
                    "COMPONENT_NAME/COMPONENT_VERSION/COMPONENT_PURL/OVERRIDE_NAME."
                )
                self.component_name = None
                self.component_version = None
                self.component_purl = None
                self.override_name = False
            # Augmentation and enrichment rewrite the document, which also breaks
            # the verbatim contract.
            if self.augment or self.enrich:
                logger.warning(f"BOM_TYPE={self.bom_type} is uploaded verbatim; ignoring AUGMENT/ENRICH.")
                self.augment = False
                self.enrich = False

        # Validate spec_version against sbom_format.
        #
        # Only lock files and Docker images run through the generator plugins whose
        # capabilities these tuples describe, so the check is scoped to them:
        #   * additional-packages-only mode builds the document itself and can
        #     bootstrap SPDX 3.0.1 (additional_packages.create_empty_sbom)
        #   * a real SBOM_FILE never consults spec_version at all
        # Enforcing generator limits on those would reject workflows that work.
        uses_generator_plugin = not self.is_additional_packages_only and bool(self.lock_file or self.docker_image)

        if self.spec_version and uses_generator_plugin:
            from .._generation import CYCLONEDX_VERSIONS, SPDX_VERSIONS

            if self.sbom_format == "cyclonedx" and self.spec_version not in CYCLONEDX_VERSIONS:
                hint = ""
                if self.spec_version in ("1.0", "1.1"):
                    hint = " CycloneDX only added JSON in 1.2, and this tool emits JSON."
                raise ConfigurationError(
                    f"Invalid spec_version '{self.spec_version}' for CycloneDX. "
                    f"Supported: {', '.join(CYCLONEDX_VERSIONS)}.{hint}"
                )
            if self.sbom_format == "spdx" and self.spec_version not in SPDX_VERSIONS:
                hint = ""
                if self.spec_version == "3.0.1":
                    hint = (
                        " SPDX 3.0.1 cannot be generated from a lock file or Docker image --"
                        " no generator plugin emits it. Two other routes produce it:"
                        " pass an existing 3.0.1 document as SBOM_FILE, or use"
                        " additional-packages-only mode (LOCK_FILE=none or SBOM_FILE=none)."
                    )
                raise ConfigurationError(
                    f"Invalid spec_version '{self.spec_version}' for SPDX. Supported: {', '.join(SPDX_VERSIONS)}.{hint}"
                )

        # Validate product releases format
        if self.product_releases:
            try:
                # Parse JSON list format like ["product_id:v1.2.3"]
                if isinstance(self.product_releases, list):
                    product_releases_list = self.product_releases
                else:
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

                # Keep the release version and the SBOM's version in step.
                #
                # The wizard emits PRODUCT_RELEASE from the raw tag while
                # COMPONENT_VERSION is normalized inside the action, so with
                # normalization on they diverge: the SBOM says 8.21.0 and the
                # release it is attached to is called curl-8_21_0. Normalizing
                # both keeps a release and its contents describing the same
                # thing.
                #
                # Only when the version *is* the tag, on the same reasoning as
                # the component version: a deliberately-chosen release name is
                # not ours to rewrite.
                if _normalize_version_enabled():
                    tag = tag_from_ci()
                    rewritten = []
                    for release in product_releases_list:
                        product_id, version = release.split(":", 1)
                        if tag and version == tag and not names_another_package(tag, _repository_name()):
                            if normalized := normalize_release_version(version, _repository_name()):
                                if normalized != version:
                                    logger.info(f"Normalized product release {version!r} to {normalized!r}")
                                    release = f"{product_id}:{normalized}"
                        rewritten.append(release)
                    product_releases_list = rewritten

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


def _repository_name() -> Optional[str]:
    """The repository this build belongs to, for spotting a foreign tag.

    Only used to answer "does this tag name a different package", so a missing
    value means the check is skipped rather than guessed at.
    """
    for var in ("GITHUB_REPOSITORY", "CI_PROJECT_PATH", "BITBUCKET_REPO_FULL_NAME"):
        if value := os.getenv(var):
            return value.split("/")[-1]
    return None


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def _version_from_tag_enabled() -> bool:
    """Whether an unset COMPONENT_VERSION may be filled in from the release tag.

    Off by default, and that is a deliberate reversal.

    The first version of this derived the version whenever a tag-triggered
    build left COMPONENT_VERSION unset, on the reasoning that the tag is
    better than nothing. It is not always better than what is already there.
    A project whose lockfile already yields a correct root version of
    ``1.2.3`` would have had it overwritten with the literal tag ``v1.2.3``,
    rebuilding the root PURL as ``pkg:pypi/foo@v1.2.3`` -- which no registry
    or CVE feed resolves. For curl the SBOM would have claimed
    ``curl-8_21_0``.

    Silently changing the version of every existing tag-triggered user's SBOM
    is not a thing to do by default, particularly on the strength of a finding
    that was withdrawn once already for being measured against the wrong
    checkout. Opt in, and the wizard asks.
    """
    return _flag("VERSION_FROM_RELEASE_TAG")


def _normalize_version_enabled() -> bool:
    """Whether to reduce a release tag to the version a registry would know.

    Off by default. Turning ``curl-8_21_0`` into ``8.21.0`` makes it matchable
    against a CVE feed, and also rewrites what the project itself called the
    release -- which is the sort of thing that should be asked for rather than
    done quietly. The wizard offers it; this is the switch it writes.
    """
    return _flag("NORMALIZE_VERSION")


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
    override_name = evaluate_boolean(override_name_env, source="OVERRIDE_NAME") if override_name_env else False

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
    source_dir: Optional[str] = None,
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
    submodule_path: Optional[str] = None,
    api_base_url: str = SBOMIFY_PRODUCTION_API,
    sbom_format: str = "cyclonedx",
    bom_type: Optional[str] = None,
    spec_version: Optional[str] = None,
    oidc_audience: Optional[str] = None,
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

    # Where the version came from, for the audit trail. Recorded there rather
    # than here because build_config is pure construction -- it runs in tests
    # and in --dry-run, and a trail that fills up during config building would
    # describe runs that never happened.
    version_source: Optional[str] = None

    # Log component version
    if final_component_version:
        # A configured version is normally left exactly as configured. The one
        # exception is when it *is* the release tag: the wizard's generated
        # workflow computes COMPONENT_VERSION by stripping refs/tags/, so the
        # version arrives configured rather than derived and every judgement
        # about the tag would otherwise be skipped.
        #
        # Routed through the same decision as the derived path rather than
        # only normalizing, because the checks are not separable. An earlier
        # version of this called normalize_release_version directly and turned
        # `meta-v1.3.0` -- a per-package tag in dart-lang/sdk -- into a clean
        # `1.3.0` stamped on the whole repository, with no warning. Laundering
        # a foreign tag into something authoritative-looking is worse than
        # leaving it alone, which is what the foreign-tag check is for.
        #
        # Matching against the tag, rather than normalizing anything
        # tag-shaped, is what keeps a deliberate COMPONENT_VERSION safe: a
        # build labelled "my-build-42" is not a curl-8_21_0.
        if final_component_version == tag_from_ci():
            resolved, warning = version_from_release_tag(
                repo_name=_repository_name(),
                normalize=_normalize_version_enabled(),
            )
            if warning:
                logger.warning(warning)
                version_source = "release tag (names another package)"
            elif resolved and resolved != final_component_version:
                logger.info(f"Normalized the release tag {final_component_version!r} to version {resolved!r}")
                version_source = f"release tag {final_component_version!r}, normalized"
                final_component_version = resolved
            else:
                version_source = "release tag"
        logger.info(f"Using component version: {final_component_version}")
    elif _version_from_tag_enabled():
        # Nothing configured, and the user asked for the tag to fill the gap.
        # A branch build still yields nothing, because there is no released
        # version to claim and inventing one would be worse.
        derived, warning = version_from_release_tag(
            repo_name=_repository_name(),
            normalize=_normalize_version_enabled(),
        )
        if warning:
            logger.warning(warning)
        if derived:
            final_component_version = derived
            logger.info(f"Using component version {derived} from the release tag")
            tag = tag_from_ci()
            version_source = f"release tag {tag!r}, normalized" if derived != tag else "release tag"
        else:
            logger.info("No component version specified (COMPONENT_VERSION not set)")
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

    # Submodule mode: empty string (unset matrix field in the emitted
    # workflow) means disabled.
    normalized_submodule_path = submodule_path.strip() if submodule_path and submodule_path.strip() else None
    if normalized_submodule_path:
        logger.info(f"Submodule mode: {normalized_submodule_path} (attach-or-backfill)")

    # Log SBOM format
    sbom_format_lower: SBOMFormat = cast(SBOMFormat, sbom_format.lower())
    logger.info(f"SBOM format: {format_display_name(sbom_format_lower)}")

    # Only None and "" mean unset (click treats an empty env var the same way);
    # any other value must survive to Config.validate() so garbage is rejected.
    # The verbatim guards (ignoring AUGMENT/ENRICH etc.) live in validate().
    normalized_bom_type = "sbom" if bom_type is None or bom_type == "" else str(bom_type).lower()

    # Expand paths if provided (skip expansion for "none" sentinel)
    expanded_sbom_file = (
        sbom_file
        if (sbom_file and sbom_file.lower() == NONE_SENTINEL)
        else (path_expansion(sbom_file) if sbom_file else None)
    )
    expanded_lock_file = (
        lock_file
        if (lock_file and lock_file.lower() == NONE_SENTINEL)
        else (_expand_lock_file_or_substitute(lock_file) if lock_file else None)
    )
    # Expanded like the others, but by directory_expansion: path_expansion
    # tests is_file(), so a directory fails it with "Specified input file
    # 'unpacked' not found" -- the same message that made passing a directory
    # as LOCK_FILE look like a missing file. No "none" sentinel either: that
    # keyword means "build from additional packages alone", which is a
    # statement about lock files and has no reading for a directory.
    expanded_source_dir = directory_expansion(source_dir) if source_dir else None

    config = Config(
        token=token or "",
        component_id=component_id or "",
        sbom_file=expanded_sbom_file,
        docker_image=docker_image,
        lock_file=expanded_lock_file,
        source_dir=expanded_source_dir,
        output_file=output_file,
        upload=upload,
        upload_destinations=upload_destinations,
        augment=augment,
        enrich=enrich,
        override_sbom_metadata=override_sbom_metadata,
        override_name=final_override_name,
        component_version=final_component_version,
        component_version_source=version_source,
        component_name=final_component_name,
        component_purl=component_purl,
        product_releases=product_releases,
        submodule_path=normalized_submodule_path,
        api_base_url=api_base_url,
        sbom_format=sbom_format_lower,
        bom_type=normalized_bom_type,
        spec_version=spec_version,
        oidc_audience=oidc_audience,
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
        token=_resolve_token(),
        component_id=os.getenv("COMPONENT_ID"),
        sbom_file=os.getenv("SBOM_FILE"),
        docker_image=os.getenv("DOCKER_IMAGE"),
        lock_file=os.getenv("LOCK_FILE"),
        source_dir=os.getenv("SOURCE_DIR"),
        output_file=os.getenv("OUTPUT_FILE", "sbom_output.json"),
        upload=evaluate_boolean(os.getenv("UPLOAD", "True"), source="UPLOAD"),
        upload_destinations=upload_destinations,
        augment=evaluate_boolean(os.getenv("AUGMENT", "False"), source="AUGMENT"),
        enrich=evaluate_boolean(os.getenv("ENRICH", "False"), source="ENRICH"),
        override_sbom_metadata=evaluate_boolean(
            os.getenv("OVERRIDE_SBOM_METADATA", "False"), source="OVERRIDE_SBOM_METADATA"
        ),
        component_version=os.getenv("COMPONENT_VERSION"),
        component_name=os.getenv("COMPONENT_NAME"),
        component_purl=os.getenv("COMPONENT_PURL"),
        product_releases=os.getenv("PRODUCT_RELEASE"),
        submodule_path=os.getenv("SUBMODULE_PATH"),
        api_base_url=os.getenv("API_BASE_URL", SBOMIFY_PRODUCTION_API),
        sbom_format=os.getenv("SBOM_FORMAT", "cyclonedx"),
        bom_type=os.getenv("BOM_TYPE"),
        oidc_audience=os.getenv("OIDC_AUDIENCE"),
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

    Can be disabled by setting TELEMETRY to any recognised false value
    (``false``, ``0``, ``no``, ``off``, ``disabled``, …).

    The CLI already gates this call on ``--telemetry/--no-telemetry``,
    which resolves TELEMETRY itself, so this re-check only matters when
    the function is called directly. It shares the one boolean
    vocabulary either way — previously it accepted ``disabled`` while
    the option layer rejected the same string outright.
    """
    # Allow users to opt-out of telemetry
    if not evaluate_boolean(os.getenv("TELEMETRY", "true"), source="TELEMETRY"):
        logger.debug("Sentry telemetry disabled via TELEMETRY environment variable")
        return

    sentry_dsn = os.getenv("SENTRY_DSN", "https://84e8d6d0a7d0872a4bba8add571a554c@sentry.vikpire.com/4")

    def before_send(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any] | None:
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
                exc_value,
                (
                    SBOMValidationError,
                    ConfigurationError,
                    DockerImageNotFoundError,
                    ToolNotAvailableError,
                    # OIDC errors are user/setup issues (missing binding, wrong audience,
                    # rate limit) — not actionable Sentry events.
                    OIDCError,
                    # "This version is already published" — the normal outcome of
                    # re-running a workflow on the same commit, not a defect.
                    DuplicateArtifactError,
                ),
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
        before_send=before_send,  # type: ignore[arg-type]
        release=f"sbomify-action@{SBOMIFY_VERSION}",
        # Don't capture frame locals — they can hold OIDC JWTs / Bearer tokens
        # if an unexpected exception fires inside sbomify_action.oidc.
        include_local_variables=False,
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


def _in_github_actions() -> bool:
    """Return True when running inside GitHub Actions."""
    value = os.environ.get("GITHUB_ACTIONS")
    return value is not None and value.lower() in {"true", "1"}


def _resolve_token(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the sbomify API token, in precedence order.

    1. ``explicit`` (eg. ``--token`` on the CLI).
    2. ``$SBOMIFY_TOKEN``.
    3. ``$TOKEN`` (legacy / matches the GitHub Action's env input).

    Returns ``None`` if none of the above produced a non-empty value.
    The wizard's auth screen treats ``None`` as "prompt the user".
    """
    if explicit:
        return explicit
    return os.environ.get("SBOMIFY_TOKEN") or os.environ.get("TOKEN") or None


def _github_workspace() -> Path:
    """Return the GitHub Actions workspace path as an absolute, resolved Path."""
    raw = os.environ.get("GITHUB_WORKSPACE") or "/github/workspace"
    workspace = Path(raw)
    return workspace.resolve()


def resolve_working_dir(working_dir: str) -> Path:
    """Resolve a working directory path for use with os.chdir().

    Supports both relative and absolute paths. When running inside GitHub Actions
    (detected via the GITHUB_ACTIONS env var), the resolved path is validated to
    be under the workspace to prevent escaping the mounted repository.

    Args:
        working_dir: The working directory path to resolve.

    Returns:
        Resolved absolute Path.

    Raises:
        click.BadParameter: If the path is outside the allowed prefix or doesn't exist.
    """
    # Guard against missing value (e.g., --working-dir --lock-file ...)
    if working_dir.startswith("-"):
        raise click.BadParameter(
            f"Invalid working directory '{working_dir}' — this looks like a CLI flag. "
            "Did you forget to provide a directory path?"
        )

    path = Path(working_dir)
    in_gha = _in_github_actions()
    workspace = _github_workspace()

    try:
        if path.is_absolute():
            resolved = path.resolve()
        else:
            # Relative path — resolve against workspace if in GHA,
            # otherwise against cwd (for local/non-GHA use)
            base = workspace if in_gha else Path.cwd()
            resolved = (base / path).resolve()
    except (OSError, RuntimeError) as exc:
        raise click.BadParameter(f"Unable to resolve working directory '{working_dir}': {exc}") from exc

    # In GitHub Actions runtime, enforce the resolved path is under the workspace
    if in_gha and not resolved.is_relative_to(workspace):
        raise click.BadParameter(
            f"Working directory '{resolved}' must be under {workspace} when running in GitHub Actions."
        )

    if not resolved.is_dir():
        raise click.BadParameter(f"Working directory '{resolved}' does not exist or is not a directory.")

    return resolved


def _format_search_locations(*candidates: Path) -> str:
    """Render the locations a lookup tried, de-duplicated, in order.

    Inside the action's container the working directory *is*
    ``/github/workspace``, so "relative to cwd" and "relative to the
    workspace" resolve to the same path. The old message listed both
    unconditionally and produced

        Searched in: '/github/workspace/unpacked', '/github/workspace/unpacked'

    -- which reads like a bug in the tool and, worse, omitted the bare
    relative path that is actually tried first. Report each distinct
    location exactly once.
    """
    seen: list[str] = []
    for candidate in candidates:
        rendered = str(candidate)
        if rendered not in seen:
            seen.append(rendered)
    return ", ".join(f"'{location}'" for location in seen)


#: Where a GitHub Action mounts the repository. path_expansion searches here
#: as well as the working directory, because the two are not the same inside
#: an action, and anything else that searches for an input has to look in the
#: same places or it will refuse a file the caller can plainly see.
GITHUB_WORKSPACE = "/github/workspace"


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
    workspace_relative_path = Path(GITHUB_WORKSPACE) / path

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
            f"Specified input file '{path}' not found. "
            f"Searched in: {_format_search_locations(Path(path), relative_path, workspace_relative_path)}"
        )


def _expand_lock_file_or_substitute(path: str) -> str:
    """Resolve LOCK_FILE, or the ecosystem's lock file that is actually there.

    LOCK_FILE names a file, and the file a project uses changes: a repository
    moves from npm to pnpm, from poetry to uv, from Pipenv to either. The
    workflow pinning the old name then fails outright with "Specified input
    file not found", which is a true statement about a name and a useless one
    about the project -- the dependencies are right there in the file next to
    it.

    So when the named file is gone and exactly one lock file for the same
    ecosystem is present, that one is used and the substitution is announced
    loudly. Silence would be worse than the error: the SBOM would come from an
    input the caller never asked for and nothing would say so.

    Deliberately only when it is unambiguous. A directory holding both
    pnpm-lock.yaml and yarn.lock has no obvious winner, and guessing between
    them is how a document ends up describing the wrong dependency tree; that
    case keeps the original error, which now lists what it found.
    """
    from .._generation.registry import records_a_resolution
    from .._generation.utils import DOTNET_PROJECT_SUFFIXES, get_lock_file_ecosystem

    try:
        return path_expansion(path)
    except FileProcessingError as missing:
        original = missing

    named = Path(path)
    ecosystem = get_lock_file_ecosystem(named.name)
    if not ecosystem:
        raise original

    # The same three places path_expansion searches, which is what the
    # sentence above used to claim while checking only two of them. The third
    # is /github/workspace, and omitting it meant a substitution could refuse
    # inside a GitHub Action whose working directory is somewhere else --
    # precisely where LOCK_FILE is most likely to be pinned and stale.
    #
    # A relative path keeps its own parent. `frontend/package-lock.json` names
    # the frontend project, and path_expansion resolves it against each root
    # *including* that subdirectory -- so widening the search to the roots
    # themselves would let a missing nested lock file be replaced by an
    # unrelated one at the top of the repository, and the SBOM would quietly
    # describe a different project. That is the failure this whole exercise
    # keeps finding, and it would have been introduced here.
    #
    # An absolute path has no such parent to preserve, so it keeps the roots
    # as a fallback.
    #
    # Resolved, because the same file reached as "./x" and as an absolute path
    # is one candidate and not two; counting it twice made every substitution
    # look ambiguous and refuse itself.
    searched: tuple[Path, ...]
    if named.is_absolute():
        searched = (named.parent, Path.cwd(), Path(GITHUB_WORKSPACE))
    else:
        searched = (Path.cwd() / named.parent, Path(GITHUB_WORKSPACE) / named.parent)
    directories = {d.resolve() for d in searched if d.is_dir()}

    # .NET project files are matched by suffix rather than by name, so a scan
    # over fixed names alone could never substitute one -- a stale
    # packages.lock.json failed even with exactly one .csproj beside it.
    def _same_ecosystem(path: Path) -> bool:
        if path.name == named.name:
            return False
        if get_lock_file_ecosystem(path.name) == ecosystem:
            return True
        return path.suffix in DOTNET_PROJECT_SUFFIXES and ecosystem == "dotnet"

    # The candidate path is kept as found, not resolved. Dereferencing changes
    # both the basename and the parent: a project-local `uv.lock ->
    # shared/base.lock` would be handed to the generator as `shared/base.lock`,
    # which scans the wrong directory and carries a name nothing recognises.
    # The directories above are already resolved, which is what deduplicates
    # the search roots.
    siblings = sorted(
        {
            candidate
            for directory in directories
            for candidate in list(directory.iterdir())
            if candidate.is_file() and _same_ecosystem(candidate)
        }
    )

    # Prefer a candidate that records a resolution over one that only
    # constrains it, and ask the same question the disclosure asks rather than
    # a second approximation of it.
    #
    # Membership of UNRESOLVED_MANIFESTS was standing in for this, which made
    # it answer two questions again: it says whether a *name* is a manifest,
    # while what matters here is whether a *file* records anything. Those came
    # apart the moment requirements.txt started being judged by its contents --
    # a pinned one records a resolution and an unpinned one does not, and they
    # share a filename.
    locks = [s for s in siblings if records_a_resolution(str(s))]
    manifests = [s for s in siblings if not records_a_resolution(str(s))]
    candidates = locks or manifests

    if len(candidates) != 1:
        if candidates:
            logger.error(
                f"LOCK_FILE names '{named.name}', which is not here, and there is more than one "
                f"{ecosystem} input to choose from: {', '.join(c.name for c in candidates)}. "
                f"Set LOCK_FILE to the one you want rather than have this guess."
            )
        raise original

    substitute = candidates[0]
    downgrade = (
        "\n  It is a manifest rather than a lock file, so the versions in this\n"
        "  SBOM will be resolved now rather than read -- see the notice below.\n"
        if not locks
        else ""
    )
    logger.warning(
        "\n"
        "  ┌───────────────────────────────────────────────────────────────┐\n"
        "  │  USING A DIFFERENT INPUT THAN THE ONE YOU CONFIGURED          │\n"
        "  └───────────────────────────────────────────────────────────────┘\n"
        f"  LOCK_FILE names '{named.name}', which is not in this repository.\n"
        f"  '{substitute.name}' is, and it describes the same ecosystem\n"
        f"  ({ecosystem}), so that is what this SBOM was built from.\n"
        f"{downgrade}"
        "\n"
        "  This usually means the project changed package manager. Update\n"
        f"  LOCK_FILE to '{substitute.name}' to make the choice explicit, or\n"
        "  set it to the file you actually want."
    )
    return str(substitute)


def directory_expansion(path: str) -> str:
    """Resolve a directory the same way path_expansion resolves a file.

    Separate from path_expansion because that one tests ``is_file()``, so a
    directory fails it with "Specified input file ... not found" -- accurate
    only about the name it was given, and the message that made an early
    attempt at directory scanning look like a missing file.

    The three-location search is the part worth sharing: inside the action's
    container a relative path resolves against the working directory or
    against /github/workspace, and which one applies depends on how the
    workflow was written.
    """
    if path.startswith("-"):
        raise FileProcessingError(
            f"Invalid directory path '{path}' - this looks like a CLI flag. "
            f"Did you forget to specify a directory? "
            f"Example: --source-dir dist or set the SOURCE_DIR environment variable."
        )

    current_dir = Path.cwd()
    relative_path = current_dir / path
    workspace_relative_path = Path(GITHUB_WORKSPACE) / path

    logger.debug(f"Searching for directory '{path}'...")
    for candidate in (Path(path), relative_path, workspace_relative_path):
        if candidate.is_dir():
            logger.info(f"Using source directory '{candidate}'.")
            return str(candidate if candidate.is_absolute() else current_dir / candidate)

    raise FileProcessingError(
        f"Specified source directory '{path}' not found. "
        f"Searched in: {_format_search_locations(Path(path), relative_path, workspace_relative_path)}"
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


#: The one boolean vocabulary every env var and flag in this CLI shares.
#: It is Click's own ``BOOL`` set (so ``--telemetry``'s long-standing
#: behaviour is preserved) plus the spellings this project already
#: accepted (``yeah``) or documented elsewhere (``enabled``/``disabled``,
#: which ``initialize_sentry`` describes as valid telemetry opt-outs).
_TRUE_VALUES = frozenset({"1", "true", "t", "yes", "y", "yeah", "on", "enable", "enabled"})
_FALSE_VALUES = frozenset({"0", "false", "f", "no", "n", "off", "", "disable", "disabled"})


def evaluate_boolean(value: str, source: str = "value") -> bool:
    """
    Evaluate a string as a boolean, rejecting anything ambiguous.

    Surrounding whitespace is stripped and case is ignored, so values
    that arrive with a trailing newline from a YAML block scalar, a
    ``.env`` file, or ``$(command)`` substitution behave as written.

    Unrecognised input raises rather than evaluating to ``False``. That
    matters most for ``UPLOAD``, which defaults to *true*: treating a
    typo as "off" silently skipped the upload while the run still
    reported success, so the user believed they had published when they
    had not. A typo must never be indistinguishable from a deliberate
    opt-out.

    Args:
        value: String value to evaluate
        source: What produced the value (an env var or option name),
            used to make the error actionable.

    Returns:
        Boolean result

    Raises:
        ConfigurationError: If the value is not a recognised boolean.
    """
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    accepted = ", ".join(sorted(_TRUE_VALUES | (_FALSE_VALUES - {""})))
    raise ConfigurationError(f"Invalid boolean for {source}: {value!r}. Accepted values: {accepted}.")


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
        with Path(file_path).open("r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except UnicodeDecodeError:
        # Undecodable (non-UTF-8) bytes fail as a clean validation error rather
        # than crashing the pipeline past step 1's SBOMValidationError handling.
        raise SBOMValidationError("SBOM file is not valid UTF-8")
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


def _detect_external_vex_format(file_path: str) -> Optional[str]:
    """Detect a non-CycloneDX VEX format from content markers.

    Returns "openvex" (@context under https://openvex.dev/ns — prefix-matched,
    v0.0.1 documents lack the version suffix; @context may be a single string or
    a JSON-LD list, in which case any entry with the namespace prefix counts) or
    "csaf" (document.category == "csaf_vex"), else None. Invalid JSON returns
    None so validate_sbom() can report it with its usual error message.
    """
    try:
        with Path(file_path).open("r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        # Non-UTF-8 / undecodable bytes fall back to None so validate_sbom()
        # reports the problem with its usual error message instead of crashing.
        return None
    if not isinstance(data, dict):
        return None
    # @context is a single IRI string or a JSON-LD list of them.
    context = data.get("@context")
    contexts = context if isinstance(context, list) else [context]
    if any(isinstance(c, str) and c.startswith("https://openvex.dev/ns") for c in contexts):
        return "openvex"
    document = data.get("document")
    if isinstance(document, dict) and document.get("category") == "csaf_vex":
        return "csaf"
    return None


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
        with Path(file_path).open("r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except UnicodeDecodeError:
        # Undecodable (non-UTF-8) bytes fail as a clean validation error rather
        # than crashing the pipeline past step 1's SBOMValidationError handling.
        raise SBOMValidationError("SBOM file is not valid UTF-8")
    except FileNotFoundError:
        raise SBOMValidationError(f"SBOM file not found: {file_path}")

    # Detect artifact type without logging
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    elif data.get("spdxVersion") is not None or is_spdx3(data):
        return "spdx"
    else:
        raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")


def load_sbom_from_file(file_path: str) -> tuple[str, dict[str, Any], object]:
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
            parsed_object = Bom.from_json(sbom_json)  # type: ignore[attr-defined]
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


def _write_final_output(src_path: str, dst_path: str, bom_type: Optional[str]) -> None:
    """Write the final artifact to ``dst_path``.

    Non-SBOM artifacts (VEX, CBOM, ...) are copied byte-for-byte so the upload matches the
    authored file exactly (a text round-trip could normalize newlines). SBOMs go through the
    text path so the CycloneDX fixups in :func:`_finalize_output_content` apply.
    """
    if bom_type and bom_type != "sbom":
        # When OUTPUT_FILE resolves to the final step file, it is already in place;
        # copyfile would raise SameFileError, so treat copy-to-self as a no-op.
        if os.path.realpath(src_path) != os.path.realpath(dst_path):
            shutil.copyfile(src_path, dst_path)
        return
    # Read, fix any PURL encoding bugs, and write final SBOM
    # This fixes double-encoded %40%40 or double @@ issues
    # Note: We preserve canonical %40 encoding per PURL spec
    with open(src_path, "r", encoding="utf-8") as f:
        content = f.read()
    content = _finalize_output_content(content, bom_type)
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(content)


def _finalize_output_content(content: str, bom_type: Optional[str]) -> str:
    """Return the content to upload after format-specific output fixes.

    CycloneDX SBOMs get PURL-encoding repairs and a compositions completeness
    indicator. For non-SBOM CycloneDX artifacts (VEX, CBOM, ...) this helper
    skips those SBOM-specific fixups; the wider verbatim contract (no
    augment/enrich, no overrides, byte-copy on write) is enforced by Config
    validation and the finalize step. SPDX and other content pass through
    unchanged.
    """
    is_cyclonedx = '"bomFormat"' in content and '"CycloneDX"' in content
    if not is_cyclonedx:
        return content
    if bom_type and bom_type != "sbom":
        return content
    content = _fix_purl_encoding_bugs_in_json(content)
    content = _add_compositions_if_missing(content)
    return content


def _finalize_post_upload(results: "AggregateResult") -> None:
    """Log the outcome of each processor that ran and exit non-zero if any failed.

    A failed processor (e.g. a 403 when the OIDC/CI token cuts a release) must
    surface as a non-zero exit, not be swallowed as a green run. Skipped
    processors don't run here, so they aren't logged and aren't failures.
    """
    for proc_result in results.enabled_processors:
        if proc_result.success:
            logger.info(
                f"Processor '{proc_result.processor_name}' completed: {proc_result.processed_items} item(s) processed"
            )
        else:
            logger.error(f"Processor '{proc_result.processor_name}' failed: {proc_result.error_message}")

    if results.any_failures:
        _log_step_end(6, success=False)
        sys.exit(1)
    _log_step_end(6)


def _find_existing_submodule_sbom(config: "Config", sbom_format: str) -> Optional[str]:
    """ID of the submodule component's SBOM at the pin-derived version, or None.

    ``config.component_version`` must already hold the pin-derived version
    (set by :func:`_prepare_submodule_mode`). Soft-fails to None on API
    errors so callers fall back to generation rather than aborting.
    """
    from ..sbomify_api import SbomifyApiClient

    if not (config.token and config.component_id and config.component_version):
        return None
    client = SbomifyApiClient(config.api_base_url, config.token)
    try:
        return client.find_component_sbom(config.component_id, config.component_version, sbom_format)
    except APIError as e:
        logger.warning(f"Could not look up an existing submodule SBOM: {e}")
        return None


def _prepare_submodule_mode(config: "Config") -> Optional[str]:
    """Resolve the submodule pin; return an existing SBOM's ID if one matches.

    Side effect: overrides ``config.component_version`` with the
    pin-derived version (exact version tag at the pinned commit, else the
    short SHA) so that a backfill uploads under the version the
    submodule's own CI would have published.

    Returns the sbom_id to attach (skip generation/upload entirely), or
    None to proceed with the normal pipeline as a backfill.
    """
    from ..submodule import resolve_submodule_pin

    assert config.submodule_path is not None  # guarded by the caller
    pin = resolve_submodule_pin(Path.cwd(), config.submodule_path)
    if pin is None:
        logger.error(
            f"SUBMODULE_PATH '{config.submodule_path}' is not a git submodule or vendored repo "
            "in this checkout: the parent tree has no gitlink at that path and the directory "
            "has no embedded .git. Check the path, and ensure the workflow checks out the "
            "parent repository (the pin is read from the parent tree, not the submodule)."
        )
        sys.exit(1)

    source_desc = "version tag" if pin.version_source == "tag" else "short commit SHA"
    logger.info(f"Submodule '{pin.path}' pinned at {pin.sha} → version '{pin.version}' ({source_desc})")
    if config.component_version and config.component_version != pin.version:
        logger.info(f"Overriding COMPONENT_VERSION '{config.component_version}' with the pin-derived '{pin.version}'")
    config.component_version = pin.version

    existing = _find_existing_submodule_sbom(config, config.sbom_format)
    if existing:
        logger.info(
            f"Component {config.component_id} already has a {format_display_name(config.sbom_format)} "
            f"SBOM at version '{pin.version}' (id: {existing})"
        )
        return existing
    logger.info(
        f"No existing {format_display_name(config.sbom_format)} SBOM for component "
        f"{config.component_id} at version '{pin.version}' — generating one (backfill)."
    )
    return None


def _run_post_upload_processing(config: "Config", sbom_id: str) -> None:
    """Step 6: post-upload processors (release tagging etc.) for ``sbom_id``."""
    _log_step_header(6, "Post-upload Processing")
    try:
        from sbomify_action._processors import ProcessorInput, ProcessorOrchestrator

        # Re-mint the OIDC token before kicking off processors: long pipelines
        # (large Docker images, Yocto builds, slow enrichment) can exceed the
        # 15-minute default TTL on the originally minted token.
        if config.token_is_oidc_minted:
            from ..exceptions import OIDCBindingMissingError, OIDCExchangeError
            from ..oidc import is_github_oidc_available, obtain_sbomify_token_via_oidc

            if is_github_oidc_available():
                try:
                    config.token = obtain_sbomify_token_via_oidc(
                        component_id=config.component_id,
                        api_base_url=config.api_base_url,
                        audience=config.oidc_audience,
                    )
                except (OIDCBindingMissingError, OIDCExchangeError) as exc:
                    logger.warning(
                        f"Could not refresh OIDC-minted token before processors: {exc}. "
                        "Continuing with the original token — long-running pipelines may see 401s."
                    )

        orchestrator = ProcessorOrchestrator(
            api_base_url=config.api_base_url,
            token=config.token,
        )
        # Normalize product_releases to list[str] | None for ProcessorInput
        pr_list: list[str] | None = None
        if isinstance(config.product_releases, list):
            pr_list = config.product_releases
        elif isinstance(config.product_releases, str):
            pr_list = json.loads(config.product_releases)

        processor_input = ProcessorInput(
            sbom_id=sbom_id,
            sbom_file=config.output_file,
            product_releases=pr_list,
            api_base_url=config.api_base_url,
            token=config.token,
        )

        # Check if any processors are enabled
        enabled_processors = orchestrator.get_enabled_processors(processor_input)
        if enabled_processors:
            logger.info(f"Running {len(enabled_processors)} processor(s): {enabled_processors}")
            results = orchestrator.process_all(processor_input)
            # Raises SystemExit(1) if any processor failed (e.g. a 403 cutting
            # a release) so the failure isn't swallowed as a green run.
            _finalize_post_upload(results)
        else:
            logger.info("No processors enabled for this run")
            _log_step_end(6)
    except Exception as e:
        # Crash in orchestrator setup. A processor's own failure already
        # comes back as a failure_result (handled above), so this only
        # catches setup/import errors; keep it non-fatal as before.
        logger.error(f"Step 6 (post-upload processing) failed: {e}")
        _log_step_end(6, success=False)


def _finalize_run(config: "Config") -> None:
    """Finalize + persist the audit trail and print the success summary."""
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

    # A version the run derived rather than was handed is exactly what an audit
    # trail is for: "8.21.0" on its own says nothing about whether a human
    # chose it or a tag supplied it, and the two carry very different weight
    # for anyone auditing the document later.
    if config.component_version and config.component_version_source:
        audit_trail.record_augmentation(
            "component.version",
            config.component_version,
            source=config.component_version_source,
        )

    # Log the API base URL being used for transparency
    if config.api_base_url != SBOMIFY_PRODUCTION_API:
        logger.info(f"Using custom API base URL: {config.api_base_url}")
    else:
        logger.info(f"Using production API: {config.api_base_url}")

    # OIDC trusted publishing (GitHub Actions): when TOKEN is missing but the
    # workflow granted id-token: write and we know which component to scope to,
    # exchange a GitHub OIDC JWT for a short-lived sbomify access token. The
    # resulting token then transparently powers upload, augment, and processors.
    #
    # Triggered for any run that will call the sbomify API (uploads, product
    # releases, OR augmentation). For augment-only with no token and no OIDC
    # env, we skip silently — augmentation falls back to sbomify.json.
    if config.will_use_sbomify_api and not config.token and config.component_id:
        from ..exceptions import OIDCBindingMissingError, OIDCExchangeError
        from ..oidc import is_github_oidc_available, obtain_sbomify_token_via_oidc

        if is_github_oidc_available():
            try:
                config.token = obtain_sbomify_token_via_oidc(
                    component_id=config.component_id,
                    api_base_url=config.api_base_url,
                    audience=config.oidc_audience,
                )
                config.token_is_oidc_minted = True
            except OIDCBindingMissingError as exc:
                logger.error(str(exc))
                sys.exit(1)
            except OIDCExchangeError as exc:
                logger.error(f"OIDC trusted publishing failed: {exc}")
                sys.exit(1)
        elif config.requires_sbomify_api:
            # validate() let this config through assuming OIDC would be
            # available at run-time. Env state drifted (caller bypassed
            # validate, subprocess scrubbed env, etc.) — fail loud instead
            # of letting the pipeline hit the API with no Authorization.
            logger.error(
                "sbomify API token is required but neither TOKEN nor GitHub OIDC env "
                "is available at pipeline runtime. Set TOKEN, or ensure the workflow "
                "grants `permissions: id-token: write` for the runner."
            )
            sys.exit(1)

    # Submodule mode: resolve the pin to a version and check whether the
    # submodule's component already published an SBOM at exactly that
    # version. Hit → attach it to the configured release(s), skipping
    # generation and upload entirely (the submodule's own CI produced the
    # authoritative artifact). Miss → fall through to the normal pipeline
    # as a backfill, with COMPONENT_VERSION overridden to the pin-derived
    # version so the upload lands where the next run's lookup will find it.
    if config.submodule_path:
        existing_sbom_id = _prepare_submodule_mode(config)
        if existing_sbom_id:
            logger.info("Skipping SBOM generation and upload — attaching the existing SBOM instead.")
            if config.product_releases:
                _run_post_upload_processing(config, existing_sbom_id)
            else:
                logger.info("No PRODUCT_RELEASE configured; the existing SBOM already covers this pin.")
            _finalize_run(config)
            return

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
    elif config.source_dir:
        FILE = config.source_dir
        FILE_TYPE = "SOURCE_DIR"
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
                # A VEX may arrive as OpenVEX or CSAF, neither of which is an
                # SBOM format; detect those first and copy verbatim.
                external_vex = _detect_external_vex_format(FILE) if config.bom_type == "vex" else None
                if external_vex:
                    FORMAT = external_vex
                    logger.info(f"Detected {format_display_name(FORMAT)} VEX document.")
                else:
                    FORMAT = validate_sbom(FILE)
                    # The config-level CycloneDX-only guard sees the declared SBOM_FORMAT; an
                    # SPDX-content file would slip past it and get byte-rewritten by the SPDX
                    # license sanitization below, so re-check against the detected format.
                    if config.bom_type and config.bom_type != "sbom" and FORMAT != "cyclonedx":
                        accepted = (
                            "a CycloneDX, OpenVEX, or CSAF document"
                            if config.bom_type == "vex"
                            else "a CycloneDX artifact"
                        )
                        raise SBOMValidationError(
                            f"BOM_TYPE='{config.bom_type}' requires {accepted}, but the file "
                            f"content is {FORMAT}; it would be re-serialized and break the verbatim upload."
                        )
                shutil.copy(FILE, STEP_1_FILE)

                # Sanitize SPDX licenses in input SBOMs (e.g. RPM-style "GPLv2+", "ASL 2.0")
                # so that downstream steps can parse the file with spdx_tools
                if FORMAT == "spdx":
                    try:
                        with open(STEP_1_FILE, encoding="utf-8") as f:
                            spdx_data = json.load(f)
                        sanitized = sanitize_spdx_licenses(spdx_data)
                        if sanitized > 0:
                            with open(STEP_1_FILE, "w", encoding="utf-8") as f:
                                json.dump(spdx_data, f, ensure_ascii=False)
                    except (OSError, json.JSONDecodeError) as e:
                        logger.warning(f"Could not sanitize SPDX licenses in input SBOM: {e}")
            elif config.docker_image:
                # Check if image is or is built FROM a Chainguard image
                from .._generation.chainguard import (
                    convert_spdx_to_cyclonedx,
                    detect_chainguard_image,
                    fetch_chainguard_sbom,
                )

                # Check format/version compatibility before attempting detection
                chainguard_compatible = True
                if config.sbom_format == "spdx" and config.spec_version == "3.0.1":
                    logger.debug("SPDX 3.0.1 requested; skipping Chainguard detection")
                    chainguard_compatible = False
                elif config.sbom_format == "cyclonedx":
                    spec = config.spec_version or "1.6"
                    spec_parts = tuple(int(x) for x in spec.split("."))
                    if spec_parts < (1, 3):
                        logger.debug(f"CycloneDX {spec} requested; skipping Chainguard detection")
                        chainguard_compatible = False

                chainguard_info = detect_chainguard_image(config.docker_image) if chainguard_compatible else None

                if chainguard_info:
                    logger.info(f"Detected Chainguard base image: {chainguard_info.image_ref}")

                    try:
                        spdx_sbom = fetch_chainguard_sbom(chainguard_info)
                    except RuntimeError as e:
                        logger.warning(f"Failed to fetch Chainguard SBOM, falling back to normal generation: {e}")
                        chainguard_info = None

                if chainguard_info:
                    if config.sbom_format == "cyclonedx":
                        cdx_spec = config.spec_version or "1.6"
                        cdx_json = convert_spdx_to_cyclonedx(spdx_sbom, cdx_spec)
                        with open(STEP_1_FILE, "w", encoding="utf-8") as f:
                            f.write(cdx_json)
                        actual_spec_version = cdx_spec
                    else:
                        with open(STEP_1_FILE, "w", encoding="utf-8") as f:
                            json.dump(spdx_sbom, f, ensure_ascii=False)
                        # Use the actual SPDX version from the document
                        spdx_version = str(spdx_sbom.get("spdxVersion", "SPDX-2.3"))
                        actual_spec_version = spdx_version.replace("SPDX-", "")
                        if config.spec_version and config.spec_version != actual_spec_version:
                            logger.warning(
                                f"Requested SPDX {config.spec_version} but Chainguard SBOM is "
                                f"SPDX {actual_spec_version}; using {actual_spec_version}"
                            )

                    gha_warning(
                        "Using the SBOM published by Chainguard for this image. It covers the "
                        "packages in the Chainguard base image only — anything your Dockerfile "
                        "adds on top (your application binary, files brought in via COPY/ADD, "
                        "artifacts from other build stages via COPY --from=..., etc.) will NOT "
                        "appear in the resulting SBOM. To include them, provide additional "
                        "packages via ADDITIONAL_PACKAGES, via ADDITIONAL_PACKAGES_FILE, or by "
                        "placing an additional_packages.txt file in the workspace for sbomify "
                        "to read. "
                        "See: https://github.com/sbomify/sbomify-action#additional-packages",
                        title="Chainguard Image Detected",
                    )
                    result = GenerationResult.success_result(
                        output_file=STEP_1_FILE,
                        sbom_format=config.sbom_format,
                        spec_version=actual_spec_version,
                        generator_name="chainguard-sbom",
                    )

                if not chainguard_info:
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
            elif FILE_TYPE == "SOURCE_DIR":
                # Says what it is: a walk of what is on disk, not a reading of
                # what an ecosystem resolved. The distinction belongs in the
                # log as much as in the API -- the resulting SBOM is a weaker
                # claim, and the operator should be able to see which they got.
                logger.info(f"Generating SBOM by scanning directory: {FILE}")
                result = generate_sbom(
                    source_dir=FILE,
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
            # The remedy is worth more here than on the happy path. A run that
            # produced nothing from a manifest is exactly the case where "no
            # lock file was committed" is the likely cause and "here is the
            # command that writes one" is the likely fix -- and until now the
            # advice only appeared when generation had already succeeded, so
            # the people who needed it never saw it.
            _recommend_a_lock_file(config.lock_file)
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

    # Everything below here edits the document itself, and none of it applies
    # to a non-SBOM artifact: a VEX, CBOM or HBOM is uploaded verbatim, which
    # is the same reason the injection step further down skips them.
    is_sbom = not config.bom_type or config.bom_type == "sbom"

    if is_sbom:
        # First, because it changes how the rest of the document should be
        # read: are these versions a record of what the project committed to,
        # or a resolution performed just now.
        _disclose_inferred_resolution(STEP_1_FILE, config)

    # Apply component PURL override if specified (regardless of augmentation settings)
    if config.component_purl:
        logger.info(f"Applying component PURL override: {config.component_purl}")
        _apply_sbom_purl_override(STEP_1_FILE, config)
    elif is_sbom:
        # No explicit PURL, so check the generator did not name the root
        # component after the directory it was pointed at.
        _repair_directory_derived_purl(STEP_1_FILE, config)

    # Inject additional packages if specified (file or environment variables).
    # Non-SBOM artifacts upload verbatim, so injection is skipped for them.
    if config.bom_type and config.bom_type != "sbom":
        logger.info(f"BOM_TYPE={config.bom_type} is uploaded verbatim; skipping additional package injection.")
        _skip_injection = True
    else:
        _skip_injection = False
    try:
        injected_count = 0 if _skip_injection else inject_additional_packages(STEP_1_FILE)
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
    if config.lock_file and not config.is_additional_packages_only:
        from sbomify_action._dependency_expansion import supports_dependency_expansion

        if supports_dependency_expansion(config.lock_file):
            _log_step_header(1.4, "Transitive Dependency Discovery")
            try:
                from sbomify_action._dependency_expansion import expand_sbom_dependencies

                logger.info("Discovering transitive dependencies...")

                expansion_result = expand_sbom_dependencies(
                    sbom_file=STEP_1_FILE,
                    lock_file=config.lock_file,
                )

                if expansion_result.added_count > 0:
                    logger.info(
                        f"Added {expansion_result.added_count} transitive dependencies (discovered {expansion_result.discovered_count} total)"
                    )
                    # Log discovered packages in collapsible group
                    with gha_group("Discovered Transitive Dependencies"):
                        for dep in expansion_result.dependencies[:50]:
                            parent_info = f" (via {dep.parent})" if dep.parent else ""
                            print(f"  {dep.purl}{parent_info}")
                        if len(expansion_result.dependencies) > 50:
                            print(f"  ... and {len(expansion_result.dependencies) - 50} more")
                else:
                    if expansion_result.discovered_count > 0:
                        logger.info(
                            f"No new dependencies to add ({expansion_result.discovered_count} discovered were already in SBOM)"
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
                "To add metadata, either create a sbomify.json file in your project "
                "root, set TOKEN + COMPONENT_ID, or in GitHub Actions enable trusted "
                "publishing with `permissions: id-token: write` plus an OIDC binding "
                "in the sbomify UI.",
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
    artifact_label = config.bom_type.upper() if config.bom_type and config.bom_type != "sbom" else "SBOM"
    _log_step_header(4, f"Finalizing {artifact_label} Output")
    try:
        final_sbom_file = get_last_sbom_from_last_step()
        if not final_sbom_file:
            raise FileProcessingError("No SBOM file found to finalize")

        # Get the parent directory of the file path
        parent_dir = Path(config.output_file).parent

        # Check if the parent directory exists; if not, create it recursively
        if parent_dir != Path(".") and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

        _write_final_output(final_sbom_file, config.output_file, config.bom_type)

        # Clean up temporary step files — never the final output itself, which
        # OUTPUT_FILE may resolve to (the write above is then a copy-to-self no-op).
        output_realpath = os.path.realpath(config.output_file)
        for temp_file in (STEP_3_FILE, STEP_2_FILE, STEP_1_FILE):
            if Path(temp_file).is_file() and os.path.realpath(temp_file) != output_realpath:
                Path(temp_file).unlink()

        logger.info(f"Final {artifact_label} saved to: {config.output_file}")
        _log_step_end(4)

    except (FileProcessingError, OSError) as e:
        logger.error(f"Failed to finalize output: {e}")
        _log_step_end(4, success=False)
        sys.exit(1)

    # Step 5: Upload SBOM to configured destinations
    sbom_id = None  # Store SBOM ID for potential release tagging (from sbomify)
    if config.upload:
        _log_step_header(5, f"Uploading {artifact_label}")
        # Re-mint again, here rather than only before the processors. The
        # earlier refresh is taken before enrichment runs, and enrichment is
        # the slow part: a 289MB bundle's SBOM spent over fifteen minutes
        # being enriched and then failed to upload with 401 Unauthorized,
        # having started from a fresh token. The token is needed *here*, so
        # this is where it should be young.
        if config.token_is_oidc_minted:
            from ..exceptions import OIDCBindingMissingError, OIDCExchangeError
            from ..oidc import is_github_oidc_available, obtain_sbomify_token_via_oidc

            if is_github_oidc_available():
                try:
                    config.token = obtain_sbomify_token_via_oidc(
                        component_id=config.component_id,
                        api_base_url=config.api_base_url,
                        audience=config.oidc_audience,
                    )
                except (OIDCBindingMissingError, OIDCExchangeError) as exc:
                    logger.warning(
                        f"Could not refresh OIDC-minted token before upload: {exc}. "
                        "Continuing with the existing token, which may have expired."
                    )
        try:
            # Upload to each configured destination
            logger.info(f"Upload destinations: {config.upload_destinations}")

            failed_destinations: list[str] = []
            # Subset of failed_destinations whose only problem was that the
            # version is already published — see DuplicateArtifactError.
            duplicate_destinations: list[str] = []
            for destination in config.upload_destinations or []:
                logger.info(f"Uploading to: {destination}")

                upload_result = upload_sbom(
                    sbom_file=config.output_file,
                    sbom_format=FORMAT,
                    token=config.token,
                    component_id=config.component_id,
                    api_base_url=config.api_base_url,
                    component_name=config.component_name,
                    component_version=config.component_version,
                    destination=destination,
                    validate_before_upload=(FORMAT == "cyclonedx"),
                    bom_type=config.bom_type,
                )

                if (
                    not upload_result.success
                    and upload_result.error_code == "DUPLICATE_ARTIFACT"
                    and config.submodule_path
                    and destination == "sbomify"
                ):
                    # Backfill race: another workflow published this
                    # (component, version, format) between our preflight
                    # lookup and this upload. The backend's uniqueness
                    # constraint guarantees a single winner — recover by
                    # re-looking it up and attaching that SBOM instead of
                    # failing the run.
                    recovered = _find_existing_submodule_sbom(config, FORMAT)
                    if recovered:
                        logger.info(
                            f"Duplicate upload for submodule component — another workflow published "
                            f"this SBOM first; reusing the existing one (id: {recovered})."
                        )
                        sbom_id = recovered
                        continue

                if not upload_result.success:
                    if upload_result.error_code == "DUPLICATE_ARTIFACT":
                        # warning, not error: Sentry's logging integration turns
                        # error-level records into events, and this one embeds
                        # the component_id — so every affected component became
                        # its own issue for a condition that is simply "already
                        # published". The user-facing panel below is unchanged.
                        logger.warning(
                            f"Upload to {destination} failed with duplicate SBOM: "
                            f"component_id={config.component_id}, format={FORMAT}, "
                            f"version={config.component_version}"
                        )
                        duplicate_destinations.append(destination)
                        print_duplicate_sbom_error(
                            config.component_id, FORMAT, config.component_version, artifact_kind=artifact_label
                        )
                    elif upload_result.error_code == "COMPONENT_NOT_FOUND":
                        logger.error(
                            f"Upload to {destination} failed: component not found (component_id={config.component_id})"
                        )
                        print_component_not_found_error(config.component_id)
                    else:
                        logger.error(f"Upload to {destination} failed: {upload_result.error_message}")
                    failed_destinations.append(destination)
                else:
                    logger.info(f"Upload to {destination} succeeded")
                    # Store sbom_id from sbomify for release tagging
                    if destination == "sbomify" and upload_result.sbom_id:
                        sbom_id = upload_result.sbom_id

            # Fail if any upload failed
            if failed_destinations:
                message = f"Upload failed for destination(s): {', '.join(failed_destinations)}"
                # When *every* failure was a duplicate the run still fails —
                # nothing new was published, and the user should know — but it
                # is an expected condition rather than a defect, so raise the
                # type ``before_send`` filters instead of a bare APIError.
                if set(failed_destinations) == set(duplicate_destinations):
                    raise DuplicateArtifactError(message)
                raise APIError(message)

            _log_step_end(5)

        except (APIError, FileProcessingError) as e:
            # The step-level echo is a second Sentry event for the same
            # occurrence — the logging integration turns any error record into
            # one, regardless of the exception type below it. Log the expected
            # duplicate case at warning so a re-run publishes nothing and
            # reports nothing, while still failing the job.
            if isinstance(e, DuplicateArtifactError):
                logger.warning(f"Step 5 (upload) failed: {e}")
            else:
                logger.error(f"Step 5 (upload) failed: {e}")
            _log_step_end(5, success=False)
            sys.exit(1)
    else:
        _log_step_header(5, "SBOM Upload - SKIPPED")
        logger.info("SBOM upload disabled (UPLOAD=false)")
        _log_step_end(5)

    # Step 6: Post-upload Processing (releases, signing, etc.)
    if sbom_id:
        _run_post_upload_processing(config, sbom_id)
    elif config.product_releases and not sbom_id:
        _log_step_header(6, "Post-upload Processing - SKIPPED")
        logger.warning("Product releases specified but no SBOM ID available (upload may have been disabled or failed)")
        _log_step_end(6, success=False)

    _finalize_run(config)


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


def _update_spdx_json_purl_version(package_json: dict[str, Any], new_version: str) -> bool:
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
                    old_bom_ref = (
                        parsed_object.metadata.component.bom_ref.value
                        if parsed_object.metadata.component.bom_ref
                        else None
                    )
                    parsed_object.metadata.component.version = config.component_version
                    # Also update the PURL version to maintain consistency
                    _update_component_purl_version(parsed_object.metadata.component, config.component_version)
                    # Update dependency graph if bom_ref changed
                    new_bom_ref = (
                        parsed_object.metadata.component.bom_ref.value
                        if parsed_object.metadata.component.bom_ref
                        else None
                    )
                    if old_bom_ref and new_bom_ref and old_bom_ref != new_bom_ref:

                        def _update_dep_refs(deps: Any) -> None:
                            for dep in deps:
                                dep_ref = getattr(dep, "ref", None)
                                if dep_ref is not None and getattr(dep_ref, "value", None) == old_bom_ref:
                                    dep_ref.value = new_bom_ref
                                nested = getattr(dep, "dependencies", None)
                                if nested:
                                    _update_dep_refs(nested)

                        if parsed_object.dependencies:
                            _update_dep_refs(parsed_object.dependencies)
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
                # SPDX 2.x - find root package via documentDescribes, not packages[0]
                main_package = None
                if "packages" in original_json and original_json["packages"]:
                    described_refs = original_json.get("documentDescribes")
                    if isinstance(described_refs, list) and described_refs and isinstance(described_refs[0], str):
                        for pkg in original_json["packages"]:
                            if pkg.get("SPDXID") == described_refs[0]:
                                main_package = pkg
                                break
                    if main_package is None:
                        main_package = original_json["packages"][0]  # fallback
                if main_package is not None:
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


#: Directory names that identify a mount point rather than a project.
#:
#: The defect this guards is specific: a generator names the root component
#: after the directory it was pointed at, and in a container that directory is
#: the same for everyone. `/workspace` is this image's own documented mount and
#: accounts for every case measured across 500 projects; the rest are the
#: conventional alternatives people bind-mount to.
#:
#: Deliberately a closed list rather than a rule. Anything cleverer -- "does
#: this look like a project name?" -- decides against the user's own data on a
#: guess, and the cost of a false positive here is overwriting a correct
#: identity, which is worse than leaving a useless one in place.
_GENERIC_MOUNT_NAMES = frozenset({"workspace", "src", "app", "repo", "code", "project", "build", "data"})


#: Ceiling for an identity we inferred. Not a measurement -- a statement that
#: this is a guess, in the field designed to carry exactly that.
_INFERRED_CONFIDENCE = 0.5


def _capped_confidence(existing: object) -> float:
    """Lower a confidence to the inferred ceiling, never raise it.

    `existing or 0.5` looked equivalent and is not: 0 is a legitimate
    confidence meaning "none at all", and it is falsy, so that spelling
    replaced it with 0.5 -- raising the confidence of a component that claimed
    none, inside the function whose whole purpose is to lower it.
    """
    try:
        value = _INFERRED_CONFIDENCE if existing is None else float(existing)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        value = _INFERRED_CONFIDENCE
    return min(value, _INFERRED_CONFIDENCE)


#: Lock file names a generator may cite as evidence. Only these are candidates
#: for correction -- everything else in concludedValue belongs to whatever
#: technique put it there.
_LOCK_FILE_EVIDENCE = frozenset(
    {
        "composer.lock",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "go.sum",
        "Package.resolved",
        "mix.lock",
        "stack.yaml.lock",
    }
)


def _cites_a_phantom_lockfile(value: object, directory: Path) -> bool:
    """Whether this evidence names a lock file that is not in the repository.

    The narrow question worth acting on. A generator that resolved a manifest
    by materialising a lock file names that file as its source, and the file
    is gone by the time anyone reads the document -- so the claim cannot be
    checked. Everything else in the field was put there by a technique that
    knew what it meant, and is left alone.
    """
    if not value:
        return False
    cited = Path(str(value))
    if cited.name not in _LOCK_FILE_EVIDENCE:
        return False

    # Where the citation actually points, not just what it is called.
    #
    # Taking the basename and looking only beside the input meant a component
    # citing `frontend/composer.lock` -- a file that is really there -- was
    # judged phantom because there is no composer.lock next to the manifest,
    # and its correct evidence was overwritten. Same over-reach as before,
    # wearing a different hat.
    if cited.is_absolute():
        return not cited.is_file()
    return not (directory / cited).is_file() and not (Path(GITHUB_WORKSPACE) / cited).is_file()


def _recommend_a_lock_file(lock_file: str | None) -> None:
    """Point at the missing lock file after a run that produced nothing.

    Same advice as the inference notice, minus the claims about a document
    that does not exist. Kept separate rather than reusing that function so
    neither has to ask whether it is being called before or after a failure.
    """
    from .._generation.registry import recommended_action, resolution_was_inferred

    if not resolution_was_inferred(lock_file):
        return
    action = recommended_action(lock_file)
    name = Path(lock_file or "").name
    if action and action[0]:
        logger.error(
            f"'{name}' constrains dependencies without resolving them, and no lock file was "
            f"committed beside it. That is a common reason for this to fail. Run `{action[0]}`, "
            f"commit {action[1]}, and point LOCK_FILE at it."
        )
    elif action:
        logger.error(f"'{name}' constrains dependencies without resolving them. {action[1]}.")


def _disclose_inferred_resolution(sbom_file: str, config: "Config") -> None:
    """Say so, loudly and in the document, when the versions were inferred.

    A lock file records what a project committed to. A manifest records what
    it would accept. When only the manifest exists, the resolver picks
    versions from whatever the registry offers at that moment, and the result
    is a statement about today rather than about the project: run it tomorrow
    and it differs, run it against a mirror and it differs, and the consuming
    application will resolve its own tree and get different answers again.

    Measured across 500 open source projects, 112 of 427 successful documents
    were built this way -- a quarter of them -- and nothing in the output said
    so. laravel/framework commits no composer.lock, and its document asserted
    72 exact versions, every one chosen during the run.

    Worse, cdxgen attributes those components to the lock file it created
    transiently and then discarded, at ``confidence: 1.0``. So the document
    did not merely omit the inference; it cited a source that is not in the
    repository, with maximum confidence. That claim is corrected here.

    The codebase already holds this principle in two places and applies it in
    neither generally: the Swift path refuses outright rather than resolve
    ranges, and the pipdeptree expander verifies the installed environment
    against the lock file before believing it. This is the same rule, said
    once, for every ecosystem.

    Not a refusal. An inferred document is genuinely useful -- it answers
    "what would I get if I installed this today", which is the right question
    for vulnerability scanning. It is only harmful when it cannot be told
    apart from the other kind.
    """
    from .._generation.registry import recommended_action, resolution_was_inferred

    if not resolution_was_inferred(config.lock_file):
        return

    name = Path(config.lock_file or "").name
    action = recommended_action(config.lock_file)

    # The fix, in this project's own terms. "Commit a lock file" is not advice
    # if the reader does not know which one, and for Maven, Gradle and sbt
    # there is no lock file to commit at all -- so those say what to do
    # instead rather than recommending something that does not exist.
    if action and action[0]:
        remedy = f"  TO FIX THIS, run:\n      {action[0]}\n  then commit {action[1]} and point LOCK_FILE at it.\n"
    elif action:
        remedy = f"  TO FIX THIS: {action[1]}.\n"
    else:
        remedy = "  TO FIX THIS: commit the lock file your build produces and point LOCK_FILE at it.\n"

    logger.warning(
        "\n"
        "  ┌───────────────────────────────────────────────────────────────┐\n"
        "  │  THE VERSIONS IN THIS SBOM WERE INFERRED, NOT RECORDED        │\n"
        "  └───────────────────────────────────────────────────────────────┘\n"
        f"  {name} constrains dependencies; it does not resolve them, and no\n"
        "  lock file was committed beside it. The versions below were chosen\n"
        "  by resolving those constraints just now, against whatever the\n"
        "  registry currently offers.\n"
        "\n"
        "  This document therefore:\n"
        "    - describes today, not what the project ships or tested\n"
        "    - will differ if you generate it again tomorrow\n"
        "    - may be incomplete, and may name versions nobody installs\n"
        "\n" + remedy
    )

    try:
        sbom_format, document, _parsed = load_sbom_from_file(sbom_file)
        if sbom_format != "cyclonedx":
            # SPDX is generated for inferred inputs too -- go.mod among them --
            # and this notice does not reach those documents. SPDX 2.3 could
            # carry it as a document annotation, which is a change with its own
            # tests rather than a line here. Until then the limitation is
            # stated rather than left for a reader to discover.
            logger.warning(
                f"This {sbom_format.upper()} document cannot carry the inference notice yet, so it "
                f"exists only in the log above. A reader of the file alone will not be told the "
                f"versions were resolved rather than recorded."
            )
            return

        # metadata.properties arrived in CycloneDX 1.3. Writing it into a 1.2
        # document produces an artifact that fails its own schema -- and does
        # so after validation has already passed, so nothing would catch it.
        # The warning still reaches the console either way; only the in-document
        # copy is unavailable.
        spec = str(document.get("specVersion") or "")
        # Compared as numbers. As strings "1.10" sorts below "1.3", so the day
        # CycloneDX reaches a double-digit minor this would start refusing to
        # write the notice into documents that support it perfectly well.
        try:
            spec_parts = tuple(int(part) for part in spec.split("."))
        except ValueError:
            spec_parts = ()
        if spec_parts and spec_parts < (1, 3):
            logger.warning(
                f"CycloneDX {spec} has no metadata.properties, so the inference notice cannot be "
                f"written into this document. It is in the log above; upgrade to 1.3 or later to "
                f"have it travel with the file."
            )
            return

        metadata = document.setdefault("metadata", {})
        properties = metadata.setdefault("properties", [])
        properties.append(
            {
                "name": "sbomify:resolution",
                "value": f"inferred-at-build-time from {name}; no lock file was committed",
            }
        )
        # The remedy goes in the document as well as the log, because the two
        # have different readers. Whoever generated this sees the console; the
        # person who later asks why the versions do not match production sees
        # only the file.
        if action:
            properties.append(
                {
                    "name": "sbomify:resolution:remedy",
                    "value": f"run `{action[0]}` and commit {action[1]}" if action[0] else action[1],
                }
            )

        # Stop the components claiming a source that is not in the repository.
        #
        # cdxgen names the lock file it materialised during the run and rates
        # itself certain of it. The file never existed for the reader, so the
        # claim cannot be checked and should not be made: the honest source is
        # the manifest, and the honest confidence is not 1.0.
        corrected_identities = 0
        directory = Path(config.lock_file or "").parent
        for component in document.get("components") or []:
            for identity in (component.get("evidence") or {}).get("identity") or []:
                # Only an identity citing a lock file that is not there.
                #
                # The first version rewrote every identity whose concludedValue
                # was not the input, which is far more than the defect: cdxgen
                # puts other things in this field -- file paths, and evidence
                # from techniques that have nothing to do with lock files --
                # and replacing those with "composer.json" destroys real
                # evidence to correct a claim they were not making.
                concluded = identity.get("concludedValue")
                if not _cites_a_phantom_lockfile(concluded, directory):
                    continue
                identity["concludedValue"] = name
                identity["confidence"] = _capped_confidence(identity.get("confidence"))
                for method in identity.get("methods") or []:
                    # Same restriction for the methods: only the ones pointing
                    # at the vanished file, not every method on the identity.
                    if _cites_a_phantom_lockfile(method.get("value"), directory):
                        method["value"] = name
                        method["confidence"] = _capped_confidence(method.get("confidence"))
                corrected_identities += 1
        if corrected_identities:
            # Identities, not components: one component can carry several, and
            # calling them components overstated the reach of the correction.
            logger.info(
                f"Corrected {corrected_identities} identity claim(s) citing a lock file that was never committed"
            )

        # Compact rather than indented, but only because there is no reason to
        # spend the bytes: this is an intermediate file and the augmentation
        # and serialisation steps downstream rewrite it before anyone sees it.
        # Checked, rather than assumed -- the shipped artifact is formatted by
        # those later steps, so the choice here is invisible either way.
        Path(sbom_file).write_text(json.dumps(document))
        get_audit_trail().record_augmentation(
            "sbom.resolution", "inferred-at-build-time", name, source="sbomify-action"
        )
    except Exception as e:  # noqa: BLE001 - disclosure must not fail the run
        # Warning, not debug. Swallowing this quietly is the failure mode the
        # notice exists to prevent, one level up: the document silently loses
        # the disclosure and nothing says so. It still must not abort the run,
        # but it has to be visible when it happens.
        logger.warning(f"Could not annotate the document with the resolution notice: {e}")


def _repair_directory_derived_purl(sbom_file: str, config: "Config") -> None:
    """Replace a root PURL that names the working directory rather than the project.

    Generators derive the root component from the directory they are pointed
    at. In this image that directory is ``/workspace`` for every project, so
    the field consumers use as the component's identity is the same string for
    everybody. Measured over 500 open source projects: thirty documents shared
    five PURLs, with ``pkg:pypi/workspace@latest`` covering fastapi, flask,
    transformers and airbyte alike, and ``pkg:gem/workspace@latest`` covering
    Alamofire, Moya, RxSwift and discourse.

    ``COMPONENT_NAME`` does not help. It is applied to the component's ``name``
    and never to its PURL, so the document ends up calling itself ``rails`` and
    identifying itself as ``pkg:gem/workspace@latest`` -- correct in the half a
    human reads and wrong in the half a machine reads.

    Repaired only when the PURL can be *shown* to come from the directory:
    its name equals the working directory's basename, and differs from the
    component name we were given. Both conditions matter. A project whose
    directory genuinely is its name keeps its PURL, and so does one where
    ``COMPONENT_NAME`` is a display name that was never meant to match the
    package name -- "My Product" against ``pkg:npm/my-product`` is normal, and
    rewriting it would be a regression rather than a fix.

    The replacement is deliberately ``pkg:generic``. Keeping the ecosystem type
    and swapping the name -- ``pkg:npm/workspace`` to ``pkg:npm/rails`` -- reads
    as the obvious fix and is worse than the bug: a PURL is a *resolvable*
    identity, npm's ``rails`` package is not the Ruby framework's asset bundle,
    and pointing at someone else's package is more dangerous than pointing
    nowhere. ``pkg:generic`` names the thing without claiming a registry entry,
    and it is unique per project, which is what removes the collision.

    Set ``COMPONENT_PURL`` to state the identity yourself; this never runs then.
    """
    if not config.component_name:
        return  # nothing to compare the PURL against

    # WORKING_DIR if the caller set it, otherwise the directory the workflow
    # already chdir'd into. Config carries no working directory of its own, and
    # reaching for one would have raised AttributeError straight into the
    # except below -- silently turning this whole function off, which is the
    # failure mode the function exists to fix.
    working_dir = Path(os.environ.get("WORKING_DIR") or Path.cwd()).resolve().name
    if working_dir.lower() not in _GENERIC_MOUNT_NAMES:
        # The directory tells us something about the project, so a PURL naming
        # it is not evidence of anything wrong.
        #
        # Without this, the repair had a false positive that would have been
        # worse than the bug: a checkout in a directory called `rails`,
        # producing a perfectly good `pkg:gem/rails`, with COMPONENT_NAME set
        # to a display label like "Rails Framework". The name matches the
        # directory and differs from the component name -- both original
        # conditions satisfied -- and a valid PURL gets overwritten with
        # pkg:generic. The two conditions were not as load-bearing as claimed.
        return

    try:
        from packageurl import PackageURL

        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)
        if sbom_format != "cyclonedx":
            # SPDX carries the PURL in the root package's externalRefs. Left
            # alone deliberately rather than half-done: the same reasoning
            # applies, and it deserves its own change with its own tests.
            return

        from cyclonedx.model.bom import Bom

        if not isinstance(parsed_object, Bom):
            return
        component = getattr(parsed_object.metadata, "component", None)
        if component is None or not component.purl:
            return

        current = PackageURL.from_string(str(component.purl))
        if current.name != working_dir or current.name == config.component_name:
            return

        # COMPONENT_NAME is free text and reaches a field that is not.
        #
        # It does not raise, which is what makes it worth handling: PackageURL
        # accepts almost anything and quietly reshapes it. "My Product"
        # percent-encodes to My%20Product, and "owner/repo" is worse than ugly
        # -- the slash is read as a namespace separator, so the identity comes
        # out structured in a way nobody asked for.
        #
        # augmentation.py already has the rule for this and two other places
        # already use it. Writing a third variant here is how a codebase ends
        # up with three spellings of one identity, which is the failure this
        # whole function exists to undo.
        from sbomify_action.augmentation import sanitize_name_for_purl

        safe_name = sanitize_name_for_purl(config.component_name)
        if not safe_name:
            logger.debug(f"COMPONENT_NAME {config.component_name!r} yields no usable PURL name; leaving the PURL")
            return

        repaired = PackageURL(
            type="generic",
            name=safe_name,
            version=current.version,
        )
        logger.warning(
            f"The root component's PURL named the working directory rather than the project "
            f"('{current}'). Replacing it with '{repaired}'. Set COMPONENT_PURL to state the "
            f"identity explicitly."
        )
        component.purl = repaired
        # source= matters: it defaults to "sbomify-api", and this change is
        # made locally from COMPONENT_NAME with nothing fetched. An audit
        # trail exists to say where a value came from, so letting it claim the
        # API supplied this would be the one kind of wrong it cannot afford.
        get_audit_trail().record_augmentation("component.purl", str(repaired), str(current), source="sbomify-action")

        spec_version = original_json.get("specVersion")
        if spec_version is None:
            raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
        with Path(sbom_file).open("w") as handle:
            handle.write(serialize_cyclonedx_bom(parsed_object, spec_version))
    except Exception as e:  # noqa: BLE001 - identity repair must never fail a run
        logger.debug(f"Could not check the root component's PURL: {e}")


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


def _make_bool_envvar_callback(
    envvar: str, default: bool
) -> "Callable[[click.Context, click.Parameter, Optional[bool]], bool]":
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
        if param.name and ctx.get_parameter_source(param.name) == click.core.ParameterSource.COMMANDLINE:
            return value if value is not None else default

        # Check environment variable with string-to-bool conversion
        env_value = os.getenv(envvar)
        if env_value is not None:
            try:
                return evaluate_boolean(env_value, source=envvar)
            except ConfigurationError as exc:
                # Surface as a parse-time usage error (exit 2) so a bad
                # value stops the run instead of silently selecting the
                # option's default.
                raise click.BadParameter(str(exc), ctx=ctx, param=param) from exc

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
    # First match wins, so this is the documented precedence:
    # $SBOMIFY_TOKEN outranks $TOKEN. Both are honoured because the
    # GitHub Action, GitLab and Bitbucket templates all map the
    # SBOMIFY_TOKEN secret onto a TOKEN env var, while a local
    # pipx/uvx user naturally exports SBOMIFY_TOKEN itself.
    envvar=["SBOMIFY_TOKEN", "TOKEN"],
    help="sbomify API token (required for upload/augment). [env: SBOMIFY_TOKEN, TOKEN]",
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
    "--source-dir",
    envvar="SOURCE_DIR",
    type=click.Path(exists=False, file_okay=False),
    help=(
        "Directory to scan (last resort). Prefer --lock-file wherever one exists: "
        "a lock file is the graph the ecosystem resolved, while a scan finds only "
        "what is on disk and what Syft recognises. Use this for what no lock file "
        "describes, such as an unpacked release archive or a vendored tree."
    ),
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
    "--submodule-path",
    envvar="SUBMODULE_PATH",
    default=None,
    help=(
        "Treat the component as a git submodule pinned at this path: resolve the pin to a "
        "version (tag or short SHA), attach the component's existing SBOM at that version if "
        "one exists, otherwise generate and upload it (backfill)."
    ),
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
    "--bom-type",
    envvar="BOM_TYPE",
    type=click.Choice(list(VALID_BOM_TYPES), case_sensitive=False),
    default="sbom",
    show_default=True,
    help="Artifact type recorded on upload. Non-SBOM types are uploaded verbatim.",
)
@click.option(
    "--spec-version",
    envvar="SPEC_VERSION",
    default=None,
    help="Override the spec version for SBOM generation (e.g., '1.6', '2.3', '3.0.1').",
)
@click.option(
    "--oidc-audience",
    envvar="OIDC_AUDIENCE",
    default=None,
    help="Audience claim for GitHub OIDC trusted publishing (default: sbomify.com; override for self-hosted).",
)
@click.option(
    "--telemetry/--no-telemetry",
    default=True,
    show_default=True,
    callback=_make_bool_envvar_callback("TELEMETRY", True),
    is_eager=True,
    help="Enable/disable error telemetry (Sentry). [env: TELEMETRY]",
)
@click.option(
    "--working-dir",
    envvar="WORKING_DIR",
    default=None,
    help="Working directory (absolute, or relative to cwd locally / GITHUB_WORKSPACE in GHA). [env: WORKING_DIR]",
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
    source_dir: Optional[str],
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
    submodule_path: Optional[str],
    api_base_url: str,
    sbom_format: str,
    bom_type: Optional[str],
    spec_version: Optional[str],
    oidc_audience: Optional[str],
    working_dir: str | None,
    telemetry: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Generate, augment, enrich, and manage SBOMs in your CI/CD pipeline.

    Provide one of: --sbom-file, --lock-file, --source-dir, or --docker-image
    as input.

    \b
    Commands:
      wizard  Interactive wizard to onboard a repository to sbomify
      init    Alias for `wizard` (backwards compatible)
      yocto   Process Yocto/OpenEmbedded SPDX SBOMs

    \b
    Examples:
      # Generate SBOM from lock file
      sbomify-action --lock-file requirements.txt --enrich --no-upload

      # Process existing SBOM and upload to sbomify
      sbomify-action --sbom-file sbom.json --token <your-token> --component-id abc123

      # Generate from Docker image with SPDX format
      sbomify-action --docker-image nginx:latest -f spdx -o sbom.spdx.json

      # Run the onboarding wizard interactively
      sbomify-action wizard
    """
    # Configure logging level early so all messages respect --verbose/--quiet
    if verbose and quiet:
        raise click.UsageError("Cannot use both --verbose and --quiet")

    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    elif quiet:
        logger.setLevel(logging.WARNING)

    # Change working directory early, before any file resolution (applies to subcommands too)
    if working_dir:
        resolved = resolve_working_dir(working_dir)
        logger.info(f"Changing working directory to '{resolved}'")
        os.chdir(resolved)
        # Verify cwd is still under workspace after chdir (TOCTOU mitigation)
        if _in_github_actions():
            cwd = Path.cwd().resolve()
            workspace = _github_workspace()
            if not cwd.is_relative_to(workspace):
                logger.error(f"Working directory '{cwd}' escaped workspace '{workspace}' after chdir. Aborting.")
                ctx.exit(1)

    # If a subcommand was invoked, don't run the default pipeline
    if ctx.invoked_subcommand is not None:
        return

    # Show help with banner if no input source is provided.
    #
    # source_dir belongs in this list. Without it, SOURCE_DIR on its own read
    # as "no input at all": the banner and help printed and the process exited
    # 0, so the action step went green having produced no SBOM. Silent, because
    # exit 0 is success -- the failure only surfaced downstream, where
    # something looked for the output file that was never written.
    if not any([sbom_file, docker_image, lock_file, source_dir]):
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

    # Reset audit trail for this run
    reset_audit_trail()

    # Mirror --docker-image into the environment so the DockerImageProvider
    # (which reads DOCKER_IMAGE) sets lifecycle_phase=post-build even when
    # the user passed the flag on the CLI rather than via the env var.
    # Click's envvar binding only reads env → option; it does not write
    # option → env. Always overwrite when docker_image is provided — if
    # the user passes a --docker-image that differs from the existing
    # DOCKER_IMAGE env var, the flag must win (Click already resolved
    # the two, so docker_image here is the effective value) and
    # downstream logging must reflect the image that is actually scanned.
    if docker_image:
        os.environ["DOCKER_IMAGE"] = docker_image

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
        source_dir=source_dir,
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
        submodule_path=submodule_path,
        api_base_url=api_base_url,
        sbom_format=sbom_format,
        bom_type=bom_type,
        spec_version=spec_version,
        oidc_audience=oidc_audience,
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
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help=(
        "Show what would happen without making API mutations or file writes. "
        "Yocto's dry-run short-circuits before any API client is constructed, "
        "so no auth call or listing is attempted."
    ),
)
@click.option(
    "--visibility",
    type=click.Choice(["public", "private", "gated"], case_sensitive=False),
    default=None,
    help="Set visibility for newly created components.",
)
@click.option(
    "--max-packages",
    type=int,
    default=None,
    hidden=False,
    help="[Advanced] Limit number of packages to process (SPDX 2.2 only). Useful for testing.",
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
    max_packages: int | None,
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

    # Token precedence: --token on the root group, then $SBOMIFY_TOKEN / $TOKEN.
    yocto_token = _resolve_token(ctx.parent.params.get("token") if ctx.parent else None)
    if not yocto_token:
        raise click.UsageError(
            "Missing required option '--token' (provide via root command, $SBOMIFY_TOKEN, or $TOKEN)."
        )

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
        max_packages=max_packages,
    )

    result = run_yocto_pipeline(config)

    if result.has_errors:
        sys.exit(1)


_FC = TypeVar("_FC", bound=Callable[..., Any])


def _wizard_options(func: _FC) -> _FC:
    """Apply the option set shared by ``wizard`` and ``init`` (its alias)."""
    decorators: list[Callable[[Callable[..., Any]], Callable[..., Any]]] = [
        click.option(
            "--token",
            default=None,
            help="sbomify API token. Falls back to $SBOMIFY_TOKEN, then $TOKEN.",
        ),
        click.option(
            "--api-base-url",
            envvar="API_BASE_URL",
            default=SBOMIFY_PRODUCTION_API,
            show_default=True,
            help="Base URL for the sbomify API.",
        ),
        click.option(
            "--repo-root",
            type=click.Path(file_okay=False, exists=True, path_type=Path),
            default=Path("."),
            show_default=True,
            help="Repository root to scan for lockfiles.",
        ),
        click.option(
            "--output-dir",
            type=click.Path(file_okay=False, path_type=Path),
            default=Path(".github/workflows"),
            show_default=True,
            help="Directory where the generated workflow file will be written.",
        ),
        click.option(
            "--dry-run",
            is_flag=True,
            default=False,
            help=(
                "Walk the wizard and render the plan, but make no API mutations "
                "and write no files. Read-only API calls during authentication / "
                "workspace prefetch still happen; apply emits [dry-run] lines for "
                "every mutation it would have made."
            ),
        ),
        click.option(
            "--debug",
            is_flag=True,
            default=False,
            help=(
                "Buffer DEBUG-level logs in memory and dump them to stdout "
                "AFTER the TUI exits. Textual takes over stdout while it's "
                "running, so streaming logs in real time isn't possible — "
                "the dump is the next-best thing."
            ),
        ),
    ]
    for decorator in reversed(decorators):
        func = decorator(func)  # type: ignore[assignment]
    return func


def _install_debug_buffer() -> "io.StringIO":
    """Attach a DEBUG-level handler that buffers logs in memory.

    Textual takes over stdout while the TUI is running, so writing
    logs directly to stdout in real time is useless (they'd interfere
    with rendering at best, get swallowed at worst). Buffer everything
    instead and dump the buffer to stdout after the TUI exits — the
    invocation stays pipeable (eg ``sbomify-action wizard --debug 2>&1
    | tee debug.log``).
    """
    import io
    import logging

    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s.%(msecs)03d  %(levelname)-7s  %(name)s  %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    # Attach to the sbomify_action root (captures everything the
    # wizard, API client, and apply phase log) AND to textual itself
    # so workflow/worker events land in the same buffer.
    for name in ("sbomify_action", "textual"):
        target = logging.getLogger(name)
        target.setLevel(logging.DEBUG)
        target.addHandler(handler)
    return buffer


def _wizard_in_ci() -> bool:
    """Refuse to launch the TUI under a non-interactive CI environment."""
    for name in ("GITHUB_ACTIONS", "CI"):
        value = os.environ.get(name)
        if value is not None and value.strip().lower() in {"true", "1", "yes", "on"}:
            return True
    return False


def _run_wizard_cli(
    token: Optional[str],
    api_base_url: str,
    repo_root: Path,
    output_dir: Path,
    dry_run: bool,
    debug: bool,
) -> None:
    """Validate options, build WizardOptions, and launch the Textual wizard."""
    from sbomify_action.cli.wizard.app import launch_wizard
    from sbomify_action.cli.wizard.options import WizardOptions

    if _wizard_in_ci():
        click.echo(
            "Refusing to launch the interactive wizard from a CI environment. "
            "Run `sbomify-action wizard` locally to onboard a repository.",
            err=True,
        )
        sys.exit(1)

    # Always work in absolute paths so downstream phases don't depend on CWD.
    repo_root = repo_root.resolve()
    if not output_dir.is_absolute():
        output_dir = repo_root / output_dir
    output_dir = output_dir.resolve()

    # GitHub Actions only loads workflow files from .github/workflows, and the
    # generated workflow's `paths:` filter is pinned to that directory.
    # Reject anything else early — silently writing non-functional workflows
    # is worse than failing fast.
    expected = (repo_root / ".github" / "workflows").resolve()
    if output_dir != expected:
        raise click.BadParameter(
            f"--output-dir must be {expected} (GitHub Actions only loads workflows "
            "from .github/workflows). Got: " + str(output_dir),
            param_hint="--output-dir",
        )

    debug_buffer = None
    if debug:
        debug_buffer = _install_debug_buffer()
        click.echo(
            "[--debug] Capturing DEBUG logs; full transcript will print to stdout after the wizard exits.",
            err=True,
        )

    opts = WizardOptions(
        token=_resolve_token(token),
        api_base_url=api_base_url.rstrip("/"),
        repo_root=repo_root,
        output_dir=output_dir,
        dry_run=dry_run,
        debug=debug,
    )
    exit_code = launch_wizard(opts)
    if debug_buffer is not None:
        # Textual has restored stdout by now; flush the buffered
        # transcript so users can pipe / tee / grep it.
        sys.stdout.write("\n=== sbomify wizard DEBUG log ===\n")
        sys.stdout.write(debug_buffer.getvalue())
        sys.stdout.write("=== end DEBUG log ===\n")
        sys.stdout.flush()
    sys.exit(exit_code)


@cli.command("wizard")
@_wizard_options
@click.pass_context
def wizard_cmd(
    ctx: click.Context,
    token: Optional[str],
    api_base_url: str,
    repo_root: Path,
    output_dir: Path,
    dry_run: bool,
    debug: bool,
) -> None:
    """Interactive wizard to onboard a repository to sbomify.

    Scans for lockfiles, authenticates against sbomify, registers
    matching components, and writes ``.github/workflows/sboms.yml``.
    """
    token = _inherit_root_token(ctx, token)
    _run_wizard_cli(token, api_base_url, repo_root, output_dir, dry_run, debug)


@cli.command("init")
@_wizard_options
@click.pass_context
def init_cmd(
    ctx: click.Context,
    token: Optional[str],
    api_base_url: str,
    repo_root: Path,
    output_dir: Path,
    dry_run: bool,
    debug: bool,
) -> None:
    """Alias for ``sbomify-action wizard``. Kept for backwards compatibility.

    Note: previous versions of ``init`` generated only a ``sbomify.json``
    configuration file. As of this release, ``init`` is an alias for
    the full onboarding wizard.
    """
    click.echo("Note: `init` is an alias for `wizard`. Prefer `sbomify-action wizard`.", err=True)
    token = _inherit_root_token(ctx, token)
    _run_wizard_cli(token, api_base_url, repo_root, output_dir, dry_run, debug)


def _inherit_root_token(ctx: click.Context, token: Optional[str]) -> Optional[str]:
    """Resolve the token for the wizard / init subcommand.

    The subcommand's own --token wins when the user typed it; otherwise
    inherit whatever the root group resolved, whether it came from the
    command line or the environment.

    Inheriting an env-derived value is only safe because the root binds
    ``envvar=["SBOMIFY_TOKEN", "TOKEN"]`` — the same precedence
    ``_resolve_token`` implements. While the root bound $TOKEN alone,
    this function had to refuse env-derived values, since inheriting one
    would have let $TOKEN outrank $SBOMIFY_TOKEN and contradict the help
    text on ``--token``.
    """
    if token:
        return token
    if ctx.parent is None:
        return None
    parent_token = ctx.parent.params.get("token")
    if isinstance(parent_token, str) and parent_token:
        return parent_token
    return None


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
