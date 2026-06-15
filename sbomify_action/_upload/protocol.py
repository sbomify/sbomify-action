"""Destination protocol for SBOM upload plugins.

This module defines the core protocol and types for the upload plugin system.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Optional, Protocol

if TYPE_CHECKING:
    from .result import UploadResult

# Supported SBOM formats (same as generation)
SBOMFormat = Literal["cyclonedx", "spdx"]


@dataclass
class UploadInput:
    """
    Input parameters for SBOM upload (SBOM-specific, not destination-specific).

    Attributes:
        sbom_file: Path to the SBOM file to upload
        sbom_format: Format of the SBOM ("cyclonedx" or "spdx")
        component_name: Name of the component (used by destinations like Dependency Track)
        component_version: Version of the component (used by destinations like Dependency Track)
        validate_before_upload: Whether to validate SBOM before uploading
    """

    sbom_file: str
    sbom_format: SBOMFormat
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    validate_before_upload: bool = True

    def __post_init__(self) -> None:
        """Validate input parameters."""
        if not self.sbom_file:
            raise ValueError("sbom_file is required")
        if self.sbom_format not in ("cyclonedx", "spdx"):
            raise ValueError(f"Invalid sbom_format: {self.sbom_format}")


class DestinationConfig(ABC):
    """
    Abstract base class for destination-specific configuration.

    Non-sbomify destinations implement their own config class that loads
    from namespaced environment variables (e.g., DTRACK_API_KEY).

    sbomify uses the existing global config from main.py.
    """

    ENV_PREFIX: str = ""

    @classmethod
    @abstractmethod
    def from_env(cls) -> Optional["DestinationConfig"]:
        """
        Load configuration from environment variables.

        Returns:
            Config instance if required env vars are set, None otherwise.
        """
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if this destination is configured for upload."""
        ...

    @classmethod
    def _get_env(cls, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get environment variable with prefix."""
        full_key = f"{cls.ENV_PREFIX}_{key}" if cls.ENV_PREFIX else key
        return os.getenv(full_key, default)

    @classmethod
    def _get_env_bool(cls, key: str, default: bool = False) -> bool:
        """Get boolean environment variable with prefix."""
        value = cls._get_env(key)
        if value is None:
            return default
        return value.lower() in ("true", "yes", "1", "on")

    @classmethod
    def _get_env_list(cls, key: str, default: list[str] | None = None) -> list[str]:
        """Get list environment variable with prefix."""
        value = cls._get_env(key)
        if value is None or value.strip() == "":
            return [] if default is None else default
        return [t.strip() for t in value.split(",") if t.strip()]


class Destination(Protocol):
    """
    Protocol defining the interface for upload destination plugins.

    Each destination implements this protocol to provide SBOM upload
    to specific targets (sbomify API, Dependency Track, etc.).

    Example:
        class SbomifyDestination:
            name = "sbomify"

            def is_configured(self) -> bool:
                return bool(self._token and self._component_id)

            def upload(self, input: UploadInput) -> UploadResult:
                # Upload to sbomify API and return result
                ...
    """

    @property
    def name(self) -> str:
        """
        Human-readable name of this destination.

        Used for logging, selection, and tracking which destination uploaded the SBOM.
        Examples: "sbomify", "dependency-track", "github-release"
        """
        ...

    def is_configured(self) -> bool:
        """
        Check if this destination is configured and ready for upload.

        For sbomify: checks if token and component_id are set.
        For others: checks if their namespaced env vars are set.

        Returns:
            True if destination can accept uploads
        """
        ...

    def upload(self, input: UploadInput) -> "UploadResult":
        """
        Upload an SBOM to this destination.

        Implementations should:
        1. Validate the SBOM if requested
        2. Upload to the destination
        3. Handle errors gracefully
        4. Return an UploadResult with success/failure info

        Args:
            input: UploadInput with SBOM file and format

        Returns:
            UploadResult with upload outcome and metadata
        """
        ...
