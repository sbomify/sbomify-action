"""AugmentationMetadata dataclass for normalized augmentation data."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AugmentationMetadata:
    """
    Normalized metadata for SBOM augmentation.

    This dataclass represents the canonical format for augmentation data
    from any provider. It includes fields for NTIA Minimum Elements and
    CISA 2025 requirements.

    Attributes:
        supplier: Supplier information (name, urls, contacts)
        manufacturer: Manufacturer information (name, urls, contacts, address)
        authors: List of author information
        licenses: List of license data (strings or dicts)
        lifecycle_phase: CISA 2025 Generation Context (build, post-build, operations, etc.)
        source: Name of the provider that supplied this metadata

        VCS fields (added by CI providers or sbomify.json config):
        vcs_url: Repository URL (e.g., https://github.com/owner/repo)
        vcs_commit_sha: Full commit SHA
        vcs_ref: Branch or tag name (e.g., main, refs/heads/main, v1.0.0)
        vcs_commit_url: URL to the specific commit

        Security and support fields (CRA compliance):
        security_contact: URL/email for security vulnerability reporting
        support_period_end: ISO-8601 date when security support ends (YYYY-MM-DD)

        Lifecycle date fields (from sbomify API):
        release_date: ISO-8601 date when the component was released (YYYY-MM-DD)
        end_of_life: ISO-8601 date when all support ends (YYYY-MM-DD)
    """

    supplier: Optional[Dict[str, Any]] = None
    manufacturer: Optional[Dict[str, Any]] = None
    authors: Optional[List[Dict[str, Any]]] = None
    licenses: Optional[List[Any]] = None
    lifecycle_phase: Optional[str] = None
    source: Optional[str] = None

    # VCS fields for CI environment enrichment
    vcs_url: Optional[str] = None
    vcs_commit_sha: Optional[str] = None
    vcs_ref: Optional[str] = None
    vcs_commit_url: Optional[str] = None

    # Security and support fields (CRA compliance)
    security_contact: Optional[str] = None  # URL/email for security vulnerability reporting
    support_period_end: Optional[str] = None  # ISO-8601 date when support ends (YYYY-MM-DD)

    # Lifecycle date fields (from sbomify API)
    release_date: Optional[str] = None  # ISO-8601 date when released (YYYY-MM-DD)
    end_of_life: Optional[str] = None  # ISO-8601 date when all support ends (YYYY-MM-DD)

    # Additional fields that may be added in the future
    _extra: Dict[str, Any] = field(default_factory=dict)

    def has_data(self) -> bool:
        """Check if this metadata contains any meaningful data."""
        return any(
            [
                self.supplier,
                self.manufacturer,
                self.authors,
                self.licenses,
                self.lifecycle_phase,
                self.vcs_url,
                self.vcs_commit_sha,
                self.vcs_ref,
                self.vcs_commit_url,
                self.security_contact,
                self.support_period_end,
                self.release_date,
                self.end_of_life,
            ]
        )

    def merge(self, other: "AugmentationMetadata") -> "AugmentationMetadata":
        """Merge another metadata instance into this one.

        The current instance's values take precedence (are not overwritten).
        Only missing fields are filled from the other instance.

        Provider-priority semantics. The augmentation registry sorts
        providers by ``priority`` ascending and folds results with
        ``result.merge(later)`` — so the **earlier** provider (lower
        numeric priority) always wins on any field both set. Concretely:

        * ``json_config`` (priority 10) beats ``github-actions`` /
          ``gitlab-ci`` (priority 20) beats ``sbomify-api`` (priority 50).
        * Lower-priority providers only fill fields higher-priority
          providers left empty — they never override an earlier choice.

        New providers slotting in between existing priorities inherit
        the same contract.

        Args:
            other: Another AugmentationMetadata to merge from

        Returns:
            New AugmentationMetadata with merged values
        """
        # Merge sources for attribution
        sources = []
        if self.source:
            sources.append(self.source)
        if other.source and other.source not in sources:
            sources.append(other.source)
        merged_source = ", ".join(sources) if sources else None

        return AugmentationMetadata(
            supplier=self.supplier if self.supplier else other.supplier,
            manufacturer=self.manufacturer if self.manufacturer else other.manufacturer,
            authors=self.authors if self.authors else other.authors,
            licenses=self.licenses if self.licenses else other.licenses,
            lifecycle_phase=self.lifecycle_phase if self.lifecycle_phase else other.lifecycle_phase,
            source=merged_source,
            # VCS fields
            vcs_url=self.vcs_url if self.vcs_url else other.vcs_url,
            vcs_commit_sha=self.vcs_commit_sha if self.vcs_commit_sha else other.vcs_commit_sha,
            vcs_ref=self.vcs_ref if self.vcs_ref else other.vcs_ref,
            vcs_commit_url=self.vcs_commit_url if self.vcs_commit_url else other.vcs_commit_url,
            # Security and support fields
            security_contact=self.security_contact if self.security_contact else other.security_contact,
            support_period_end=self.support_period_end if self.support_period_end else other.support_period_end,
            # Lifecycle date fields
            release_date=self.release_date if self.release_date else other.release_date,
            end_of_life=self.end_of_life if self.end_of_life else other.end_of_life,
            _extra={**other._extra, **self._extra},  # self takes precedence
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format compatible with existing augmentation functions.

        Returns:
            Dictionary with augmentation data
        """
        result: Dict[str, Any] = {}

        if self.supplier:
            result["supplier"] = self.supplier
        if self.manufacturer:
            result["manufacturer"] = self.manufacturer
        if self.authors:
            result["authors"] = self.authors
        if self.licenses:
            result["licenses"] = self.licenses
        if self.lifecycle_phase:
            result["lifecycle_phase"] = self.lifecycle_phase

        # VCS fields
        if self.vcs_url:
            result["vcs_url"] = self.vcs_url
        if self.vcs_commit_sha:
            result["vcs_commit_sha"] = self.vcs_commit_sha
        if self.vcs_ref:
            result["vcs_ref"] = self.vcs_ref
        if self.vcs_commit_url:
            result["vcs_commit_url"] = self.vcs_commit_url

        # Security and support fields
        if self.security_contact:
            result["security_contact"] = self.security_contact
        if self.support_period_end:
            result["support_period_end"] = self.support_period_end

        # Lifecycle date fields
        if self.release_date:
            result["release_date"] = self.release_date
        if self.end_of_life:
            result["end_of_life"] = self.end_of_life

        # Include any extra fields
        result.update(self._extra)

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: Optional[str] = None) -> "AugmentationMetadata":
        """
        Create AugmentationMetadata from a dictionary.

        Handles both config file field names and sbomify API field names:
        - API uses 'end_of_support' -> maps to 'support_period_end'

        Args:
            data: Dictionary with augmentation data
            source: Name of the source that provided this data

        Returns:
            New AugmentationMetadata instance
        """
        known_keys = {
            "supplier",
            "manufacturer",
            "authors",
            "licenses",
            "lifecycle_phase",
            "vcs_url",
            "vcs_commit_sha",
            "vcs_ref",
            "vcs_commit_url",
            "security_contact",
            "support_period_end",
            "release_date",
            "end_of_life",
            # API field names (mapped to internal names)
            "end_of_support",  # -> support_period_end
            # API fields handled by SbomifyApiProvider (extracted to direct fields)
            "contact_profile",  # Extracted to supplier/manufacturer/authors/security_contact
            "contact_profile_id",
            "uses_custom_contact",
            "id",  # Component ID from API
            "name",  # Component name from API
        }
        extra = {k: v for k, v in data.items() if k not in known_keys}

        # Map API field names to internal names
        # API uses 'end_of_support', we use 'support_period_end'
        # Prefer explicit support_period_end, fall back to API's end_of_support
        support_period_end = data.get("support_period_end") or data.get("end_of_support")

        return cls(
            supplier=data.get("supplier"),
            manufacturer=data.get("manufacturer"),
            authors=data.get("authors"),
            licenses=data.get("licenses"),
            lifecycle_phase=data.get("lifecycle_phase"),
            source=source,
            vcs_url=data.get("vcs_url"),
            vcs_commit_sha=data.get("vcs_commit_sha"),
            vcs_ref=data.get("vcs_ref"),
            vcs_commit_url=data.get("vcs_commit_url"),
            security_contact=data.get("security_contact"),
            support_period_end=support_period_end,
            release_date=data.get("release_date"),
            end_of_life=data.get("end_of_life"),
            _extra=extra,
        )
