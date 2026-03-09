"""Normalized metadata dataclass for SBOM enrichment."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedMetadata:
    """
    Normalized metadata from any data source.

    This dataclass provides a consistent structure for metadata regardless
    of the source (PyPI, ecosyste.ms, deps.dev, PURL parsing, etc.).
    All fields are optional - sources populate what they can provide.

    Per-field attribution is tracked in `field_sources` to know exactly
    which source provided which field.

    CLE (Common Lifecycle Enumeration) fields follow ECMA-428:
    - cle_eos: End of Support date (when standard/active updates end)
    - cle_eol: End of Life date (when all support ends)
    - cle_release_date: Release date for the distribution version
    These are applied as component properties with cle: namespace.
    See: https://sbomify.com/compliance/cle/
    """

    # Core NTIA fields
    description: Optional[str] = None
    licenses: List[str] = field(default_factory=list)  # SPDX identifiers or expressions
    license_texts: Dict[str, str] = field(default_factory=dict)  # license_id -> full text
    supplier: Optional[str] = None

    # URLs
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    documentation_url: Optional[str] = None
    registry_url: Optional[str] = None
    issue_tracker_url: Optional[str] = None
    download_url: Optional[str] = None

    # Maintainer info
    maintainer_name: Optional[str] = None
    maintainer_email: Optional[str] = None

    # CLE (Common Lifecycle Enumeration) fields - ECMA-428
    # Used for distro-level lifecycle dates applied to all packages from that distro
    cle_eos: Optional[str] = None  # End of Support date (ISO 8601)
    cle_eol: Optional[str] = None  # End of Life date (ISO 8601)
    cle_release_date: Optional[str] = None  # Release date (ISO 8601)

    # Source tracking
    source: str = ""  # Primary source (first source with data)
    field_sources: Dict[str, str] = field(default_factory=dict)  # field_name -> source_name

    def merge(self, other: "NormalizedMetadata") -> "NormalizedMetadata":
        """
        Merge another metadata object, filling in missing fields.

        The current object's values take precedence - only missing fields
        are filled from the other object. Per-field attribution is tracked.

        Args:
            other: Another NormalizedMetadata to merge from

        Returns:
            A new NormalizedMetadata with merged values
        """
        # Start with existing field_sources
        merged_sources = dict(self.field_sources)

        # Helper to pick value and track source
        def pick(field_name: str, self_val: Any, other_val: Any, is_list: bool = False) -> Any:
            if is_list:
                if self_val:
                    return self_val
                if other_val and other.source:
                    merged_sources[field_name] = other.source
                return other_val
            else:
                if self_val:
                    return self_val
                if other_val and other.source:
                    merged_sources[field_name] = other.source
                return other_val

        # Merge license_texts (combine both)
        merged_license_texts = dict(self.license_texts)
        for lic_id, text in other.license_texts.items():
            if lic_id not in merged_license_texts:
                merged_license_texts[lic_id] = text

        return NormalizedMetadata(
            # Core fields - use self if present, otherwise other
            description=pick("description", self.description, other.description),
            licenses=pick("licenses", self.licenses, other.licenses, is_list=True),
            license_texts=merged_license_texts,
            supplier=pick("supplier", self.supplier, other.supplier),
            # URLs
            homepage=pick("homepage", self.homepage, other.homepage),
            repository_url=pick("repository_url", self.repository_url, other.repository_url),
            documentation_url=pick("documentation_url", self.documentation_url, other.documentation_url),
            registry_url=pick("registry_url", self.registry_url, other.registry_url),
            issue_tracker_url=pick("issue_tracker_url", self.issue_tracker_url, other.issue_tracker_url),
            download_url=pick("download_url", self.download_url, other.download_url),
            # Maintainer info
            maintainer_name=pick("maintainer_name", self.maintainer_name, other.maintainer_name),
            maintainer_email=pick("maintainer_email", self.maintainer_email, other.maintainer_email),
            # CLE fields
            cle_eos=pick("cle_eos", self.cle_eos, other.cle_eos),
            cle_eol=pick("cle_eol", self.cle_eol, other.cle_eol),
            cle_release_date=pick("cle_release_date", self.cle_release_date, other.cle_release_date),
            # Source tracking - primary source is the first one
            source=self.source or other.source,
            field_sources=merged_sources,
        )

    def has_data(self) -> bool:
        """Check if this metadata has any meaningful data."""
        return bool(
            self.description
            or self.licenses
            or self.supplier
            or self.homepage
            or self.repository_url
            or self.documentation_url
            or self.registry_url
            or self.issue_tracker_url
            or self.download_url
            or self.maintainer_name
            or self.cle_eos
            or self.cle_eol
            or self.cle_release_date
        )
