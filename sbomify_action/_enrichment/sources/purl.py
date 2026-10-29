"""PURL-based data source for OS package metadata extraction.

Provides supplier fallback for OS packages (deb, rpm, apk) when registry
lookups fail, using the PURL namespace to derive the distribution supplier.

This ensures NTIA Supplier Name requirement is met for all OS packages.

References:
    NTIA Minimum Elements: https://sbomify.com/compliance/ntia-minimum-elements/
    Schema Crosswalk: https://sbomify.com/compliance/schema-crosswalk/
"""

from typing import Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

# OS package types that can be enriched via PURL parsing
OS_PACKAGE_TYPES = {"deb", "rpm", "apk", "alpm", "ebuild"}

# Mapping of PURL namespace to supplier organization name
NAMESPACE_TO_SUPPLIER: Dict[str, str] = {
    # Debian-based
    "debian": "Debian Project",
    "ubuntu": "Canonical Ltd",
    # Red Hat-based (rpm)
    "redhat": "Red Hat, Inc.",
    "rhel": "Red Hat, Inc.",
    "centos": "CentOS Project",
    "fedora": "Fedora Project",
    "amazon": "Amazon Web Services, Inc. (AWS)",
    "amazonlinux": "Amazon Web Services, Inc. (AWS)",
    "oracle": "Oracle Corporation",
    "rocky": "Rocky Enterprise Software Foundation",
    "almalinux": "AlmaLinux OS Foundation",
    "alma": "AlmaLinux OS Foundation",  # Trivy uses "alma" as OS name
    # Alpine (apk)
    "alpine": "Alpine Linux",
    # Other distros
    "arch": "Arch Linux",
    "gentoo": "Gentoo Foundation",
    "opensuse": "openSUSE Project",
    "suse": "SUSE LLC",
    "wolfi": "Chainguard, Inc.",
    "chainguard": "Chainguard, Inc.",
}

# Mapping of PURL type to distribution platform supplier name
# For language packages, the distribution platform (not the author) is the supplier
PURL_TYPE_TO_SUPPLIER: dict[str, str] = {
    # Language package registries
    "pypi": "Python Package Index (PyPI)",
    "npm": "npm",
    "cargo": "crates.io",
    "maven": "Maven Central",
    "gem": "RubyGems.org",
    "nuget": "NuGet Gallery",
    "golang": "Go Modules",
    "pub": "pub.dev",
    "conan": "Conan Center",
    "composer": "Packagist",
    "hex": "Hex.pm",
    "cocoapods": "CocoaPods",
    "conda": "Anaconda",
    "hackage": "Hackage",
    "swift": "Swift Package Registry",
    # Container registries
    "docker": "Docker Hub",
    "oci": "OCI Registry",
}


def get_supplier_for_purl(purl: PackageURL) -> str | None:
    """Get the appropriate supplier for a PURL.

    For OS packages (deb, rpm, apk), uses NAMESPACE_TO_SUPPLIER based on the
    distribution namespace (e.g., debian, ubuntu, alpine).

    For language packages (pypi, npm, cargo, etc.), uses PURL_TYPE_TO_SUPPLIER
    to return the distribution platform as the supplier.

    Args:
        purl: Parsed PackageURL

    Returns:
        Supplier name or None if not found
    """
    # OS packages use namespace-based supplier (distribution name)
    if purl.type in OS_PACKAGE_TYPES and purl.namespace:
        supplier = NAMESPACE_TO_SUPPLIER.get(purl.namespace.lower())
        if supplier:
            return supplier
        # Fallback for unknown namespaces
        return f"{purl.namespace.title()} Project"

    # Language packages use type-based supplier (platform name)
    return PURL_TYPE_TO_SUPPLIER.get(purl.type)


# Mapping of PURL type/namespace to package tracker URL templates
PACKAGE_TRACKER_URLS: Dict[str, Dict[str, str]] = {
    "deb": {
        "debian": "https://tracker.debian.org/pkg/{name}",
        "ubuntu": "https://launchpad.net/ubuntu/+source/{name}",
    },
    "rpm": {
        "fedora": "https://packages.fedoraproject.org/pkgs/{name}",
        "centos": "https://git.centos.org/rpms/{name}",
        "redhat": "https://access.redhat.com/downloads/content/package-browser",
        "rhel": "https://access.redhat.com/downloads/content/package-browser",
        "amazon": "https://docs.aws.amazon.com/linux/",
        "rocky": "https://pkgs.org/search/?q={name}",
        "almalinux": "https://pkgs.org/search/?q={name}",
    },
    "apk": {
        "alpine": "https://pkgs.alpinelinux.org/package/edge/main/x86_64/{name}",
        "wolfi": "https://github.com/wolfi-dev/os/tree/main/{name}",
        "chainguard": "https://images.chainguard.dev/directory/image/{name}/overview",
    },
}


class PURLSource:
    """
    Data source that extracts metadata from PURL components.

    This source doesn't make API calls - it extracts supplier and
    package tracker URLs directly from the PURL namespace and type.
    Works for OS package types (deb, rpm, apk).

    Priority: 70 (medium-low - no API calls, basic metadata only)
    Supports: pkg:deb/*, pkg:rpm/*, pkg:apk/* and similar OS packages
    """

    @property
    def name(self) -> str:
        return "purl"

    @property
    def priority(self) -> int:
        # Tier 3: Fallback sources (70-99) - Last resort, basic or rate-limited
        return 70

    # Still asked about a package no registry publishes (see registry.py).
    offline = True

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in OS_PACKAGE_TYPES

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Extract metadata from PURL components.

        This doesn't make network calls - it extracts supplier and
        homepage URL from the PURL namespace.

        Args:
            purl: Parsed PackageURL for an OS package
            session: requests.Session (unused, for interface compatibility)

        Returns:
            NormalizedMetadata if extraction succeeds, None otherwise
        """
        if purl.type not in OS_PACKAGE_TYPES:
            return None

        supplier = self._get_supplier(purl)
        homepage = self._get_package_tracker_url(purl)

        if not supplier and not homepage:
            return None

        logger.debug(
            f"Extracted PURL metadata for {purl.name}: supplier={supplier}, homepage={'yes' if homepage else 'no'}"
        )

        # Build field_sources for attribution
        field_sources = {}
        if supplier:
            field_sources["supplier"] = self.name
            # For OS packages, the distribution is also the maintainer/publisher
            field_sources["maintainer_name"] = self.name
        if homepage:
            field_sources["homepage"] = self.name

        return NormalizedMetadata(
            supplier=supplier,
            # For OS packages, distribution is the publisher (maintainer_name -> component.publisher)
            maintainer_name=supplier,
            homepage=homepage,
            source=self.name,
            field_sources=field_sources,
        )

    def _get_supplier(self, purl: PackageURL) -> Optional[str]:
        """
        Get supplier organization name from PURL namespace.

        Args:
            purl: Parsed PackageURL

        Returns:
            Supplier name or None if not found
        """
        if purl.namespace:
            # Check our mapping first
            supplier = NAMESPACE_TO_SUPPLIER.get(purl.namespace.lower())
            if supplier:
                return supplier
            # Fall back to capitalizing the namespace
            return f"{purl.namespace.title()} Project"
        return None

    def _get_package_tracker_url(self, purl: PackageURL) -> Optional[str]:
        """
        Get package tracker URL for OS packages.

        Args:
            purl: Parsed PackageURL

        Returns:
            Package tracker URL or None if not available
        """
        if purl.type in PACKAGE_TRACKER_URLS:
            type_urls = PACKAGE_TRACKER_URLS[purl.type]
            if purl.namespace and purl.namespace.lower() in type_urls:
                url_template = type_urls[purl.namespace.lower()]
                return url_template.format(name=purl.name)
        return None
