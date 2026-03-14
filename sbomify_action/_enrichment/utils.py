"""Shared utilities for enrichment sources."""

from typing import Optional, Tuple
from urllib.parse import urlencode

from packageurl import PackageURL


def purl_to_string(purl: PackageURL) -> str:
    """
    Convert a PackageURL to a string with @ instead of %40 in the namespace.

    The standard PackageURL.to_string() method URL-encodes @ as %40, which is
    the canonical form per PURL spec. However, this causes double-encoding issues
    when the PURL is used as a query parameter in API calls (%40 → %2540).

    This function outputs the PURL with literal @ characters, which will be
    correctly single-encoded by HTTP clients when used in API calls.

    When to use each:
        - str(purl) or purl.to_string(): For SBOM output (canonical %40 form)
        - purl_to_string(purl): For API query parameters (literal @ form)

    Args:
        purl: Parsed PackageURL object

    Returns:
        PURL string with @ instead of %40
    """
    # Build the PURL string manually with @ instead of %40
    # Format: pkg:type/namespace/name@version?qualifiers#subpath
    parts = [f"pkg:{purl.type}"]
    if purl.namespace:
        parts.append(f"/{purl.namespace}")
    parts.append(f"/{purl.name}")
    if purl.version:
        parts.append(f"@{purl.version}")
    if purl.qualifiers:
        # Qualifiers need proper encoding; doseq=True handles list/tuple values correctly
        qual_str = urlencode(purl.qualifiers, doseq=True)
        parts.append(f"?{qual_str}")
    if purl.subpath:
        parts.append(f"#{purl.subpath}")
    return "".join(parts)


def get_qualified_name(purl: PackageURL, separator: str = ":") -> str:
    """
    Get the fully qualified package name for APIs that need namespace.

    For packages with namespaces (like Maven's group:artifact), this combines
    the namespace and name with the specified separator.

    Args:
        purl: Parsed PackageURL
        separator: Character to join namespace and name (default ":")
                   - Use ":" for deps.dev (Maven)
                   - Use "/" for ClearlyDefined

    Returns:
        Qualified name string, e.g. "org.apache.commons:commons-lang3"
    """
    if purl.namespace:
        return f"{purl.namespace}{separator}{purl.name}"
    return str(purl.name)


def parse_author_string(author_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse an author string which may be in format "Name <email>".

    This is a common format used by pub.dev (Dart), npm, and other package managers.

    Args:
        author_str: Author string like "John Doe <john@example.com>" or just "John Doe"

    Returns:
        Tuple of (name, email) where either may be None
    """
    if not author_str:
        return None, None

    author_str = author_str.strip()

    # Check for "Name <email>" format
    if "<" in author_str and ">" in author_str:
        try:
            lt_idx = author_str.index("<")
            gt_idx = author_str.index(">")
            if lt_idx < gt_idx:
                name_part = author_str[:lt_idx].strip()
                email_part = author_str[lt_idx + 1 : gt_idx].strip()
                return name_part or None, email_part or None
        except (ValueError, IndexError):
            pass

    # Just a name (no email)
    return author_str, None
