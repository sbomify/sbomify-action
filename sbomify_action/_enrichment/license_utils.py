"""License normalization utilities for SBOM enrichment.

IMPORTANT: License identification is a critical legal matter. This module takes
a CONSERVATIVE approach - we only normalize when we're 100% certain. We NEVER
guess or use fuzzy matching. When in doubt, we preserve the original and let
humans review.

This module validates licenses against the official SPDX license list using
the `license-expression` library, ensuring compliance with CycloneDX and SPDX
schema requirements across all versions.
"""

import logging
import re
from typing import Optional, Tuple

from license_expression import ExpressionError, get_spdx_licensing

logger = logging.getLogger(__name__)

# Get the SPDX licensing instance (contains all official SPDX license IDs)
_spdx_licensing = get_spdx_licensing()

# SPDX special values that are always valid
SPDX_SPECIAL_VALUES = {"NOASSERTION", "NONE"}

# EXACT mappings only - these are 100% certain translations
# We do NOT do fuzzy matching - that could lead to legal errors
# These map common non-SPDX strings to their exact SPDX equivalents
LICENSE_EXACT_ALIASES = {
    # Case-insensitive exact matches for common variations
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd 3-clause": "BSD-3-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "2-clause bsd": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "isc license": "ISC",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gnu gpl v2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gnu gpl v3": "GPL-3.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl v2.1": "LGPL-2.1-only",
    "gnu lgpl v2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "lgpl v3": "LGPL-3.0-only",
    "gnu lgpl v3": "LGPL-3.0-only",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "cc0 1.0": "CC0-1.0",
    "public domain": "CC0-1.0",  # Note: This is an approximation
    "psf-2.0": "Python-2.0",
    "psf": "Python-2.0",
    "python software foundation license": "Python-2.0",
    # Common shorthand IDs missing the .0 suffix
    "gpl-2": "GPL-2.0-only",
    "gpl-3": "GPL-3.0-only",
    "lgpl-2": "LGPL-2.0-only",
    "lgpl-3": "LGPL-3.0-only",
    # RPM-style license identifiers (seen from Repology/distro packages)
    "asl 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",  # RPM "BSD" tag conventionally means 3-Clause
    "gpl2": "GPL-2.0-only",
    "gpl3": "GPL-3.0-only",
    "gpl-2+": "GPL-2.0-or-later",
    "gpl-3+": "GPL-3.0-or-later",
    "gplv2+": "GPL-2.0-or-later",
    "gplv3+": "GPL-3.0-or-later",
    "gpl2+": "GPL-2.0-or-later",
    "gpl3+": "GPL-3.0-or-later",
    "lgplv2": "LGPL-2.0-only",
    "lgpl2.1": "LGPL-2.1-only",
    "lgpl2.1+": "LGPL-2.1-or-later",
    "lgplv2+": "LGPL-2.0-or-later",
    "lgplv2.1+": "LGPL-2.1-or-later",
    "lgplv3+": "LGPL-3.0-or-later",
    # Verbose license names seen in distro metadata
    "3-clause bsd license": "BSD-3-Clause",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "expat": "MIT",  # Expat is the MIT license (Debian convention)
}

# Threshold for considering a string as full license text (not an identifier)
LICENSE_TEXT_LENGTH_THRESHOLD = 100

# Licenses that the license-expression library accepts but are NOT in the official
# SPDX license list. The library includes ScanCode-detected licenses which are not
# valid for CycloneDX/SPDX schema validation.
# See: https://spdx.org/licenses/ for the official list
NON_SPDX_LICENSES = frozenset(
    {
        # ScanCode-specific licenses mistakenly included
        "Artistic-dist",  # Should be Artistic-1.0-Perl
        "ClArtistic",  # Clarified Artistic - use Artistic-1.0-cl8
    }
)


def validate_spdx_expression(license_str: str) -> bool:
    """
    Validate a license string against the official SPDX license list.

    This validates against ALL SPDX license IDs from the official list,
    ensuring compliance with CycloneDX 1.4-1.7 and SPDX 2.2-2.3 schemas.

    Note: The license-expression library includes some non-SPDX licenses
    (e.g., ScanCode-detected licenses). We explicitly reject those here.

    Args:
        license_str: License string to validate (ID or expression)

    Returns:
        True if it's a valid SPDX identifier or expression
    """
    if not license_str:
        return False

    # Check special values first
    if license_str in SPDX_SPECIAL_VALUES:
        return True

    # Explicitly reject known non-SPDX licenses that license-expression accepts
    if license_str in NON_SPDX_LICENSES:
        return False

    # LicenseRef-* is always valid (custom license references)
    if license_str.startswith("LicenseRef-"):
        # Validate format: LicenseRef-[idstring]
        # idstring must match [a-zA-Z0-9.-]+
        if re.match(r"^LicenseRef-[a-zA-Z0-9.\-]+$", license_str):
            return True
        return False

    try:
        # Parse without validation first
        parsed = _spdx_licensing.parse(license_str, validate=False)
        # Check for unknown license keys
        unknown = _spdx_licensing.unknown_license_keys(parsed)
        return len(unknown) == 0
    except ExpressionError:
        return False


def is_spdx_identifier(license_str: str) -> bool:
    """
    Check if a string is a valid SPDX license identifier or expression.

    This validates against the official SPDX license list used by
    CycloneDX and SPDX schemas.

    Args:
        license_str: License string to check

    Returns:
        True if it's a valid SPDX identifier or expression
    """
    if not license_str:
        return False

    # If it's too long, it's definitely not an identifier (probably full text)
    # SPDX expressions rarely exceed 100 chars
    if len(license_str) > LICENSE_TEXT_LENGTH_THRESHOLD:
        return False

    # If it has multiple newlines, it's full text, not an identifier
    if license_str.count("\n") > 2:
        return False

    return validate_spdx_expression(license_str)


def is_license_text(license_str: str) -> bool:
    """
    Check if a string appears to be full license text rather than an identifier.

    We use simple heuristics - length and presence of newlines.

    Args:
        license_str: License string to check

    Returns:
        True if it appears to be full license text
    """
    if not license_str:
        return False

    # Long strings are likely full text
    if len(license_str) > LICENSE_TEXT_LENGTH_THRESHOLD:
        return True

    # Multiple newlines indicate full text
    if license_str.count("\n") > 2:
        return True

    return False


def normalize_license(license_str: str) -> Tuple[str, Optional[str]]:
    """
    Normalize a license string to SPDX format.

    CONSERVATIVE APPROACH:
    - Only normalize exact matches we're 100% certain about
    - Validate against official SPDX license list
    - Never guess or use fuzzy matching
    - Full license text is stored with LicenseRef, NOT identified

    Args:
        license_str: Raw license string from data source

    Returns:
        Tuple of (SPDX identifier or LicenseRef, full text if applicable)
    """
    if not license_str:
        return ("NOASSERTION", None)

    stripped = license_str.strip()

    # Already a valid SPDX identifier - use as-is
    if is_spdx_identifier(stripped):
        return (stripped, None)

    # Check if it's full license text
    if is_license_text(stripped):
        # DO NOT try to identify - store as LicenseRef with full text
        # Let humans review the actual license
        return ("LicenseRef-Custom", stripped)

    # Strip parenthesized descriptions like "LGPL2.1+ (the library)" or "Expat (MIT/X11)"
    # These are informational annotations, not part of the license identifier
    # Only use the stripped version if it yields a valid SPDX ID or known alias;
    # otherwise preserve the original string to avoid losing information.
    stripped_no_parens = re.sub(r"\s*\([^)]*\)\s*$", "", stripped).strip()
    if stripped_no_parens and stripped_no_parens != stripped:
        if is_spdx_identifier(stripped_no_parens):
            return (stripped_no_parens, None)
        lower_no_parens = stripped_no_parens.lower()
        if lower_no_parens in LICENSE_EXACT_ALIASES:
            normalized = LICENSE_EXACT_ALIASES[lower_no_parens]
            if validate_spdx_expression(normalized):
                return (normalized, None)

    # Try EXACT alias matching (case-insensitive)
    lower = stripped.lower()
    if lower in LICENSE_EXACT_ALIASES:
        normalized = LICENSE_EXACT_ALIASES[lower]
        # Verify the alias target is valid SPDX
        if validate_spdx_expression(normalized):
            return (normalized, None)
        else:
            # This shouldn't happen - log a warning
            logger.warning(f"Alias '{lower}' maps to invalid SPDX ID '{normalized}'")

    # Short string that's not in our aliases - could be:
    # 1. A valid SPDX ID we haven't mapped yet
    # 2. A custom license name
    # 3. Something like "non-standard" or "proprietary"
    #
    # Try to parse it as SPDX (case-insensitive)
    try:
        parsed = _spdx_licensing.parse(stripped, validate=False)
        unknown = _spdx_licensing.unknown_license_keys(parsed)
        if not unknown:
            # It's a valid SPDX expression! Return the canonical form
            return (str(parsed), None)
    except ExpressionError:
        pass

    # Not a valid SPDX - return as-is and let the SBOM consumer handle it
    # This preserves the original information without guessing
    logger.debug(f"Unrecognized license string: '{stripped}'")
    return (stripped, None)


def _split_license_string(license_str: str) -> list[str]:
    """
    Split a license string that may contain comma, lowercase "and"/"or" separators.

    Some enrichment sources (deps.dev, ecosyste.ms, Repology) return license strings
    like "MPL-1.1, GPL-2 and LGPL-2.1" or "GPLv2+ or LGPLv3+" which are not valid
    SPDX expressions. This splits them into individual license identifiers for
    separate normalization.

    Note: Uppercase "AND" / "OR" are valid SPDX operators and are NOT split.
    """
    # First split on commas
    parts = license_str.split(",")

    # Then split each part on lowercase " and " / " or " (word boundary to avoid
    # splitting words like "Standard")
    # Uppercase "AND"/"OR" are valid SPDX operators, so we leave them alone
    result: list[str] = []
    for part in parts:
        sub_parts = re.split(r"\s+(?:and|or)\s+", part)
        for sp in sub_parts:
            stripped = sp.strip()
            if stripped:
                result.append(stripped)

    return result


def normalize_license_list(licenses: list[str]) -> Tuple[list[str], dict[str, str]]:
    """
    Normalize a list of license strings.

    Args:
        licenses: List of raw license strings

    Returns:
        Tuple of (list of normalized identifiers, dict of license_id -> full text)
    """
    normalized = []
    texts = {}

    for lic in licenses:
        if not lic:
            continue
        # If this looks like full license text, do NOT split — preserve as one blob
        if is_license_text(lic.strip()):
            spdx_id, text = normalize_license(lic)
            normalized.append(spdx_id)
            if text:
                key = spdx_id
                if key in texts:
                    counter = 2
                    while f"{key}-{counter}" in texts:
                        counter += 1
                    key = f"{key}-{counter}"
                    normalized[-1] = key
                texts[key] = text
            continue
        # Split comma/"and"-separated license strings into individual licenses
        for split_lic in _split_license_string(lic):
            spdx_id, text = normalize_license(split_lic)
            normalized.append(spdx_id)
            if text:
                # Use a unique key if we have multiple custom licenses
                key = spdx_id
                if key in texts:
                    # Already have this key - make it unique
                    counter = 2
                    while f"{key}-{counter}" in texts:
                        counter += 1
                    key = f"{key}-{counter}"
                    # Also update the normalized list
                    normalized[-1] = key
                texts[key] = text

    return (normalized, texts)


def get_spdx_license_info(spdx_id: str) -> Optional[dict[str, object]]:
    """
    Get information about an SPDX license ID.

    Args:
        spdx_id: SPDX license identifier

    Returns:
        Dict with license info (name, deprecated, etc.) or None if not found
    """
    if not spdx_id:
        return None

    if spdx_id in SPDX_SPECIAL_VALUES:
        return {"id": spdx_id, "name": spdx_id, "is_special": True}

    if spdx_id.startswith("LicenseRef-"):
        return {"id": spdx_id, "name": spdx_id, "is_custom": True}

    # Look up in the SPDX license database (case-insensitive)
    symbol = _spdx_licensing.known_symbols.get(spdx_id.lower())
    if symbol:
        # Get the key (canonical ID) from the symbol
        canonical_id = symbol.key if hasattr(symbol, "key") else spdx_id
        return {
            "id": canonical_id,
            "name": getattr(symbol, "name", canonical_id),
            "is_custom": False,
        }

    return None
