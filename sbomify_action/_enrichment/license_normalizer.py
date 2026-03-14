"""License normalization library for SBOM enrichment.

This module provides conservative, accuracy-focused license normalization
for Linux distribution packages (Debian/Ubuntu DEP-5 and RPM formats).

CONSERVATIVE APPROACH: We only return licenses we're 100% certain about.
It's better to return None than to return an incorrect license.

This module is used by:
- The license database generator (sbomify_action/_enrichment/license_db_generator.py)
- The enrichment pipeline (sbomify_action/_enrichment/)
"""

import re
from dataclasses import dataclass
from typing import Dict, Iterator, Optional, Set

from license_expression import ExpressionError, get_spdx_licensing

# SPDX licensing instance for validation
_spdx_licensing = get_spdx_licensing()


# =============================================================================
# License Alias Mappings
# =============================================================================

# RPM-specific license aliases (Fedora/RHEL use these)
# ONLY include licenses we are 100% certain about the mapping
RPM_LICENSE_ALIASES: Dict[str, str] = {
    # GPL variants
    "gplv2": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later",
    "gpl+": "GPL-1.0-or-later",
    "gpl": "GPL-1.0-only",
    # LGPL variants
    "lgplv2": "LGPL-2.0-only",
    "lgplv2+": "LGPL-2.1-or-later",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv2.1+": "LGPL-2.1-or-later",
    "lgplv3": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later",
    # BSD variants
    "bsd": "BSD-3-Clause",
    "bsd with advertising": "BSD-4-Clause",
    # MIT
    "mit": "MIT",
    "x11": "X11",
    # Apache
    "asl 2.0": "Apache-2.0",
    "asl 1.1": "Apache-1.1",
    # MPL
    "mplv1.0": "MPL-1.0",
    "mplv1.1": "MPL-1.1",
    "mplv2.0": "MPL-2.0",
    # Others
    "artistic": "Artistic-1.0",
    "artistic 2.0": "Artistic-2.0",
    "public domain": "CC0-1.0",
    "cc0": "CC0-1.0",
    "zlib": "Zlib",
    "openssl": "OpenSSL",
    "php": "PHP-3.01",
    "ruby": "Ruby",
    "psfl": "Python-2.0",
    "psf": "Python-2.0",
    "python": "Python-2.0",
    # wxWidgets is LGPL-2.0-or-later WITH wxWindows-exception-3.1, too complex for a simple alias
    "boost": "BSL-1.0",
    "unlicense": "Unlicense",
    "wtfpl": "WTFPL",
    "isc": "ISC",
    "ncsa": "NCSA",
    "ofl": "OFL-1.1",
    "cc-by": "CC-BY-4.0",
    "cc-by-sa": "CC-BY-SA-4.0",
    "epl": "EPL-1.0",
    "epl 2.0": "EPL-2.0",
    "cddl": "CDDL-1.0",
    "agplv3": "AGPL-3.0-only",
    "agplv3+": "AGPL-3.0-or-later",
    # Additional well-known licenses
    "afl": "AFL-2.1",
    "ftl": "FTL",
    "bitstream vera": "Bitstream-Vera",
}

# DEP-5 license short names to SPDX mapping
DEP5_LICENSE_ALIASES: Dict[str, str] = {
    # GPL variants
    "gpl-1": "GPL-1.0-only",
    "gpl-1+": "GPL-1.0-or-later",
    "gpl-2": "GPL-2.0-only",
    "gpl-2+": "GPL-2.0-or-later",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-3": "GPL-3.0-only",
    "gpl-3+": "GPL-3.0-or-later",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0+": "GPL-3.0-or-later",
    # LGPL variants
    "lgpl-2": "LGPL-2.0-only",
    "lgpl-2+": "LGPL-2.0-or-later",
    "lgpl-2.0": "LGPL-2.0-only",
    "lgpl-2.0+": "LGPL-2.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgpl-3": "LGPL-3.0-only",
    "lgpl-3+": "LGPL-3.0-or-later",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0+": "LGPL-3.0-or-later",
    # AGPL
    "agpl-3": "AGPL-3.0-only",
    "agpl-3+": "AGPL-3.0-or-later",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl-3.0+": "AGPL-3.0-or-later",
    # BSD variants
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd-4-clause": "BSD-4-Clause",
    # Apache
    "apache-2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    # MIT/ISC
    "mit": "MIT",
    "expat": "MIT",
    "isc": "ISC",
    # MPL
    "mpl-1.0": "MPL-1.0",
    "mpl-1.1": "MPL-1.1",
    "mpl-2.0": "MPL-2.0",
    # Others
    "artistic": "Artistic-1.0",
    "artistic-1.0": "Artistic-1.0",
    "artistic-2.0": "Artistic-2.0",
    "artistic-dist": "Artistic-1.0-Perl",  # Debian variant of Artistic license
    "zlib": "Zlib",
    "zlib/libpng": "Zlib",
    "public-domain": "CC0-1.0",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "cc-by-3.0": "CC-BY-3.0",
    "cc-by-4.0": "CC-BY-4.0",
    "cc-by-sa-3.0": "CC-BY-SA-3.0",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "wtfpl": "WTFPL",
    "unlicense": "Unlicense",
    "boost-1.0": "BSL-1.0",
    "bsl-1.0": "BSL-1.0",
    "epl-1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "openssl": "OpenSSL",
    "python-2.0": "Python-2.0",
    "psf-2": "Python-2.0",
    "ruby": "Ruby",
    "ofl-1.1": "OFL-1.1",
    "curl": "curl",
    "unicode": "Unicode-DFS-2016",
}

# Combined aliases for general use
ALL_LICENSE_ALIASES: Dict[str, str] = {**RPM_LICENSE_ALIASES, **DEP5_LICENSE_ALIASES}


# =============================================================================
# SPDX Validation
# =============================================================================


def validate_spdx_expression(license_str: str) -> bool:
    """
    Validate a license string against the SPDX license list.

    Args:
        license_str: License string to validate

    Returns:
        True if valid SPDX expression, False otherwise
    """
    if not license_str:
        return False

    # Special values
    if license_str in {"NOASSERTION", "NONE"}:
        return True

    # LicenseRef-* is always valid
    if license_str.startswith("LicenseRef-"):
        return bool(re.match(r"^LicenseRef-[a-zA-Z0-9.\-]+$", license_str))

    try:
        parsed = _spdx_licensing.parse(license_str, validate=False)
        unknown = _spdx_licensing.unknown_license_keys(parsed)
        return len(unknown) == 0
    except ExpressionError:
        return False


# =============================================================================
# License Normalization
# =============================================================================


@dataclass
class NormalizationResult:
    """Result of license normalization."""

    spdx: Optional[str]  # Validated SPDX expression, or None if failed
    raw: str  # Original license string
    confidence: str  # "high" or "low"


def _normalize_component(component: str, aliases: Dict[str, str]) -> Optional[str]:
    """
    Normalize a single license component (no AND/OR).

    Args:
        component: Single license identifier
        aliases: Alias mapping to use

    Returns:
        SPDX identifier or None if cannot normalize
    """
    component = component.strip()
    if not component:
        return None

    # Handle parenthesized expressions recursively
    if component.startswith("(") and component.endswith(")"):
        inner = component[1:-1].strip()
        inner_result = _normalize_expression(inner, aliases)
        if inner_result:
            return f"({inner_result})"
        return None

    # Check alias map (case-insensitive)
    lower = component.lower()
    if lower in aliases:
        return aliases[lower]

    # Check if already valid SPDX
    if validate_spdx_expression(component):
        return component

    return None


def _normalize_expression(expr: str, aliases: Dict[str, str]) -> Optional[str]:
    """
    Normalize a license expression (may contain AND/OR).

    Args:
        expr: License expression string
        aliases: Alias mapping to use

    Returns:
        SPDX expression or None if cannot normalize
    """
    if not expr:
        return None

    expr = expr.strip()

    # Check if already valid SPDX
    if validate_spdx_expression(expr):
        return expr

    # Check alias for simple cases
    lower = expr.lower()
    if lower in aliases:
        return aliases[lower]

    # Convert operators to SPDX format
    normalized = expr
    normalized = re.sub(r"\s+and\s+", " AND ", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+or\s+", " OR ", normalized, flags=re.IGNORECASE)

    # If no operators, try as single component
    if " AND " not in normalized and " OR " not in normalized:
        return _normalize_component(normalized, aliases)

    # Split on AND/OR, respecting parentheses
    parts = []
    current = ""
    paren_depth = 0

    tokens = re.split(r"(\s+AND\s+|\s+OR\s+)", normalized)
    for token in tokens:
        token_upper = token.strip().upper()
        if token_upper in ("AND", "OR") and paren_depth == 0:
            if current.strip():
                parts.append(current.strip())
            parts.append(token_upper)
            current = ""
        else:
            current += token
            paren_depth += token.count("(") - token.count(")")

    if current.strip():
        parts.append(current.strip())

    # Normalize each component - ALL must succeed
    normalized_parts = []
    for part in parts:
        if part in ("AND", "OR"):
            normalized_parts.append(part)
        else:
            norm = _normalize_component(part, aliases)
            if norm is None:
                return None
            normalized_parts.append(norm)

    if not normalized_parts:
        return None

    result = " ".join(normalized_parts)

    # Final validation
    if validate_spdx_expression(result):
        return result

    return None


def normalize_rpm_license(raw_license: str) -> NormalizationResult:
    """
    Normalize an RPM license string to SPDX format.

    Uses RPM-specific aliases (GPLv2+, ASL 2.0, etc.)

    Args:
        raw_license: License string from RPM metadata

    Returns:
        NormalizationResult with SPDX expression or None
    """
    if not raw_license:
        return NormalizationResult(spdx=None, raw="", confidence="low")

    spdx = _normalize_expression(raw_license, RPM_LICENSE_ALIASES)

    return NormalizationResult(
        spdx=spdx,
        raw=raw_license,
        confidence="high" if spdx else "low",
    )


def normalize_dep5_license(raw_license: str) -> NormalizationResult:
    """
    Normalize a DEP-5 license string to SPDX format.

    Uses DEP-5/Debian-specific aliases (GPL-2+, Expat, etc.)

    Args:
        raw_license: License string from DEP-5 copyright file

    Returns:
        NormalizationResult with SPDX expression or None
    """
    if not raw_license:
        return NormalizationResult(spdx=None, raw="", confidence="low")

    spdx = _normalize_expression(raw_license, DEP5_LICENSE_ALIASES)

    return NormalizationResult(
        spdx=spdx,
        raw=raw_license,
        confidence="high" if spdx else "low",
    )


def normalize_license(raw_license: str) -> NormalizationResult:
    """
    Normalize a license string to SPDX format using all known aliases.

    Tries both RPM and DEP-5 aliases.

    Args:
        raw_license: License string from any source

    Returns:
        NormalizationResult with SPDX expression or None
    """
    if not raw_license:
        return NormalizationResult(spdx=None, raw="", confidence="low")

    spdx = _normalize_expression(raw_license, ALL_LICENSE_ALIASES)

    return NormalizationResult(
        spdx=spdx,
        raw=raw_license,
        confidence="high" if spdx else "low",
    )


# =============================================================================
# DEP-5 Copyright File Parsing
# =============================================================================


@dataclass
class DEP5File:
    """Parsed DEP-5 copyright file."""

    is_dep5: bool = False
    format_url: Optional[str] = None
    licenses: Optional[Set[str]] = None

    def __post_init__(self) -> None:
        if self.licenses is None:
            self.licenses = set()


def parse_deb822_stanzas(text: str) -> Iterator[Dict[str, str]]:
    """
    Parse RFC 822-style stanzas from text.

    Yields:
        Dict of field name -> value for each stanza
    """
    cur: Dict[str, str] = {}
    last_key: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()

        if not line.strip():
            if cur:
                yield cur
                cur = {}
                last_key = None
            continue

        if line.startswith((" ", "\t")) and last_key:
            cur[last_key] = cur[last_key] + "\n" + line[1:]
            continue

        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            # Normalize UK spelling of "Licence" to "License"
            if k.lower() == "licence":
                k = "License"
            v = v.strip()
            cur[k] = v
            last_key = k

    if cur:
        yield cur


def parse_dep5_copyright(text: str) -> DEP5File:
    """
    Parse a Debian copyright file.

    Args:
        text: Contents of the copyright file

    Returns:
        DEP5File with parsed information
    """
    result = DEP5File()

    stanzas = list(parse_deb822_stanzas(text))
    if not stanzas:
        return result

    # Check if first stanza has Format field (DEP-5 indicator)
    header = stanzas[0]
    if "Format" in header:
        format_url = header["Format"]
        if "copyright-format" in format_url.lower() or "dep5" in format_url.lower():
            result.is_dep5 = True
            result.format_url = format_url

    if not result.is_dep5:
        return result

    # Extract all License: fields
    for stanza in stanzas:
        if "License" in stanza:
            license_field = stanza["License"]
            # Take first line only (rest is license text)
            license_id = license_field.split("\n")[0].strip()
            if license_id and not license_id.startswith("."):
                assert result.licenses is not None  # guaranteed by __post_init__
                result.licenses.add(license_id)

    return result


def extract_dep5_license(text: str) -> Optional[str]:
    """
    Extract and normalize license from a DEP-5 copyright file.

    CONSERVATIVE: Only returns if ALL licenses can be validated.

    Args:
        text: Contents of the copyright file

    Returns:
        Validated SPDX expression or None
    """
    dep5 = parse_dep5_copyright(text)

    if not dep5.is_dep5 or not dep5.licenses:
        return None

    # Normalize ALL licenses - if ANY fails, reject entire file
    normalized = []
    for lic in sorted(dep5.licenses):
        result = normalize_dep5_license(lic)
        if result.spdx:
            normalized.append(result.spdx)
        else:
            # Cannot normalize - reject entire file
            return None

    if not normalized:
        return None

    if len(normalized) == 1:
        return normalized[0]

    # Multiple licenses - create AND expression
    combined = " AND ".join(f"({n})" if " " in n else n for n in sorted(set(normalized)))

    # Final validation
    if validate_spdx_expression(combined):
        return combined

    return None
