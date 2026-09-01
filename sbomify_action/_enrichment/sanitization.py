"""Input sanitization utilities for enrichment data.

This module provides sanitization functions to protect against injection attacks
when using data from external package registries.

Security considerations:
- URLs: Allow http/https and SPDX VCS schemes (git, git+ssh, git+https, git+http), validate format
- Strings: Remove control characters, enforce length limits
- Emails: Basic format validation
"""

import re
from typing import Optional
from urllib.parse import urlparse

from sbomify_action._runtime.vcs_url import (
    _KNOWN_GIT_HOSTS as _KNOWN_GIT_HOSTS,
)

# Both moved to _runtime so the CI platforms can share the predicate without
# importing this module (which pulls in console and logging_config).
# Re-exported because they were importable from here.
from sbomify_action._runtime.vcs_url import (
    _is_known_git_host as _is_known_git_host,
)
from sbomify_action.console import get_transformation_tracker
from sbomify_action.logging_config import logger

# Maximum lengths for various fields
MAX_DESCRIPTION_LENGTH = 4096
MAX_SUPPLIER_LENGTH = 256
MAX_URL_LENGTH = 2048
MAX_LICENSE_LENGTH = 512
MAX_EMAIL_LENGTH = 254

# Allowed URL schemes
# Includes SPDX VCS URL schemes: git, git+ssh, git+https, git+http
# See: https://spdx.github.io/spdx-spec/v2.3/package-information/
ALLOWED_URL_SCHEMES = {"http", "https", "git", "git+ssh", "git+https", "git+http"}

# Control characters to remove (except newline/tab in descriptions)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Pattern for basic email validation
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# Pattern to detect HTML-like content in URLs (potential XSS vectors)
HTML_PATTERN = re.compile(r"<[a-zA-Z][^>]*>", re.IGNORECASE)

# Pattern for SSH-style git URLs: git@host:path
_SSH_GIT_PATTERN = re.compile(r"^git@([^:]+):(.+)$")

# Pattern for Maven SCM URLs: scm:git:...
_SCM_GIT_PATTERN = re.compile(r"^scm:git:(.+)$", re.IGNORECASE)

# Known git hosting providers - we can safely assume URLs from these are git repos
# Track already-logged VCS normalizations to avoid duplicate messages
_logged_vcs_normalizations: set[str] = set()


def _log_vcs_normalization(original: str, normalized: str) -> None:
    """Record VCS URL normalization for attestation."""
    key = f"{original} -> {normalized}"
    if key not in _logged_vcs_normalizations:
        _logged_vcs_normalizations.add(key)
        # Record for attestation via transformation tracker
        tracker = get_transformation_tracker()
        tracker.record_vcs_normalization(original, normalized)


def sanitize_string(
    value: Optional[str],
    max_length: int = MAX_DESCRIPTION_LENGTH,
    allow_newlines: bool = True,
    field_name: str = "field",
) -> Optional[str]:
    """
    Sanitize a string value from external sources.

    Removes control characters, enforces length limits, and normalizes whitespace.

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to preserve newlines (for descriptions)
        field_name: Name of field for logging

    Returns:
        Sanitized string or None if input was None/empty
    """
    if value is None:
        return None

    if not isinstance(value, str):
        logger.warning(f"Non-string value for {field_name}: {type(value)}")
        value = str(value)

    # Remove control characters
    sanitized = CONTROL_CHAR_PATTERN.sub("", value)

    # Optionally remove newlines
    if not allow_newlines:
        sanitized = sanitized.replace("\n", " ").replace("\r", " ")

    # Normalize whitespace (collapse multiple spaces)
    sanitized = " ".join(sanitized.split()) if not allow_newlines else sanitized

    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()

    # Enforce length limit
    if len(sanitized) > max_length:
        logger.debug(f"Truncating {field_name} from {len(sanitized)} to {max_length} chars")
        # Reserve space for ellipsis so the final length does not exceed max_length
        if max_length > 3:
            truncation_limit = max_length - 3
            base = sanitized[:truncation_limit]

            # Try not to cut a word in half if there is a space to break on
            last_space = base.rfind(" ")
            if last_space > 0:
                base = base[:last_space]

            sanitized = base.rstrip() + "..."
        else:
            # For very small max_length, just hard-truncate without ellipsis
            sanitized = sanitized[:max_length]

    return sanitized if sanitized else None


def sanitize_url(value: Optional[str], field_name: str = "url") -> Optional[str]:
    """
    Sanitize and validate a URL from external sources.

    Allows http/https URLs and SPDX VCS URL schemes (git, git+ssh, git+https, git+http).
    Validates format and enforces length limits.

    Args:
        value: The URL to sanitize
        field_name: Name of field for logging

    Returns:
        Sanitized URL or None if invalid/empty
    """
    tracker = get_transformation_tracker()

    if value is None:
        return None

    if not isinstance(value, str):
        # Record for attestation - non-string values are data quality issues
        tracker.record_url_rejected(field_name, str(value)[:100], f"non-string type: {type(value).__name__}")
        return None

    # Strip whitespace
    url = value.strip()

    if not url:
        return None

    # Enforce length limit
    if len(url) > MAX_URL_LENGTH:
        tracker.record_url_rejected(field_name, url[:100], f"too long: {len(url)} chars")
        return None

    # Parse and validate URL
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
            tracker.record_url_rejected(field_name, url[:100], f"disallowed scheme: {parsed.scheme}")
            return None

        # Must have a netloc (host)
        if not parsed.netloc:
            tracker.record_url_rejected(field_name, url[:100], "no host")
            return None

        # Reject URLs with HTML-like content (potential XSS vectors)
        if HTML_PATTERN.search(url):
            tracker.record_url_rejected(field_name, url[:100], "contains HTML-like content")
            return None

        # Reconstruct URL to normalize it
        # This also helps prevent some injection attempts
        return url

    except Exception as e:
        tracker.record_url_rejected(field_name, url[:100], f"parse error: {e}")
        return None


def sanitize_email(value: Optional[str], field_name: str = "email") -> Optional[str]:
    """
    Sanitize and validate an email address.

    Args:
        value: The email to sanitize
        field_name: Name of field for logging

    Returns:
        Sanitized email or None if invalid/empty
    """
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    email = value.strip()

    if not email:
        return None

    # Enforce length limit
    if len(email) > MAX_EMAIL_LENGTH:
        logger.warning(f"Email too long for {field_name}: {len(email)} chars")
        return None

    # Basic format validation
    if not EMAIL_PATTERN.match(email):
        # Don't log the actual email for privacy
        logger.debug(f"Invalid email format for {field_name}")
        return None

    return email


def sanitize_description(value: Optional[str]) -> Optional[str]:
    """Sanitize a description field (allows newlines)."""
    return sanitize_string(value, MAX_DESCRIPTION_LENGTH, allow_newlines=True, field_name="description")


def sanitize_supplier(value: Optional[str]) -> Optional[str]:
    """Sanitize a supplier/vendor field."""
    return sanitize_string(value, MAX_SUPPLIER_LENGTH, allow_newlines=False, field_name="supplier")


def sanitize_license(value: Optional[str]) -> Optional[str]:
    """Sanitize a license string."""
    return sanitize_string(value, MAX_LICENSE_LENGTH, allow_newlines=False, field_name="license")


def normalize_vcs_url(url: str) -> str:
    """
    Normalize VCS URLs to SPDX-standard format.

    Normalizes URLs that are explicitly git-related or from known git hosts:
    - scm:git:... -> strips prefix, normalizes inner URL
    - git@host:path -> git+https://host/path
    - git://host/path -> unchanged (already valid SPDX VCS scheme)
    - https://github.com/... (known git hosts) -> git+https://...

    Plain https:// URLs from unknown domains are NOT modified since we can't
    assume they are git repositories (could be Mercurial, SVN, or just a website).

    Args:
        url: The URL to normalize

    Returns:
        Normalized URL in SPDX VCS format, or original URL unchanged if:
        - Input is None or empty
        - URL is from an unknown host and doesn't have git-specific markers
    """
    if not url:
        return url

    original_url = url
    had_scm_prefix = False

    # Step 1: Strip Maven SCM prefix if present
    scm_match = _SCM_GIT_PATTERN.match(url)
    if scm_match:
        url = scm_match.group(1)
        had_scm_prefix = True

    # Step 2: Handle SSH shorthand (git@host:path) -> git+https://host/path
    # We convert to HTTPS because:
    # 1. SBOM metadata is for public reference, not for cloning
    # 2. HTTPS URLs are universally accessible without SSH keys
    # 3. Major hosting providers (GitHub, GitLab, etc.) support both protocols
    ssh_match = _SSH_GIT_PATTERN.match(url)
    if ssh_match:
        host = ssh_match.group(1)
        path = ssh_match.group(2)
        normalized = f"git+https://{host}/{path}"
        _log_vcs_normalization(original_url, normalized)
        return normalized

    # Step 3: git:// is already a valid SPDX VCS URL scheme - leave it as-is
    # (git:// is the git protocol on port 9418, NOT https)
    # Note: git:// is unencrypted and largely deprecated by hosting providers,
    # but we preserve it for accuracy when it appears in upstream metadata
    if url.startswith("git://"):
        # Only log if we stripped an scm: prefix
        if original_url != url:
            _log_vcs_normalization(original_url, url)
        return url

    # Step 4: Add git+ prefix if we KNOW it's git:
    # - Had scm:git: prefix, OR
    # - URL is from a known git hosting provider
    is_known_git = had_scm_prefix or _is_known_git_host(url)

    if is_known_git:
        if url.startswith("https://"):
            normalized = f"git+{url}"
            if original_url != normalized:
                _log_vcs_normalization(original_url, normalized)
            return normalized
        elif url.startswith("http://"):
            normalized = f"git+{url}"
            if original_url != normalized:
                _log_vcs_normalization(original_url, normalized)
            return normalized

    # No normalization needed - return URL as-is
    return url
