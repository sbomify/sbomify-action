"""Utility functions for augmentation providers."""

import os
import re
from typing import Optional
from urllib.parse import urlsplit


def truncate_sha(sha: Optional[str], length: int = 7) -> str:
    """
    Safely truncate a commit SHA to the specified length.

    Args:
        sha: The commit SHA to truncate, or None
        length: Target length (default 7 for short SHA display)

    Returns:
        Truncated SHA if long enough, full SHA if shorter, or "unknown" if None
    """
    if not sha:
        return "unknown"
    if len(sha) <= length:
        return sha
    return sha[:length]


def is_vcs_augmentation_disabled() -> bool:
    """
    Check if VCS augmentation is disabled via environment variable.

    Set DISABLE_VCS_AUGMENTATION=true to disable all VCS enrichment
    from CI providers and sbomify.json config.

    Returns:
        True if VCS augmentation should be disabled, False otherwise
    """
    return os.getenv("DISABLE_VCS_AUGMENTATION", "").lower() in ("true", "1", "yes")


def build_vcs_url_with_commit(vcs_url: str, commit_sha: Optional[str]) -> str:
    """
    Build a VCS URL with commit pinning in git+ format.

    This creates URLs compatible with both CycloneDX and SPDX specs:
    - git+https://github.com/owner/repo@abc123def456

    Args:
        vcs_url: Base repository URL (e.g., https://github.com/owner/repo)
        commit_sha: Full commit SHA to pin, or None for unpinned URL

    Returns:
        VCS URL with commit pinning if SHA provided, otherwise the
        URL normalized to git+ format
    """
    # Both http and https are prefixed: TeamCity is the first provider that can
    # emit a plain-http root URL (an internal server), and without the prefix
    # the result "http://host/org/app@<sha>" is not a parseable VCS locator.
    is_http = vcs_url.startswith(("https://", "http://"))

    if not commit_sha:
        # Just normalize to git+ format if no commit
        if is_http:
            return f"git+{vcs_url}"
        return vcs_url

    # Build URL with commit pinning
    if is_http:
        return f"git+{vcs_url}@{commit_sha}"
    return f"{vcs_url}@{commit_sha}"


# Maximum length we will consider for a VCS URL. Anything longer is treated as
# malformed rather than truncated.
_MAX_VCS_URL_LENGTH = 2048

# scp-style shorthand: ``user@host:path``. The ``user@`` part is REQUIRED so that
# "host:1234/path" can never be misread as scp syntax and a Windows path such as
# "C:\repos\app" cannot match either.
_SCP_LIKE_RE = re.compile(r"^(?P<user>[^\s@/:\\]+)@(?P<host>[^\s@/:\\]+):(?P<path>/?[^\s].*)$")

# Schemes we are willing to interpret as a remote repository. Anything else
# (file://, svn://, perforce, ...) is rejected outright.
_ALLOWED_URL_SCHEMES = frozenset({"https", "http", "ssh", "git", "git+ssh", "git+https", "git+http"})

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_IPV6_RE = re.compile(r"^[0-9A-Fa-f:.]+$")

_REF_PREFIXES = ("refs/heads/", "refs/tags/")


def strip_ref_prefix(ref: Optional[str]) -> Optional[str]:
    """
    Strip the ``refs/heads/`` or ``refs/tags/`` prefix from a git ref.

    Anything else (``refs/pull/42/head``, ``refs/merge-requests/1/head``) is
    returned untouched rather than guessed at.

    Args:
        ref: A git ref name, or None

    Returns:
        The short ref name, or None if the input was None/empty
    """
    if not ref:
        return None
    for prefix in _REF_PREFIXES:
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


def is_scp_like_git_url(url: str) -> bool:
    """Whether ``url`` is scp-style shorthand for a git remote.

    ``git@host:org/repo.git`` and ``git@host:/srv/git/app.git`` qualify; a
    Perforce P4PORT such as ``user@perforce.example.com:1666`` does not, since
    its "path" is a port number with no path separator and no ``.git`` suffix.
    """
    match = _SCP_LIKE_RE.match(url.strip())
    if not match:
        return False
    path = match.group("path")
    return "/" in path or path.lower().endswith(".git")


def _assemble_repo_url(scheme: str, host: str, port: Optional[int], path: str) -> Optional[str]:
    """Rebuild a clean URL from validated components, or None if unusable."""
    if not host:
        return None

    if ":" in host:
        # urlsplit().hostname strips the brackets from an IPv6 literal.
        if not _IPV6_RE.match(host):
            return None
        netloc_host = f"[{host}]"
    elif not _HOSTNAME_RE.match(host):
        return None
    else:
        netloc_host = host

    path = path.strip().strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    path = path.strip("/")
    if not path:
        # A host with no path carries no repository identity.
        return None

    netloc = f"{netloc_host}:{port}" if port else netloc_host
    return f"{scheme}://{netloc}/{path}"


def normalize_repo_url(raw: Optional[str]) -> Optional[str]:
    """
    Normalize a repository URL to a credential-free browse URL.

    Unlike the other CI providers, TeamCity hands us whatever is configured on
    the VCS root -- commonly SSH, and often carrying an embedded access token.
    This returns a plain ``https://`` (or ``http://``) URL; the ``git+`` prefix
    is added downstream by :func:`build_vcs_url_with_commit`, so it must NOT be
    added here.

    Rules:
      * ``git@host:org/repo.git``                -> ``https://host/org/repo``
      * ``ssh://`` / ``git://`` / ``git+ssh://`` -> ``https://``, and the SSH
        port is DROPPED. An SSH port such as 7999 is not an HTTPS port; keeping
        it would produce a URL that resolves to nothing.
      * ``http(s)://`` -> scheme and port preserved. An internal server on
        :8443, or on plain http, must keep working rather than be silently
        rewritten into a 404.
      * userinfo, query string and fragment are always discarded, so
        ``https://user:token@host/org/repo.git`` -> ``https://host/org/repo``.
      * a trailing ``.git`` and trailing slashes are stripped.

    Args:
        raw: The URL to normalize, or None

    Returns:
        A normalized URL, or None for anything that is not a recognizable
        remote repository URL (empty, local path, file://, svn://, embedded
        whitespace, over-long input). Callers fall back to their next source.
    """
    if not raw:
        return None
    url = raw.strip()
    if not url or len(url) > _MAX_VCS_URL_LENGTH:
        return None
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        return None

    if scp_match := _SCP_LIKE_RE.match(url):
        # scp syntax has no port: everything after the colon is a path, so
        # "git@host:7999/org/repo.git" legitimately means path "7999/org/repo".
        # Require the path to look like a repository path, otherwise a Perforce
        # P4PORT ("user@perforce.example.com:1666") would be turned into the
        # fabricated URL https://perforce.example.com/1666.
        if is_scp_like_git_url(url):
            return _assemble_repo_url("https", scp_match.group("host").lower(), None, scp_match.group("path"))
        return None

    try:
        parts = urlsplit(url)
        host = parts.hostname  # lowercased, userinfo and port removed
        port = parts.port  # raises ValueError on a non-numeric port
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        return None
    if scheme.startswith("git+"):
        scheme = scheme[4:]
    if scheme in ("ssh", "git"):
        return _assemble_repo_url("https", host or "", None, parts.path)
    return _assemble_repo_url(scheme, host or "", port, parts.path)
