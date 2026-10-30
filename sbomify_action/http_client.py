"""HTTP client utilities with consistent user agent."""

import ipaddress
import logging
from typing import Optional
from urllib.parse import urlsplit

from .exceptions import ConfigurationError

# Not logging_config's logger: that module imports _runtime, which imports this one.
logger = logging.getLogger(__name__)


def _get_package_version() -> str:
    """Get the package version for User-Agent header."""
    try:
        from importlib.metadata import version

        return version("sbomify-action")
    except Exception:
        try:
            import tomllib
            from pathlib import Path

            pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                return str(pyproject_data.get("project", {}).get("version", "unknown"))
        except Exception:
            pass
    return "unknown"


USER_AGENT = f"sbomify-action/{_get_package_version()} (hello@sbomify.com)"


def get_default_headers(token: Optional[str] = None, content_type: Optional[str] = None) -> dict[str, str]:
    """
    Get default HTTP headers with user agent.

    Args:
        token: Optional authentication token to include
        content_type: Optional Content-Type header value (e.g., "application/json")

    Returns:
        Dictionary of HTTP headers
    """
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _is_loopback(host: str) -> bool:
    """True for localhost, ``*.localhost`` (RFC 6761) and loopback IP literals."""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_endpoint_url(
    url: str,
    setting: str,
    *,
    allow_http: bool = False,
    allow_http_setting: str | None = None,
    credential: str = "the token or API key sent with every request",
) -> None:
    """Refuse an endpoint URL that would put the credentials sent to it at risk.

    Every upload destination sends a token or API key with each request, so its
    URL must be https://. Plain http:// is accepted only for a loopback host,
    where the traffic never leaves the machine. Userinfo (``user:pass@``) is
    refused outright: it is a second credential sitting in a value that gets
    logged and echoed.

    Args:
        url: The configured endpoint URL.
        setting: The setting it came from (e.g. ``DTRACK_API_URL``), named in
            the error so the user knows what to fix.
        allow_http: Accept http:// to any host, with a warning. Only for an
            explicit user opt-in; the other checks still apply.
        allow_http_setting: The opt-in setting behind ``allow_http``, offered
            in the error and named in the warning.
        credential: What travels with each request, for the error and warning.

    Raises:
        ConfigurationError: If the URL is not safe to send credentials to.
    """
    try:
        parts = urlsplit(url)
    except ValueError as e:  # e.g. an unclosed IPv6 bracket
        raise ConfigurationError(f"{setting} is not a valid URL: {e}") from e
    if parts.scheme not in ("http", "https"):
        raise ConfigurationError(f"{setting} must start with http:// or https://")
    if "@" in parts.netloc:
        # Never echo the URL here: the part being rejected is a password.
        raise ConfigurationError(
            f"{setting} must not contain credentials (user:password@host). "
            "Pass the token or API key through its own setting instead."
        )
    if not parts.hostname:
        raise ConfigurationError(f"{setting} must include a valid hostname")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        if allow_http:
            logger.warning(
                f"{setting} uses plain http:// to {parts.hostname} ({allow_http_setting}=true): "
                f"{credential} crosses the network unencrypted."
            )
            return
        opt_in = (
            f" If every network hop to {parts.hostname} is one you trust, set {allow_http_setting}=true "
            "to accept that risk."
            if allow_http_setting
            else ""
        )
        raise ConfigurationError(
            f"{setting} must use https:// for {parts.hostname}. Over plain http:// {credential} "
            "crosses the network unencrypted, readable by anyone on the path. http:// is only "
            f"accepted for localhost, 127.0.0.1 and ::1.{opt_in}"
        )
