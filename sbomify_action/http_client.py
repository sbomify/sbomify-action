"""HTTP client utilities with consistent user agent."""

from typing import Optional


def _get_package_version() -> str:
    """Get the package version for User-Agent header."""
    try:
        from importlib.metadata import version

        return version("sbomify-action")
    except Exception:
        try:
            from pathlib import Path

            import tomllib

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
