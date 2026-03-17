"""sbomify-action package for SBOM generation and enrichment."""


def format_display_name(fmt: str) -> str:
    """Return properly capitalized display name for SBOM format.

    This is the canonical function for displaying SBOM format names.
    Use this everywhere format names are shown to users.

    Args:
        fmt: Format string ('cyclonedx' or 'spdx', case-insensitive)

    Returns:
        Display name: 'CycloneDX' or 'SPDX'

    Examples:
        >>> format_display_name("cyclonedx")
        'CycloneDX'
        >>> format_display_name("SPDX")
        'SPDX'
    """
    return "CycloneDX" if fmt.lower() == "cyclonedx" else "SPDX"


def _get_version() -> str:
    """Get package version with fallback mechanisms.

    Tries the following methods in order until one succeeds:
    - importlib.metadata (preferred for installed packages)
    - tomllib/pyproject.toml (Python 3.11+, for development)
    - toml library/pyproject.toml (older Python, for development)
    - Returns "unknown" if all methods fail
    """
    # Try importlib.metadata (preferred for installed packages)
    try:
        from importlib.metadata import version

        return version("sbomify-action")
    except ImportError:
        pass
    except Exception:
        pass

    # Try reading from pyproject.toml using tomllib (Python 3.11+)
    try:
        from pathlib import Path

        import tomllib

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
            return str(pyproject_data.get("project", {}).get("version", "unknown"))
    except ImportError:
        # Python < 3.11 doesn't have tomllib
        pass
    except Exception:
        pass

    # Try toml library as fallback for older Python
    try:
        from pathlib import Path

        import toml

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "r") as f:
                pyproject_data = toml.load(f)
            return str(pyproject_data.get("project", {}).get("version", "unknown"))
    except ImportError:
        pass
    except Exception:
        pass

    # Final fallback
    return "unknown"


__version__ = _get_version()
