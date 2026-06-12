"""Release-related API helpers.

Thin functional facade over ``SbomifyApiClient`` for legacy callers that
pass ``api_base_url`` + ``token`` strings (the CLI, the Yocto pipeline,
and the ``SbomifyReleasesProcessor``). New code should use
``SbomifyApiClient`` directly.
"""

from __future__ import annotations

from typing import Any, Optional

from sbomify_action.sbomify_api import SbomifyApiClient


def _client(api_base_url: str, token: str) -> SbomifyApiClient:
    """One-shot client for a single call."""
    return SbomifyApiClient(api_base_url, token)


def check_release_exists(api_base_url: str, token: str, product_id: str, version: str) -> bool:
    """Return True iff a release with ``version`` exists for ``product_id``."""
    return _client(api_base_url, token).check_release_exists(product_id, version)


def get_release_id(api_base_url: str, token: str, product_id: str, version: str) -> Optional[str]:
    """Return the release ID matching ``version``, or None."""
    return _client(api_base_url, token).get_release_id(product_id, version)


def get_release_id_by_name(api_base_url: str, token: str, product_id: str, name: str) -> Optional[str]:
    """Look a release up by its name field (used for DUPLICATE_NAME recovery)."""
    return _client(api_base_url, token).get_release_id_by_name(product_id, name)


def get_release_details(api_base_url: str, token: str, product_id: str, version: str) -> Optional[dict[str, Any]]:
    """Fetch full release details for ``(product_id, version)``, or None."""
    return _client(api_base_url, token).get_release_details(product_id, version)


def create_release(api_base_url: str, token: str, product_id: str, version: str) -> Optional[str]:
    """Create a release (or recover an existing one on DUPLICATE_NAME).

    Returns the release ID. ``Optional[str]`` keeps the historical
    signature even though the client now raises ``APIError`` on
    failures that used to return ``None``.
    """
    return _client(api_base_url, token).create_release(product_id, version)


def tag_sbom_with_release(api_base_url: str, token: str, sbom_id: str, release_id: str) -> None:
    """Associate an SBOM with a release; idempotent on DUPLICATE_ARTIFACT."""
    _client(api_base_url, token).tag_sbom_with_release(sbom_id, release_id)


def get_release_friendly_name(release_details: Optional[dict[str, Any]], version: str) -> str:
    """Return a user-friendly release label.

    Pure helper — no I/O — so this stays here rather than moving to the
    client.
    """
    if not release_details:
        return version

    release_name = release_details.get("name")
    if isinstance(release_name, str):
        stripped_name = release_name.strip()
        if stripped_name and stripped_name not in (version, f"Release {version}"):
            return f"'{stripped_name}' ({version})"
    return version
