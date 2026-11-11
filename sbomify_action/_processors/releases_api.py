"""Release-related API helpers.

Thin functional facade over ``SbomifyApiClient`` for legacy callers that
pass ``api_base_url`` + ``token`` strings (the CLI, the Yocto pipeline,
and the ``SbomifyReleasesProcessor``). New code should use
``SbomifyApiClient`` directly.
"""

from __future__ import annotations

from typing import Any, Optional

from sbomify_action.sbomify_api import SbomifyApiClient


def _client(api_base_url: str, token: str, allow_insecure_http: bool = False) -> SbomifyApiClient:
    """One-shot client for a single call. ``allow_insecure_http`` is API_ALLOW_INSECURE_HTTP."""
    return SbomifyApiClient(api_base_url, token, allow_insecure_http=allow_insecure_http)


def check_release_exists(
    api_base_url: str, token: str, product_id: str, version: str, allow_insecure_http: bool = False
) -> bool:
    """Return True iff a release with ``version`` exists for ``product_id``."""
    return _client(api_base_url, token, allow_insecure_http).check_release_exists(product_id, version)


def get_release_id(
    api_base_url: str, token: str, product_id: str, version: str, allow_insecure_http: bool = False
) -> Optional[str]:
    """Return the release ID matching ``version``, or None."""
    return _client(api_base_url, token, allow_insecure_http).get_release_id(product_id, version)


def get_release_id_by_name(api_base_url: str, token: str, product_id: str, name: str) -> Optional[str]:
    """Look a release up by its name field (used for DUPLICATE_NAME recovery)."""
    return _client(api_base_url, token).get_release_id_by_name(product_id, name)


def get_release_details(
    api_base_url: str, token: str, product_id: str, version: str, allow_insecure_http: bool = False
) -> Optional[dict[str, Any]]:
    """Fetch full release details for ``(product_id, version)``, or None."""
    return _client(api_base_url, token, allow_insecure_http).get_release_details(product_id, version)


def create_release(
    api_base_url: str,
    token: str,
    product_id: str,
    version: str,
    *,
    is_prerelease: Optional[bool] = None,
    allow_insecure_http: bool = False,
) -> Optional[str]:
    """Create a release (or recover an existing one on DUPLICATE_NAME).

    Returns the release ID. ``Optional[str]`` keeps the historical
    signature even though the client now raises ``APIError`` on
    failures that used to return ``None``.

    ``is_prerelease`` reaches the backend's own field of that name. The client
    has accepted it since releases were added; this wrapper did not pass it
    on, so every release the action created was recorded as a final one --
    alphas and release candidates included.
    """
    return _client(api_base_url, token, allow_insecure_http).create_release(
        product_id, version, is_prerelease=is_prerelease
    )


def tag_sbom_with_release(
    api_base_url: str, token: str, sbom_id: str, release_id: str, allow_insecure_http: bool = False
) -> None:
    """Associate an SBOM with a release; idempotent on DUPLICATE_ARTIFACT."""
    _client(api_base_url, token, allow_insecure_http).tag_sbom_with_release(sbom_id, release_id)


def tag_artifact_with_release(
    api_base_url: str,
    token: str,
    artifact_id: str,
    release_id: str,
    artifact_kind: str = "sbom",
    allow_insecure_http: bool = False,
) -> None:
    """Associate an SBOM or a document with a release; idempotent on DUPLICATE_ARTIFACT."""
    _client(api_base_url, token, allow_insecure_http).tag_artifact_with_release(
        artifact_id, release_id, artifact_kind=artifact_kind
    )


def link_release(api_base_url: str, token: str, release_id: str, product_id: str, version: str) -> None:
    """Link another product's release into a release; idempotent on an existing link."""
    _client(api_base_url, token).link_release(release_id, product_id, version)


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
