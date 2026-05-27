"""Component CRUD API calls for the Yocto pipeline.

This module preserves the historical function signatures
(``api_base_url`` / ``token`` arguments) so the rest of the Yocto pipeline
doesn't need to know about ``SbomifyApiClient``. Each function constructs
a one-shot client and delegates — the real plumbing lives in
``sbomify_action.sbomify_api``.
"""

from __future__ import annotations

from typing import Any, Iterator

from sbomify_action.sbomify_api import SbomifyApiClient


def _client(api_base_url: str, token: str) -> SbomifyApiClient:
    """Build a fresh client for a single Yocto-style call."""
    return SbomifyApiClient(api_base_url, token)


def _iter_components(api_base_url: str, token: str, error_context: str) -> Iterator[dict[str, Any]]:
    """Yield every component item, paginating as needed.

    Preserved as a module-level helper so existing callers (and tests) can
    import it under the old name. Delegates straight to the client.
    """
    return _client(api_base_url, token).iter_components(error_context=error_context)


def list_components(api_base_url: str, token: str) -> dict[str, str]:
    """Fetch all components and return a ``{name: id}`` mapping."""
    return _client(api_base_url, token).list_components_by_name()


def get_component_id_by_name(api_base_url: str, token: str, name: str) -> str | None:
    """Look up a component ID by exact name match."""
    return _client(api_base_url, token).get_component_id_by_name(name)


def create_component(api_base_url: str, token: str, name: str) -> tuple[str, bool]:
    """Create a new component (or recover an existing one on DUPLICATE_NAME)."""
    return _client(api_base_url, token).create_component(name)


def patch_component_visibility(api_base_url: str, token: str, component_id: str, visibility: str) -> None:
    """Best-effort visibility patch — logs on failure rather than raising."""
    _client(api_base_url, token).patch_component_visibility(component_id, visibility)


def get_or_create_component(api_base_url: str, token: str, name: str, cache: dict[str, str]) -> tuple[str, bool]:
    """Look the name up in ``cache``; on miss, create the component (and update cache)."""
    return _client(api_base_url, token).get_or_create_component(name, cache)
