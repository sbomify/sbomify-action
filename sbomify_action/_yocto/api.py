"""Component CRUD API calls for Yocto pipeline."""

from typing import Any, Iterator

import requests

from sbomify_action.exceptions import APIError, PlanLimitError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

_PAGE_SIZE = 100
_MAX_PAGES = 500  # Safety limit against runaway pagination


def _iter_components(api_base_url: str, token: str, error_context: str) -> Iterator[dict[str, Any]]:
    """Yield every component item from /api/v1/components, paginating as needed.

    Raises APIError for any HTTP/transport/JSON-shape failure so callers see
    the real cause instead of a misleading downstream error. Caller can
    short-circuit by breaking out of the iteration.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        error_context: Phrase used in error messages (e.g. "list components",
            "look up component 'foo'")

    Yields:
        Each item dict from the paginated response.

    Raises:
        APIError: On network/timeout/HTTP error, or malformed/truncated response.
    """
    url = api_base_url + "/api/v1/components"
    headers = get_default_headers(token)
    page = 1

    while page <= _MAX_PAGES:
        try:
            response = requests.get(url, headers=headers, params={"page": page, "page_size": _PAGE_SIZE}, timeout=60)
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to sbomify API")
        except requests.exceptions.Timeout:
            raise APIError("API request timed out")

        if not response.ok:
            raise APIError(f"Failed to {error_context}. [{response.status_code}]")

        try:
            data = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            raise APIError(f"Failed to {error_context}: invalid JSON response from API")

        if not isinstance(data, dict):
            raise APIError(f"Failed to {error_context}: unexpected response type ({type(data).__name__})")

        yield from data.get("items", [])

        if not data.get("next"):
            return
        page += 1

    raise APIError(
        f"Failed to {error_context}: pagination safety limit reached ({_MAX_PAGES} pages × {_PAGE_SIZE} items)"
    )


def list_components(api_base_url: str, token: str) -> dict[str, str]:
    """Fetch all components and return a name-to-id mapping.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token

    Returns:
        Dict mapping component name to component ID

    Raises:
        APIError: If API call fails
    """
    components: dict[str, str] = {}
    for item in _iter_components(api_base_url, token, "list components"):
        name = item.get("name")
        comp_id = item.get("id")
        if name and comp_id:
            components[name] = str(comp_id)
    logger.info(f"Cached {len(components)} existing components")
    return components


def get_component_id_by_name(api_base_url: str, token: str, name: str) -> str | None:
    """Look up a component ID by exact name match.

    Used to recover from DUPLICATE_NAME errors when the local cache is stale
    (e.g. another concurrent run created the component, or it predates our
    initial snapshot). The /api/v1/components endpoint doesn't support
    server-side name filtering, so this paginates until the name is found
    (short-circuits on first match).

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        name: Component name to look up

    Returns:
        Component ID if found, None if walked all pages without a match.

    Raises:
        APIError: On network/HTTP/JSON failure (callers see the real cause
            rather than a misleading "could not be found" error).
    """
    for item in _iter_components(api_base_url, token, f"look up component '{name}'"):
        if item.get("name") == name:
            comp_id = item.get("id")
            if comp_id is not None:
                return str(comp_id)
    return None


def create_component(api_base_url: str, token: str, name: str) -> tuple[str, bool]:
    """Create a new component.

    If a component with the same name already exists (DUPLICATE_NAME error
    from sbomify API), the existing component's ID is returned with
    ``was_created=False`` instead of failing — get-or-create semantics.
    This guards against stale caches and concurrent runs racing on the
    same name.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        name: Component name

    Returns:
        Tuple of (component_id, was_created). ``was_created`` is False when
        an existing component was recovered via DUPLICATE_NAME.

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + "/api/v1/components"
    headers = get_default_headers(token, content_type="application/json")
    payload = {"name": name, "component_type": "sbom"}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        err_msg = f"Failed to create component '{name}'. [{response.status_code}]"
        body: dict[str, Any] = {}
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                body = parsed
        except ValueError:
            pass
        detail = body.get("detail") or ""
        error_code = body.get("error_code") or ""
        if detail:
            err_msg += f" - {detail}"

        # Recover from DUPLICATE_NAME (stale cache or concurrent create).
        # Accept both 400 and 409: 409 is REST-canonical for conflicts and
        # matches the DUPLICATE_ARTIFACT shape in _upload/destinations/sbomify.py.
        if response.status_code in (400, 409) and error_code == "DUPLICATE_NAME":
            logger.info(f"Component '{name}' already exists, retrieving existing component ID")
            existing_id = get_component_id_by_name(api_base_url, token, name)
            if existing_id is not None:
                return existing_id, False
            raise APIError(f"Component '{name}' reported as duplicate by API but could not be found via lookup")

        if response.status_code == 403 and isinstance(detail, str) and "maximum" in detail.lower():
            raise PlanLimitError(err_msg)

        raise APIError(err_msg)

    try:
        data = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        raise APIError(f"Invalid JSON response when creating component '{name}'")
    comp_id = data.get("id")
    if comp_id is None:
        raise APIError(f"Invalid response when creating component '{name}': no id returned")
    return str(comp_id), True


def patch_component_visibility(api_base_url: str, token: str, component_id: str, visibility: str) -> None:
    """Set the visibility of a component.

    Non-fatal: logs a warning on failure since visibility is a best-effort
    setting that should not block the pipeline.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        component_id: Component ID to patch
        visibility: One of "public", "private", "gated"

    Raises:
        APIError: If connection or timeout fails
    """
    url = f"{api_base_url}/api/v1/components/{component_id}"
    headers = get_default_headers(token, content_type="application/json")

    try:
        response = requests.patch(url, headers=headers, json={"visibility": visibility}, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        logger.warning(f"Failed to set visibility for component {component_id}: [{response.status_code}]")


def get_or_create_component(api_base_url: str, token: str, name: str, cache: dict[str, str]) -> tuple[str, bool]:
    """Get an existing component or create a new one.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        name: Component name
        cache: Name-to-id mapping (updated in-place if created)

    Returns:
        Tuple of (component_id, was_created)

    Raises:
        APIError: If API call fails
    """
    if name in cache:
        return cache[name], False

    comp_id, was_created = create_component(api_base_url, token, name)
    cache[name] = comp_id
    if was_created:
        logger.info(f"Created component '{name}' -> {comp_id}")
    else:
        logger.info(f"Recovered existing component '{name}' -> {comp_id}")
    return comp_id, was_created
