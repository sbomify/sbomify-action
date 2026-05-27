"""Component CRUD API calls for Yocto pipeline."""

import requests

from sbomify_action.exceptions import APIError, PlanLimitError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger


def list_components(api_base_url: str, token: str) -> dict[str, str]:
    """Fetch all components and return a name-to-id mapping.

    Paginates through all results to build a complete cache.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token

    Returns:
        Dict mapping component name to component ID

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + "/api/v1/components"
    headers = get_default_headers(token)
    components: dict[str, str] = {}
    page = 1
    max_pages = 500  # Safety limit against infinite pagination

    while page <= max_pages:
        try:
            response = requests.get(url, headers=headers, params={"page": page, "page_size": 100}, timeout=60)
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to sbomify API")
        except requests.exceptions.Timeout:
            raise APIError("API request timed out")

        if not response.ok:
            raise APIError(f"Failed to list components. [{response.status_code}]")

        try:
            data = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            raise APIError("Failed to list components: invalid JSON response from API")

        if not isinstance(data, dict):
            raise APIError(f"Failed to list components: unexpected response type ({type(data).__name__})")

        for item in data.get("items", []):
            name = item.get("name")
            comp_id = item.get("id")
            if name and comp_id:
                components[name] = str(comp_id)

        # Paginate based on 'next' link, not empty items
        if not data.get("next"):
            break
        page += 1

    if page > max_pages and data.get("next"):
        logger.warning(
            f"Pagination safety limit reached ({max_pages} pages). "
            f"Component cache may be incomplete ({len(components)} components fetched)."
        )

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
        Component ID if found, None otherwise

    Raises:
        APIError: If API call fails (network/timeout/non-404 HTTP error)
    """
    url = api_base_url + "/api/v1/components"
    headers = get_default_headers(token)
    page = 1
    max_pages = 500  # Safety limit against runaway pagination

    while page <= max_pages:
        try:
            response = requests.get(url, headers=headers, params={"page": page, "page_size": 100}, timeout=60)
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to sbomify API")
        except requests.exceptions.Timeout:
            raise APIError("API request timed out")

        if response.status_code == 404:
            return None
        if not response.ok:
            raise APIError(f"Failed to look up component '{name}'. [{response.status_code}]")

        try:
            data = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None

        for item in data.get("items", []):
            if item.get("name") == name:
                comp_id = item.get("id")
                if comp_id is not None:
                    return str(comp_id)

        if not data.get("next"):
            return None
        page += 1

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
        detail = ""
        error_code = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                detail = body.get("detail", "") or ""
                error_code = body.get("error_code", "") or ""
            if detail:
                err_msg += f" - {detail}"
        except ValueError:
            pass

        if response.status_code == 400 and error_code == "DUPLICATE_NAME":
            logger.info(f"Component '{name}' already exists, retrieving existing component ID")
            existing_id = get_component_id_by_name(api_base_url, token, name)
            if existing_id:
                return existing_id, False
            raise APIError(f"Component '{name}' reported as duplicate by API but could not be found via lookup")

        if response.status_code == 403 and "maximum" in detail.lower():
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
