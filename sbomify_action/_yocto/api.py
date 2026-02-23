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

    while True:
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

    logger.info(f"Cached {len(components)} existing components")
    return components


def create_component(api_base_url: str, token: str, name: str) -> str:
    """Create a new component.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        name: Component name

    Returns:
        Component ID

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
        try:
            detail = response.json().get("detail", "")
            if detail:
                err_msg += f" - {detail}"
        except ValueError:
            pass

        if response.status_code == 403 and "maximum" in detail.lower():
            raise PlanLimitError(err_msg)

        raise APIError(err_msg)

    data = response.json()
    comp_id = data.get("id")
    if comp_id is None:
        raise APIError(f"Invalid response when creating component '{name}': no id returned")
    return str(comp_id)


def patch_component_visibility(api_base_url: str, token: str, component_id: str, visibility: str) -> None:
    """Set the visibility of a component.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        component_id: Component ID to patch
        visibility: One of "public", "private", "gated"

    Raises:
        APIError: If API call fails
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

    comp_id = create_component(api_base_url, token, name)
    cache[name] = comp_id
    logger.info(f"Created component '{name}' -> {comp_id}")
    return comp_id, True
