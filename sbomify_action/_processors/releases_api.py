"""Shared API client for release-related operations.

This module provides reusable functions for interacting with the sbomify
releases API. Used by both cli/main.py and the ReleasesProcessor.
"""

from typing import Any, Dict, List, Optional

import requests

from sbomify_action.exceptions import APIError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger


def _safe_json_dict(response: requests.Response) -> Optional[Dict[str, Any]]:
    """
    Safely parse JSON response and return as dict, or None if not a valid dict.

    Args:
        response: The HTTP response object

    Returns:
        Parsed JSON as dict, or None if parsing fails or result is not a dict

    Note:
        Catches ValueError which includes JSONDecodeError (its subclass in requests).
    """
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
    except ValueError:
        pass
    return None


def _fetch_releases(api_base_url: str, token: str, params: Dict[str, str], error_context: str) -> List[Dict[str, Any]]:
    """
    Fetch releases from the API with the given query parameters.

    This is an internal helper that handles the common request/response
    logic for all release-fetching operations.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        params: Query parameters for the request
        error_context: Context string for error messages (e.g., "check release existence")

    Returns:
        List of release dicts from the API

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + "/api/v1/releases"
    headers = get_default_headers(token)

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.status_code == 404:
        return []
    elif response.ok:
        data = _safe_json_dict(response)
        if data is None:
            return []
        items = data.get("items")
        if not isinstance(items, list):
            return []
        return items
    else:
        err_msg = f"Failed to {error_context}. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            data = _safe_json_dict(response)
            if data is not None and "detail" in data:
                err_msg += f" - {data['detail']}"
        raise APIError(err_msg)


def check_release_exists(api_base_url: str, token: str, product_id: str, version: str) -> bool:
    """
    Check if a release exists for a product.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        True if release exists, False otherwise

    Raises:
        APIError: If API call fails
    """
    params = {"product_id": product_id, "version": version}
    releases = _fetch_releases(api_base_url, token, params, "check release existence")
    return any(release.get("version") == version for release in releases)


def get_release_id(api_base_url: str, token: str, product_id: str, version: str) -> Optional[str]:
    """
    Get the release ID for a product and version.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        The release ID if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    params = {"product_id": product_id, "version": version}
    releases = _fetch_releases(api_base_url, token, params, "get release ID")
    for release in releases:
        if release.get("version") == version:
            return release.get("id")
    return None


def get_release_id_by_name(api_base_url: str, token: str, product_id: str, name: str) -> Optional[str]:
    """
    Get the release ID by name field (used for DUPLICATE_NAME recovery).

    This function searches releases by name instead of version, which is needed
    when recovering from DUPLICATE_NAME errors since the API enforces uniqueness
    on the name field, not the version field.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        name: The release name to search for

    Returns:
        The release ID if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    # Query by product_id only, don't filter by version
    params = {"product_id": product_id}
    releases = _fetch_releases(api_base_url, token, params, "get release ID by name")
    for release in releases:
        if release.get("name") == name:
            return release.get("id")
    return None


def get_release_details(api_base_url: str, token: str, product_id: str, version: str) -> Optional[Dict[str, Any]]:
    """
    Get full release details for a product and version.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        Full release details dict if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    params = {"product_id": product_id, "version": version}
    releases = _fetch_releases(api_base_url, token, params, "get release details")
    for release in releases:
        if release.get("version") == version:
            return release
    return None


def create_release(api_base_url: str, token: str, product_id: str, version: str) -> Optional[str]:
    """
    Create a release for a product, with get-or-create pattern.

    If the release already exists (DUPLICATE_NAME error), retrieves
    and returns the existing release ID instead of failing.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        The created or existing release ID

    Raises:
        APIError: If API call fails and release cannot be retrieved
    """
    url = api_base_url + "/api/v1/releases"
    headers = get_default_headers(token, content_type="application/json")

    payload = {
        "product_id": product_id,
        "version": version,
        "name": f"Release {version}",
        "description": f"Release {version} created by sbomify-action",
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        # Handle duplicate release - get existing instead of failing (get-or-create pattern)
        if response.status_code == 400:
            error_data = _safe_json_dict(response)
            if error_data is not None and error_data.get("error_code") == "DUPLICATE_NAME":
                logger.info(
                    f"Release {version} for product {product_id} already exists, retrieving existing release ID"
                )
                # Search by name since the API enforces uniqueness on the name field
                existing_id = get_release_id_by_name(api_base_url, token, product_id, f"Release {version}")
                if existing_id:
                    return existing_id
                # If we couldn't find it, fall through to error handling

        err_msg = f"Failed to create release. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            error_data = _safe_json_dict(response)
            if error_data is not None:
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
                else:
                    err_msg += f" - {error_data}"
        else:
            if response.text:
                err_msg += f" - Response: {response.text[:500]}"
        raise APIError(err_msg)

    data = _safe_json_dict(response)
    if data is not None:
        release_id = data.get("id")
        if release_id is not None:
            return release_id
    raise APIError("Invalid response format when creating release")


def tag_sbom_with_release(api_base_url: str, token: str, sbom_id: str, release_id: str) -> None:
    """
    Associate/tag an SBOM with a release.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        sbom_id: The SBOM ID from upload response
        release_id: The release ID to associate with

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + f"/api/v1/releases/{release_id}/artifacts"
    headers = get_default_headers(token, content_type="application/json")
    payload = {"sbom_id": sbom_id}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        # Handle duplicate artifact - SBOM already tagged (idempotent success)
        if response.status_code == 409:
            error_data = _safe_json_dict(response)
            if error_data is not None and error_data.get("error_code") == "DUPLICATE_ARTIFACT":
                logger.info(f"SBOM {sbom_id} already tagged with release {release_id}")
                return  # Success - desired state achieved

        err_msg = f"Failed to tag SBOM with release. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            error_data = _safe_json_dict(response)
            if error_data is not None and "detail" in error_data:
                err_msg += f" - {error_data['detail']}"
        raise APIError(err_msg)


def get_release_friendly_name(release_details: Optional[Dict[str, Any]], version: str) -> str:
    """
    Get a user-friendly name for a release.

    Args:
        release_details: Full release details from the API
        version: The release version (fallback)

    Returns:
        User-friendly release name
    """
    if not release_details:
        return f"Release {version}"

    release_name = release_details.get("name")
    if isinstance(release_name, str):
        stripped_name = release_name.strip()
        if stripped_name and stripped_name != f"Release {version}":
            return f"'{stripped_name}' ({version})"
    return f"Release {version}"
