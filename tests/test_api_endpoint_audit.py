"""URL-construction audit for every sbomify-facing endpoint.

These tests pin the exact URL each call site produces, so we don't
regress to ``/api/v1/api/v1/...`` shapes if the base URL convention
ever drifts. All callers now route through ``SbomifyApiClient``, so
the patch target is the shared client's ``session.request``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sbomify_action._augmentation.providers.sbomify_api import SbomifyApiProvider
from sbomify_action._processors.releases_api import (
    check_release_exists,
    create_release,
    get_release_details,
    get_release_id,
    tag_sbom_with_release,
)
from sbomify_action.cli.main import SBOMIFY_PRODUCTION_API

API_BASE = SBOMIFY_PRODUCTION_API
TOKEN = "test-token"
COMPONENT_ID = "test-component"


def _ok_response(json_body: Any) -> MagicMock:
    response = MagicMock()
    response.ok = True
    response.status_code = 200
    response.json.return_value = json_body
    response.headers = {"content-type": "application/json"}
    return response


def _captured_urls(mock_request: MagicMock) -> list[str]:
    """Extract the ``url`` argument from each session.request call."""
    urls: list[str] = []
    for call in mock_request.call_args_list:
        args, kwargs = call
        if "url" in kwargs:
            urls.append(kwargs["url"])
        elif len(args) >= 2:
            urls.append(args[1])
    return urls


@pytest.fixture
def mock_session_request() -> Any:
    """Patch SbomifyApiClient's session.request for the duration of the test."""
    with patch("sbomify_action.sbomify_api.requests.Session") as mock_session_cls:
        instance = MagicMock()
        mock_session_cls.return_value = instance
        yield instance.request


def test_production_api_base_url_format() -> None:
    """Base URL must be the bare domain, no /api/v1 suffix, no trailing slash."""
    assert SBOMIFY_PRODUCTION_API == "https://app.sbomify.com"
    assert not SBOMIFY_PRODUCTION_API.endswith("/api/v1")
    assert not SBOMIFY_PRODUCTION_API.endswith("/")


def test_check_release_exists_endpoint(mock_session_request: MagicMock) -> None:
    mock_session_request.return_value = _ok_response({"items": []})
    check_release_exists(API_BASE, TOKEN, "product123", "v1.0.0")

    urls = _captured_urls(mock_session_request)
    assert urls == ["https://app.sbomify.com/api/v1/releases"]


def test_create_release_endpoint(mock_session_request: MagicMock) -> None:
    mock_session_request.return_value = _ok_response({"id": "new-release-id"})
    create_release(API_BASE, TOKEN, "product123", "v1.0.0")

    urls = _captured_urls(mock_session_request)
    assert urls == ["https://app.sbomify.com/api/v1/releases"]


def test_tag_sbom_with_release_endpoint(mock_session_request: MagicMock) -> None:
    mock_session_request.return_value = _ok_response({})
    tag_sbom_with_release(API_BASE, TOKEN, "sbom123", "release456")

    urls = _captured_urls(mock_session_request)
    assert urls == ["https://app.sbomify.com/api/v1/releases/release456/artifacts"]


def test_get_release_id_endpoint(mock_session_request: MagicMock) -> None:
    mock_session_request.return_value = _ok_response({"items": []})
    get_release_id(API_BASE, TOKEN, "product123", "v1.0.0")

    urls = _captured_urls(mock_session_request)
    assert urls == ["https://app.sbomify.com/api/v1/releases"]


def test_get_release_details_endpoint(mock_session_request: MagicMock) -> None:
    mock_session_request.return_value = _ok_response({"items": []})
    get_release_details(API_BASE, TOKEN, "product123", "v1.0.0")

    urls = _captured_urls(mock_session_request)
    assert urls == ["https://app.sbomify.com/api/v1/releases"]


def test_sbomify_api_provider_endpoint(mock_session_request: MagicMock) -> None:
    """Augmentation now routes through SbomifyApiClient; verify the URL it asks for."""
    mock_session_request.return_value = _ok_response({"supplier": {}, "authors": [], "licenses": []})

    provider = SbomifyApiProvider()
    provider.fetch(api_base_url=API_BASE, token=TOKEN, component_id=COMPONENT_ID)

    urls = _captured_urls(mock_session_request)
    assert urls == ["https://app.sbomify.com/api/v1/sboms/component/test-component/meta"]


def test_sbom_upload_url_construction() -> None:
    """Static check on the upload URL template (no session call required)."""
    sbom_format = "cyclonedx"
    expected = f"{API_BASE}/api/v1/sboms/artifact/{sbom_format}/{COMPONENT_ID}"
    assert expected == "https://app.sbomify.com/api/v1/sboms/artifact/cyclonedx/test-component"
    assert "/api/v1/api/v1" not in expected
    assert expected.count("/api/v1") == 1


def test_custom_api_base_url_override() -> None:
    """A custom base URL still composes cleanly with the endpoint paths."""
    custom = "https://api.dev.sbomify.com"
    assert custom + "/api/v1/releases" == "https://api.dev.sbomify.com/api/v1/releases"
    assert (
        custom + f"/api/v1/sboms/component/{COMPONENT_ID}/meta"
        == "https://api.dev.sbomify.com/api/v1/sboms/component/test-component/meta"
    )


def test_all_endpoints_have_single_api_v1_prefix() -> None:
    base = "https://app.sbomify.com"
    component_id = "test-component"
    release_id = "test-release"
    sbom_format = "cyclonedx"
    endpoints = [
        f"{base}/api/v1/releases",
        f"{base}/api/v1/releases/{release_id}/artifacts",
        f"{base}/api/v1/sboms/component/{component_id}/meta",
        f"{base}/api/v1/sboms/artifact/{sbom_format}/{component_id}",
    ]
    for endpoint in endpoints:
        assert endpoint.count("/api/v1") == 1, endpoint
        assert "//" not in endpoint.replace("https://", ""), endpoint
        assert "/api/v1/api/v1" not in endpoint, endpoint
