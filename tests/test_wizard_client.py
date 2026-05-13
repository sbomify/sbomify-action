"""Tests for sbomify_action.cli.wizard.client.SbomifyClient."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard.client import (
    SbomifyAPIError,
    SbomifyAuthError,
    SbomifyClient,
)


def _response(
    *,
    status: int = 200,
    json_body: Any = None,
    content_type: str = "application/json",
) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.ok = 200 <= status < 300
    response.reason = "OK" if response.ok else "Error"
    response.headers = {"content-type": content_type}
    response.json.return_value = json_body if json_body is not None else {}
    response.text = "" if json_body is None else str(json_body)
    return response


def _client(session: MagicMock) -> SbomifyClient:
    return SbomifyClient("https://app.sbomify.test", "tok-123", session=session)


def test_request_passes_authorization_header():
    session = MagicMock()
    session.request.return_value = _response(json_body={"items": []})
    client = _client(session)

    client.list_products()

    session.request.assert_called_once()
    _, call_kwargs = session.request.call_args
    assert call_kwargs["headers"]["Authorization"] == "Bearer tok-123"


def test_401_raises_auth_error():
    session = MagicMock()
    session.request.return_value = _response(status=401, json_body={"detail": "Bad token"})
    client = _client(session)

    with pytest.raises(SbomifyAuthError) as excinfo:
        client.whoami()
    assert "Bad token" in str(excinfo.value)


def test_other_4xx_raises_api_error():
    session = MagicMock()
    session.request.return_value = _response(status=403, json_body={"detail": "Forbidden"})
    client = _client(session)

    with pytest.raises(SbomifyAPIError) as excinfo:
        client.whoami()
    assert excinfo.value.status == 403
    assert "Forbidden" in str(excinfo.value)


def test_400_surfaces_field_level_errors():
    """sbomify PR #961 (#952): the `errors` dict on 400 responses must be
    surfaced inline so users see which field was rejected, not just
    "Validation error"."""
    session = MagicMock()
    session.request.return_value = _response(
        status=400,
        json_body={
            "detail": "Validation error",
            "error_code": "INVALID_DATA",
            "errors": {"name": ["Component with this Team and Name already exists."]},
        },
    )
    client = _client(session)

    with pytest.raises(SbomifyAPIError) as excinfo:
        client.create_component("dup")
    message = str(excinfo.value)
    assert "Validation error" in message
    assert "name" in message
    assert "already exists" in message


def test_400_field_errors_without_detail():
    """If a 400 omits `detail` but includes `errors`, still surface the fields."""
    session = MagicMock()
    session.request.return_value = _response(
        status=400,
        json_body={"errors": {"version": ["Required."]}},
    )
    client = _client(session)

    with pytest.raises(SbomifyAPIError) as excinfo:
        client.create_component("x")
    assert "version" in str(excinfo.value)
    assert "Required" in str(excinfo.value)


def test_pagination_collects_all_pages():
    """Walks pages via sbomify's `pagination.has_next` field."""
    session = MagicMock()
    session.request.side_effect = [
        _response(
            json_body={
                "items": [{"id": "a"}, {"id": "b"}],
                "pagination": {"has_next": True, "total": 3, "page": 1},
            }
        ),
        _response(
            json_body={
                "items": [{"id": "c"}],
                "pagination": {"has_next": False, "total": 3, "page": 2},
            }
        ),
    ]
    client = _client(session)

    products = client.list_products()
    assert [p["id"] for p in products] == ["a", "b", "c"]
    assert session.request.call_count == 2


def test_pagination_terminates_on_empty_items():
    """Fallback termination: post-#960 servers return empty `items` for
    out-of-range pages, so the loop must stop even without a `pagination` hint."""
    session = MagicMock()
    session.request.side_effect = [
        _response(json_body={"items": [{"id": "a"}]}),
        _response(json_body={"items": []}),
    ]
    client = _client(session)

    products = client.list_products()
    assert [p["id"] for p in products] == ["a"]
    assert session.request.call_count == 2


def test_pagination_handles_results_key():
    session = MagicMock()
    session.request.side_effect = [
        _response(json_body={"results": [{"id": "a"}]}),
        _response(json_body={"results": []}),
    ]
    client = _client(session)
    products = client.list_products()
    assert [p["id"] for p in products] == ["a"]


def test_pagination_handles_bare_list():
    session = MagicMock()
    session.request.side_effect = [
        _response(json_body=[{"id": "a"}, {"id": "b"}]),
        _response(json_body=[]),
    ]
    client = _client(session)
    products = client.list_products()
    assert [p["id"] for p in products] == ["a", "b"]


def test_create_product_posts_name():
    session = MagicMock()
    session.request.return_value = _response(status=201, json_body={"id": "prod_1", "name": "demo"})
    client = _client(session)

    result = client.create_product("demo")

    args, call_kwargs = session.request.call_args
    assert args[0] == "POST"
    assert args[1].endswith("/api/v1/products")
    assert call_kwargs["json"] == {"name": "demo"}
    assert result["id"] == "prod_1"


def test_create_component_posts_name_and_type():
    session = MagicMock()
    session.request.return_value = _response(status=201, json_body={"id": "comp_1"})
    client = _client(session)
    client.create_component("svc")

    _, call_kwargs = session.request.call_args
    assert call_kwargs["json"] == {"name": "svc", "component_type": "bom"}


def test_patch_component_sends_kwargs():
    session = MagicMock()
    session.request.return_value = _response(json_body={"id": "comp_1"})
    client = _client(session)
    client.patch_component("comp_1", visibility="private", lifecycle_phase="build")

    args, call_kwargs = session.request.call_args
    assert args[0] == "PATCH"
    assert call_kwargs["json"] == {"visibility": "private", "lifecycle_phase": "build"}


def test_ensure_default_project_reuses_existing_match():
    session = MagicMock()
    # 1) list_projects: returns the existing helper.
    # 2) link_project_to_product POST.
    session.request.side_effect = [
        _response(
            json_body={
                "items": [{"id": "proj_1", "name": "demo-default", "products": []}],
                "pagination": {"has_next": False, "total": 1, "page": 1},
            }
        ),
        _response(status=201, json_body={}),
    ]
    client = _client(session)
    project = client.ensure_default_project({"id": "prod_1", "name": "demo"})

    assert project["id"] == "proj_1"
    # Cached for subsequent calls.
    project_again = client.ensure_default_project({"id": "prod_1", "name": "demo"})
    assert project_again is project


def test_ensure_default_project_creates_when_absent():
    session = MagicMock()
    session.request.side_effect = [
        _response(json_body={"items": [], "total": 0}),  # list_projects (page 1, empty)
        _response(status=201, json_body={"id": "proj_new", "name": "demo-default"}),  # create_project
        _response(status=201, json_body={}),  # link_project_to_product
    ]
    client = _client(session)
    project = client.ensure_default_project({"id": "prod_1", "name": "demo"})
    assert project["id"] == "proj_new"


def test_attach_component_to_product_patches_components_list():
    session = MagicMock()
    session.request.side_effect = [
        # list_projects → existing helper with no components
        _response(
            json_body={
                "items": [
                    {
                        "id": "proj_1",
                        "name": "demo-default",
                        "products": [{"id": "prod_1"}],
                        "components": [],
                    }
                ],
                "pagination": {"has_next": False, "total": 1, "page": 1},
            }
        ),
        # PATCH project components
        _response(json_body={"id": "proj_1"}),
    ]
    client = _client(session)
    client.attach_component_to_product({"id": "prod_1", "name": "demo"}, "comp_1")

    patch_call = session.request.call_args_list[-1]
    args, call_kwargs = patch_call
    assert args[0] == "PATCH"
    assert call_kwargs["json"] == {"component_ids": ["comp_1"]}


def test_contact_profiles_404_returns_empty():
    session = MagicMock()
    session.request.return_value = _response(status=404, json_body={"detail": "Not Found"})
    client = _client(session)
    assert client.list_contact_profiles() == []


def test_create_release_posts_required_fields():
    session = MagicMock()
    session.request.return_value = _response(status=201, json_body={"id": "rel_1", "name": "v0.0.0"})
    client = _client(session)
    client.create_release("prod_1", "v0.0.0", version="v0.0.0", is_prerelease=True)

    _, call_kwargs = session.request.call_args
    assert call_kwargs["json"] == {
        "product_id": "prod_1",
        "name": "v0.0.0",
        "is_prerelease": True,
        "version": "v0.0.0",
    }
