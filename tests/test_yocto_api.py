"""Tests for the Yocto component-API facade.

The functional API in ``sbomify_action._yocto.api`` is now a thin
delegation layer over ``SbomifyApiClient``. Detailed semantics
(pagination, DUPLICATE_NAME recovery, plan-limit detection, etc.) are
covered in ``test_sbomify_api.py``. These tests pin the *delegation
contract* — each Yocto-facing function must call the matching client
method with the matching arguments.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sbomify_action._yocto.api import (
    _iter_components,
    create_component,
    get_component_id_by_name,
    get_or_create_component,
    list_components,
    patch_component_visibility,
)
from sbomify_action.exceptions import APIError

API_BASE = "https://app.sbomify.com"
TOKEN = "test-token"


@pytest.fixture
def stub_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the per-call client factory with a single MagicMock instance."""
    stub = MagicMock()
    monkeypatch.setattr("sbomify_action._yocto.api._client", lambda _base, _token: stub)
    return stub


def test_list_components_delegates(stub_client: MagicMock) -> None:
    stub_client.list_components_by_name.return_value = {"busybox": "comp-1"}

    result = list_components(API_BASE, TOKEN)

    assert result == {"busybox": "comp-1"}
    stub_client.list_components_by_name.assert_called_once_with()


def test_get_component_id_by_name_delegates(stub_client: MagicMock) -> None:
    stub_client.get_component_id_by_name.return_value = "comp-2"

    assert get_component_id_by_name(API_BASE, TOKEN, "busybox") == "comp-2"
    stub_client.get_component_id_by_name.assert_called_once_with("busybox")


def test_create_component_delegates(stub_client: MagicMock) -> None:
    stub_client.create_component.return_value = ("new-id", True)

    comp_id, was_created = create_component(API_BASE, TOKEN, "busybox")

    assert comp_id == "new-id"
    assert was_created is True
    stub_client.create_component.assert_called_once_with("busybox")


def test_patch_component_visibility_delegates(stub_client: MagicMock) -> None:
    patch_component_visibility(API_BASE, TOKEN, "comp-1", "public")
    stub_client.patch_component_visibility.assert_called_once_with("comp-1", "public")


def test_iter_components_delegates(stub_client: MagicMock) -> None:
    stub_client.iter_components.return_value = iter([{"id": "x"}])

    items = list(_iter_components(API_BASE, TOKEN, "list components"))

    assert items == [{"id": "x"}]
    stub_client.iter_components.assert_called_once_with(error_context="list components")


def test_get_or_create_component_cache_hit(stub_client: MagicMock) -> None:
    # The client provides its own cache check; verify the facade still passes
    # the cache through.
    stub_client.get_or_create_component.return_value = ("cached", False)

    cache: dict[str, str] = {"busybox": "cached"}
    comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)

    assert comp_id == "cached"
    assert was_created is False
    stub_client.get_or_create_component.assert_called_once_with("busybox", cache)


def test_get_or_create_component_cache_miss(stub_client: MagicMock) -> None:
    stub_client.get_or_create_component.return_value = ("new-id", True)

    cache: dict[str, str] = {}
    comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)

    assert comp_id == "new-id"
    assert was_created is True
    stub_client.get_or_create_component.assert_called_once_with("busybox", cache)


def test_create_component_error_propagates(stub_client: MagicMock) -> None:
    stub_client.create_component.side_effect = APIError("boom")
    with pytest.raises(APIError):
        create_component(API_BASE, TOKEN, "busybox")
