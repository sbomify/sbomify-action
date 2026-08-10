"""Tests for the release-related API facade.

Most of the functions in ``_processors/releases_api.py`` now delegate
straight to ``SbomifyApiClient``; their semantics are pinned in
``test_sbomify_api.py``. Here we keep the delegation contract checked
and exercise the one helper that doesn't talk to the API:
``get_release_friendly_name``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sbomify_action._processors.releases_api import (
    check_release_exists,
    create_release,
    get_release_details,
    get_release_friendly_name,
    get_release_id,
    get_release_id_by_name,
    tag_sbom_with_release,
)
from sbomify_action.exceptions import APIError

API_BASE = "https://api.test.com/v1"
TOKEN = "test-token"


@pytest.fixture
def stub_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    stub = MagicMock()
    monkeypatch.setattr("sbomify_action._processors.releases_api._client", lambda _base, _token: stub)
    return stub


# ----------------------------------------------------------------------
# delegation pins


def test_check_release_exists_delegates(stub_client: MagicMock) -> None:
    stub_client.check_release_exists.return_value = True
    assert check_release_exists(API_BASE, TOKEN, "prod-1", "v1.0.0") is True
    stub_client.check_release_exists.assert_called_once_with("prod-1", "v1.0.0")


def test_get_release_id_delegates(stub_client: MagicMock) -> None:
    stub_client.get_release_id.return_value = "rel-1"
    assert get_release_id(API_BASE, TOKEN, "prod-1", "v1.0.0") == "rel-1"
    stub_client.get_release_id.assert_called_once_with("prod-1", "v1.0.0")


def test_get_release_id_by_name_delegates(stub_client: MagicMock) -> None:
    stub_client.get_release_id_by_name.return_value = "rel-1"
    assert get_release_id_by_name(API_BASE, TOKEN, "prod-1", "v1.0.0") == "rel-1"
    stub_client.get_release_id_by_name.assert_called_once_with("prod-1", "v1.0.0")


def test_get_release_details_delegates(stub_client: MagicMock) -> None:
    stub_client.get_release_details.return_value = {"id": "rel-1", "version": "v1.0.0"}
    assert get_release_details(API_BASE, TOKEN, "prod-1", "v1.0.0") == {"id": "rel-1", "version": "v1.0.0"}
    stub_client.get_release_details.assert_called_once_with("prod-1", "v1.0.0")


def test_create_release_delegates(stub_client: MagicMock) -> None:
    stub_client.create_release.return_value = "rel-new"
    assert create_release(API_BASE, TOKEN, "prod-1", "v1.0.0") == "rel-new"
    # is_prerelease=None rather than omitted: the client distinguishes "not a
    # prerelease" from "we could not tell", and only the second should leave
    # the backend's own default in place.
    stub_client.create_release.assert_called_once_with("prod-1", "v1.0.0", is_prerelease=None)


def test_create_release_forwards_prerelease(stub_client: MagicMock) -> None:
    """The wrapper used to drop this, so every alpha was recorded as final."""
    stub_client.create_release.return_value = "rel-new"

    create_release(API_BASE, TOKEN, "prod-1", "6.1a1", is_prerelease=True)

    stub_client.create_release.assert_called_once_with("prod-1", "6.1a1", is_prerelease=True)


def test_create_release_error_propagates(stub_client: MagicMock) -> None:
    stub_client.create_release.side_effect = APIError("boom")
    with pytest.raises(APIError):
        create_release(API_BASE, TOKEN, "prod-1", "v1.0.0")


def test_tag_sbom_with_release_delegates(stub_client: MagicMock) -> None:
    tag_sbom_with_release(API_BASE, TOKEN, "sbom-1", "rel-1")
    stub_client.tag_sbom_with_release.assert_called_once_with("sbom-1", "rel-1")


# ----------------------------------------------------------------------
# pure helper — no I/O


class TestFriendlyName:
    def test_custom_name(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": "Major Feature Release"}
        assert get_release_friendly_name(details, "v1.0.0") == "'Major Feature Release' (v1.0.0)"

    def test_default_name_equals_version(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": "v1.0.0"}
        assert get_release_friendly_name(details, "v1.0.0") == "v1.0.0"

    def test_legacy_default_name(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": "Release v1.0.0"}
        assert get_release_friendly_name(details, "v1.0.0") == "v1.0.0"

    def test_no_details(self) -> None:
        assert get_release_friendly_name(None, "v1.0.0") == "v1.0.0"

    def test_empty_name(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": ""}
        assert get_release_friendly_name(details, "v1.0.0") == "v1.0.0"

    def test_none_name(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": None}
        assert get_release_friendly_name(details, "v1.0.0") == "v1.0.0"

    def test_whitespace_only_name(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": "   "}
        assert get_release_friendly_name(details, "v1.0.0") == "v1.0.0"

    def test_trims_whitespace(self) -> None:
        details = {"id": "rel1", "version": "v1.0.0", "name": "  Custom Release Name  "}
        assert get_release_friendly_name(details, "v1.0.0") == "'Custom Release Name' (v1.0.0)"
