"""Tests for Yocto component API calls."""

from unittest.mock import MagicMock, patch

import pytest

from sbomify_action._yocto.api import create_component, get_or_create_component, list_components
from sbomify_action.exceptions import APIError, PlanLimitError

API_BASE = "https://app.sbomify.com"
TOKEN = "test-token"


class TestListComponents:
    @patch("sbomify_action._yocto.api.requests.get")
    def test_single_page(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "items": [
                {"id": "comp-1", "name": "busybox"},
                {"id": "comp-2", "name": "zlib"},
            ],
            "next": None,
        }
        mock_get.return_value = mock_resp

        result = list_components(API_BASE, TOKEN)
        assert result == {"busybox": "comp-1", "zlib": "comp-2"}

    @patch("sbomify_action._yocto.api.requests.get")
    def test_pagination(self, mock_get):
        page1 = MagicMock()
        page1.ok = True
        page1.json.return_value = {
            "items": [{"id": "c1", "name": "pkg1"}],
            "next": "page2",
        }
        page2 = MagicMock()
        page2.ok = True
        page2.json.return_value = {
            "items": [{"id": "c2", "name": "pkg2"}],
            "next": None,
        }
        mock_get.side_effect = [page1, page2]

        result = list_components(API_BASE, TOKEN)
        assert result == {"pkg1": "c1", "pkg2": "c2"}
        assert mock_get.call_count == 2

    @patch("sbomify_action._yocto.api.requests.get")
    def test_empty_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"items": [], "next": None}
        mock_get.return_value = mock_resp

        result = list_components(API_BASE, TOKEN)
        assert result == {}

    @patch("sbomify_action._yocto.api.requests.get")
    def test_api_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="Failed to list components"):
            list_components(API_BASE, TOKEN)

    @patch("sbomify_action._yocto.api.requests.get")
    def test_connection_error(self, mock_get):
        import requests

        mock_get.side_effect = requests.exceptions.ConnectionError()

        with pytest.raises(APIError, match="Failed to connect"):
            list_components(API_BASE, TOKEN)

    @patch("sbomify_action._yocto.api.requests.get")
    def test_invalid_json_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="invalid JSON response"):
            list_components(API_BASE, TOKEN)

    @patch("sbomify_action._yocto.api.requests.get")
    def test_non_dict_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = ["not", "a", "dict"]
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="unexpected response type"):
            list_components(API_BASE, TOKEN)


class TestCreateComponent:
    @patch("sbomify_action._yocto.api.requests.post")
    def test_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"id": "new-comp-1", "name": "busybox"}
        mock_post.return_value = mock_resp

        result = create_component(API_BASE, TOKEN, "busybox")
        assert result == "new-comp-1"

        # Verify correct payload
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs["json"] == {"name": "busybox", "component_type": "sbom"}

    @patch("sbomify_action._yocto.api.requests.post")
    def test_failure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"detail": "Duplicate name"}
        mock_post.return_value = mock_resp

        with pytest.raises(APIError, match="Failed to create component"):
            create_component(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.post")
    def test_plan_limit_raises_plan_limit_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "detail": "You have reached the maximum 200 components allowed by your plan."
        }
        mock_post.return_value = mock_resp

        with pytest.raises(PlanLimitError, match="maximum"):
            create_component(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.post")
    def test_403_without_limit_raises_api_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"detail": "Permission denied"}
        mock_post.return_value = mock_resp

        with pytest.raises(APIError) as exc_info:
            create_component(API_BASE, TOKEN, "busybox")
        assert not isinstance(exc_info.value, PlanLimitError)

    @patch("sbomify_action._yocto.api.requests.post")
    def test_no_id_in_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"name": "busybox"}  # missing id
        mock_post.return_value = mock_resp

        with pytest.raises(APIError, match="no id returned"):
            create_component(API_BASE, TOKEN, "busybox")


class TestGetOrCreateComponent:
    def test_cache_hit(self):
        cache = {"busybox": "cached-id"}
        comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)
        assert comp_id == "cached-id"
        assert was_created is False

    @patch("sbomify_action._yocto.api.create_component")
    def test_cache_miss_creates(self, mock_create):
        mock_create.return_value = "new-id"
        cache: dict[str, str] = {}

        comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)
        assert comp_id == "new-id"
        assert was_created is True
        assert cache["busybox"] == "new-id"  # cache updated

    @patch("sbomify_action._yocto.api.create_component")
    def test_create_failure_propagates(self, mock_create):
        mock_create.side_effect = APIError("boom")
        cache: dict[str, str] = {}

        with pytest.raises(APIError):
            get_or_create_component(API_BASE, TOKEN, "busybox", cache)
