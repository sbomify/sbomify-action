"""Tests for Yocto component API calls."""

from unittest.mock import MagicMock, patch

import pytest

from sbomify_action._yocto.api import (
    create_component,
    get_component_id_by_name,
    get_or_create_component,
    list_components,
    patch_component_visibility,
)
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

        comp_id, was_created = create_component(API_BASE, TOKEN, "busybox")
        assert comp_id == "new-comp-1"
        assert was_created is True

        # Verify correct payload
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs["json"] == {"name": "busybox", "component_type": "sbom"}

    @patch("sbomify_action._yocto.api.requests.post")
    def test_400_with_invalid_data_raises(self, mock_post):
        # 400 with error_code != DUPLICATE_NAME still raises (no recovery)
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"detail": "Validation error", "error_code": "INVALID_DATA"}
        mock_post.return_value = mock_resp

        with pytest.raises(APIError, match="Failed to create component"):
            create_component(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.post")
    def test_400_without_error_code_raises(self, mock_post):
        # Regression pin: a 400 whose body OMITS error_code (older API
        # version, proxy stripping fields, etc.) must NOT trigger recovery.
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"detail": "Duplicate name"}
        mock_post.return_value = mock_resp

        with pytest.raises(APIError, match="Failed to create component"):
            create_component(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.get")
    @patch("sbomify_action._yocto.api.requests.post")
    def test_duplicate_name_recovers_existing_id(self, mock_post, mock_get):
        # POST returns 400 with DUPLICATE_NAME error_code
        post_resp = MagicMock()
        post_resp.ok = False
        post_resp.status_code = 400
        post_resp.json.return_value = {
            "detail": "A component with this name already exists in this team",
            "error_code": "DUPLICATE_NAME",
        }
        mock_post.return_value = post_resp

        # Lookup finds the existing component
        get_resp = MagicMock()
        get_resp.ok = True
        get_resp.status_code = 200
        get_resp.json.return_value = {
            "items": [{"id": "existing-id", "name": "busybox"}],
            "next": None,
        }
        mock_get.return_value = get_resp

        comp_id, was_created = create_component(API_BASE, TOKEN, "busybox")
        assert comp_id == "existing-id"
        assert was_created is False  # signals recovered, not newly created

    @patch("sbomify_action._yocto.api.requests.get")
    @patch("sbomify_action._yocto.api.requests.post")
    def test_409_duplicate_name_recovers_existing_id(self, mock_post, mock_get):
        # Future-proofing: API may migrate to REST-canonical 409 Conflict
        # (matching the DUPLICATE_ARTIFACT shape) while preserving error_code.
        post_resp = MagicMock()
        post_resp.ok = False
        post_resp.status_code = 409
        post_resp.json.return_value = {
            "detail": "A component with this name already exists in this team",
            "error_code": "DUPLICATE_NAME",
        }
        mock_post.return_value = post_resp

        get_resp = MagicMock()
        get_resp.ok = True
        get_resp.status_code = 200
        get_resp.json.return_value = {
            "items": [{"id": "existing-id", "name": "busybox"}],
            "next": None,
        }
        mock_get.return_value = get_resp

        comp_id, was_created = create_component(API_BASE, TOKEN, "busybox")
        assert comp_id == "existing-id"
        assert was_created is False

    @patch("sbomify_action._yocto.api.requests.get")
    @patch("sbomify_action._yocto.api.requests.post")
    def test_duplicate_name_but_lookup_misses_raises(self, mock_post, mock_get):
        post_resp = MagicMock()
        post_resp.ok = False
        post_resp.status_code = 400
        post_resp.json.return_value = {
            "detail": "duplicate",
            "error_code": "DUPLICATE_NAME",
        }
        mock_post.return_value = post_resp

        get_resp = MagicMock()
        get_resp.ok = True
        get_resp.status_code = 200
        get_resp.json.return_value = {"items": [], "next": None}
        mock_get.return_value = get_resp

        with pytest.raises(APIError, match="reported as duplicate"):
            create_component(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.post")
    def test_plan_limit_raises_plan_limit_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"detail": "You have reached the maximum 200 components allowed by your plan."}
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


class TestGetComponentIdByName:
    @patch("sbomify_action._yocto.api.requests.get")
    def test_finds_on_first_page(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "items": [
                {"id": "c1", "name": "other"},
                {"id": "c2", "name": "busybox"},
            ],
            "next": None,
        }
        mock_get.return_value = mock_resp

        assert get_component_id_by_name(API_BASE, TOKEN, "busybox") == "c2"

    @patch("sbomify_action._yocto.api.requests.get")
    def test_paginates_until_found(self, mock_get):
        page1 = MagicMock()
        page1.ok = True
        page1.status_code = 200
        page1.json.return_value = {"items": [{"id": "c1", "name": "other"}], "next": "page2"}
        page2 = MagicMock()
        page2.ok = True
        page2.status_code = 200
        page2.json.return_value = {"items": [{"id": "c2", "name": "busybox"}], "next": "page3"}
        mock_get.side_effect = [page1, page2]

        assert get_component_id_by_name(API_BASE, TOKEN, "busybox") == "c2"
        # Stops at page 2 — does not fetch page 3
        assert mock_get.call_count == 2

    @patch("sbomify_action._yocto.api.requests.get")
    def test_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"items": [], "next": None}
        mock_get.return_value = mock_resp

        assert get_component_id_by_name(API_BASE, TOKEN, "busybox") is None

    @patch("sbomify_action._yocto.api.requests.get")
    def test_404_raises(self, mock_get):
        # 404 on a collection endpoint signals misconfiguration (wrong base URL,
        # endpoint removed), not "no such component" — surface the real cause
        # rather than mask it as "could not be found via lookup".
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="Failed to look up component"):
            get_component_id_by_name(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.get")
    def test_500_raises(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="Failed to look up component"):
            get_component_id_by_name(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.get")
    def test_invalid_json_raises(self, mock_get):
        # Matches list_components behavior — don't silently swallow malformed
        # JSON as "not found", because that produces a misleading downstream
        # error in create_component's recovery path.
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Expecting value")
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="invalid JSON"):
            get_component_id_by_name(API_BASE, TOKEN, "busybox")

    @patch("sbomify_action._yocto.api.requests.get")
    def test_non_dict_response_raises(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = ["not", "a", "dict"]
        mock_get.return_value = mock_resp

        with pytest.raises(APIError, match="unexpected response type"):
            get_component_id_by_name(API_BASE, TOKEN, "busybox")


class TestPatchComponentVisibility:
    @patch("sbomify_action._yocto.api.requests.patch")
    def test_success(self, mock_patch):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_patch.return_value = mock_resp

        patch_component_visibility(API_BASE, TOKEN, "comp-1", "public")

        call_kwargs = mock_patch.call_args
        assert call_kwargs.kwargs["json"] == {"visibility": "public"}
        assert call_kwargs.kwargs["timeout"] == 60

    @patch("sbomify_action._yocto.api.requests.patch")
    def test_failure_logs_warning_no_raise(self, mock_patch):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 500
        mock_patch.return_value = mock_resp

        # Should not raise — visibility is best-effort
        patch_component_visibility(API_BASE, TOKEN, "comp-1", "public")

    @patch("sbomify_action._yocto.api.requests.patch")
    def test_connection_error_raises(self, mock_patch):
        import requests

        mock_patch.side_effect = requests.exceptions.ConnectionError()

        with pytest.raises(APIError, match="Failed to connect"):
            patch_component_visibility(API_BASE, TOKEN, "comp-1", "public")

    @patch("sbomify_action._yocto.api.requests.patch")
    def test_timeout_error_raises(self, mock_patch):
        import requests

        mock_patch.side_effect = requests.exceptions.Timeout()

        with pytest.raises(APIError, match="timed out"):
            patch_component_visibility(API_BASE, TOKEN, "comp-1", "public")


class TestGetOrCreateComponent:
    def test_cache_hit(self):
        cache = {"busybox": "cached-id"}
        comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)
        assert comp_id == "cached-id"
        assert was_created is False

    @patch("sbomify_action._yocto.api.create_component")
    def test_cache_miss_creates(self, mock_create):
        mock_create.return_value = ("new-id", True)
        cache: dict[str, str] = {}

        comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)
        assert comp_id == "new-id"
        assert was_created is True
        assert cache["busybox"] == "new-id"  # cache updated

    @patch("sbomify_action._yocto.api.create_component")
    def test_cache_miss_recovers_existing(self, mock_create):
        # Stale cache: API reports DUPLICATE_NAME, create_component recovers
        # the existing ID and signals was_created=False
        mock_create.return_value = ("existing-id", False)
        cache: dict[str, str] = {}

        comp_id, was_created = get_or_create_component(API_BASE, TOKEN, "busybox", cache)
        assert comp_id == "existing-id"
        assert was_created is False
        assert cache["busybox"] == "existing-id"

    @patch("sbomify_action._yocto.api.create_component")
    def test_create_failure_propagates(self, mock_create):
        mock_create.side_effect = APIError("boom")
        cache: dict[str, str] = {}

        with pytest.raises(APIError):
            get_or_create_component(API_BASE, TOKEN, "busybox", cache)
