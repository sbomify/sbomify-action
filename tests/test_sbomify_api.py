"""Tests for sbomify_action.sbomify_api.SbomifyApiClient."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

from sbomify_action.exceptions import APIError, AuthError, PlanLimitError
from sbomify_action.sbomify_api import SbomifyApiClient


class _FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: Any = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.headers = headers or {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        if isinstance(self._json, Exception):
            raise self._json
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


def _client_with(responses: list[_FakeResponse]) -> tuple[SbomifyApiClient, MagicMock]:
    """Build a SbomifyApiClient whose Session yields the given responses in order."""
    session = MagicMock(spec=requests.Session)
    session.request = MagicMock(side_effect=responses)
    client = SbomifyApiClient("https://api.test", "token", session=session)
    return client, session


# ----------------------------------------------------------------------
# plumbing


def test_request_strips_trailing_slash() -> None:
    session = MagicMock(spec=requests.Session)
    session.request = MagicMock(return_value=_FakeResponse(200, {}))
    client = SbomifyApiClient("https://api.test/", "tok", session=session)
    client._request("GET", "/x")
    args, kwargs = session.request.call_args
    # session.request is called as (method, url, ...kwargs) — check both positions.
    url = kwargs.get("url", args[1] if len(args) > 1 else None)
    assert url == "https://api.test/x"


def test_request_401_raises_auth_error() -> None:
    client, _ = _client_with([_FakeResponse(401, {"detail": "bad token"})])
    with pytest.raises(AuthError):
        client._request("GET", "/anything")


def test_request_connection_error_raises_api_error() -> None:
    session = MagicMock(spec=requests.Session)
    session.request = MagicMock(side_effect=requests.exceptions.ConnectionError("boom"))
    client = SbomifyApiClient("https://api.test", "tok", session=session)
    with pytest.raises(APIError, match="connect"):
        client._request("GET", "/x")


def test_request_timeout_raises_api_error() -> None:
    session = MagicMock(spec=requests.Session)
    session.request = MagicMock(side_effect=requests.exceptions.Timeout("slow"))
    client = SbomifyApiClient("https://api.test", "tok", session=session)
    with pytest.raises(APIError, match="timed out"):
        client._request("GET", "/x")


# ----------------------------------------------------------------------
# whoami


def test_whoami_success() -> None:
    client, _ = _client_with([_FakeResponse(200, {"items": []})])
    client.whoami()


def test_whoami_401() -> None:
    client, _ = _client_with([_FakeResponse(401)])
    with pytest.raises(AuthError):
        client.whoami()


def test_whoami_500_raises_api_error() -> None:
    client, _ = _client_with([_FakeResponse(500, text="boom")])
    with pytest.raises(APIError, match="authenticate"):
        client.whoami()


# ----------------------------------------------------------------------
# pagination


def test_paginate_stops_on_pagination_has_next_false() -> None:
    client, session = _client_with(
        [
            _FakeResponse(
                200,
                {
                    "items": [{"id": "a"}, {"id": "b"}],
                    "pagination": {"has_next": False},
                },
            ),
        ]
    )
    items = list(client._paginate("/x"))
    assert [i["id"] for i in items] == ["a", "b"]
    assert session.request.call_count == 1


def test_paginate_walks_multiple_pages() -> None:
    client, session = _client_with(
        [
            _FakeResponse(200, {"items": [{"id": "a"}], "next": "page2"}),
            _FakeResponse(200, {"items": [{"id": "b"}], "next": None}),
        ]
    )
    items = list(client._paginate("/x"))
    assert [i["id"] for i in items] == ["a", "b"]
    assert session.request.call_count == 2


def test_paginate_stops_on_empty_page() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(200, {"items": [{"id": "a"}]}),
            _FakeResponse(200, {"items": []}),
        ]
    )
    items = list(client._paginate("/x"))
    assert [i["id"] for i in items] == ["a"]


def test_paginate_handles_bare_list_response() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(200, [{"id": "a"}]),
            _FakeResponse(200, []),
        ]
    )
    items = list(client._paginate("/x"))
    assert [i["id"] for i in items] == ["a"]


def test_paginate_invalid_json_raises() -> None:
    client, _ = _client_with([_FakeResponse(200, json_data=ValueError("bad"))])
    with pytest.raises(APIError, match="invalid JSON"):
        list(client._paginate("/x", error_context="list components"))


# ----------------------------------------------------------------------
# components


def test_iter_components_yields_each_item() -> None:
    client, _ = _client_with(
        [_FakeResponse(200, {"items": [{"id": "1"}, {"id": "2"}], "pagination": {"has_next": False}})]
    )
    items = list(client.iter_components())
    assert [i["id"] for i in items] == ["1", "2"]


def test_list_components_by_name() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(
                200,
                {
                    "items": [{"id": "1", "name": "alpha"}, {"id": "2", "name": "beta"}],
                    "pagination": {"has_next": False},
                },
            )
        ]
    )
    assert client.list_components_by_name() == {"alpha": "1", "beta": "2"}


def test_get_component_id_by_name_finds_match() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(
                200,
                {
                    "items": [{"id": "1", "name": "alpha"}, {"id": "2", "name": "beta"}],
                    "pagination": {"has_next": False},
                },
            )
        ]
    )
    assert client.get_component_id_by_name("beta") == "2"


def test_get_component_id_by_name_returns_none_when_missing() -> None:
    client, _ = _client_with(
        [_FakeResponse(200, {"items": [{"id": "1", "name": "alpha"}], "pagination": {"has_next": False}})]
    )
    assert client.get_component_id_by_name("missing") is None


def test_create_component_success() -> None:
    client, _ = _client_with([_FakeResponse(201, {"id": "new-id", "name": "foo"})])
    comp_id, was_created = client.create_component("foo", component_type="bom")
    assert comp_id == "new-id"
    assert was_created is True


def test_create_component_rejects_invalid_type_without_request() -> None:
    """A component_type the backend doesn't accept (e.g. the old "sbom"
    literal) must fail fast client-side with a clear ValueError, never
    reaching the network to come back as an opaque 422."""
    client, session = _client_with([])
    with pytest.raises(ValueError, match="Invalid component_type 'sbom'"):
        client.create_component("foo", component_type="sbom")
    session.request.assert_not_called()


def test_create_component_recovers_from_duplicate_name() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(400, {"error_code": "DUPLICATE_NAME", "detail": "exists"}),
            _FakeResponse(
                200,
                {"items": [{"id": "existing-id", "name": "foo"}], "pagination": {"has_next": False}},
            ),
        ]
    )
    comp_id, was_created = client.create_component("foo", component_type="bom")
    assert comp_id == "existing-id"
    assert was_created is False


def test_create_component_plan_limit() -> None:
    client, _ = _client_with([_FakeResponse(403, {"detail": "maximum components reached"})])
    with pytest.raises(PlanLimitError):
        client.create_component("foo", component_type="bom")


def test_create_component_403_validation_list_is_not_plan_limit() -> None:
    """A 403 whose detail is a pydantic *list* (not the plain plan-limit
    string) must raise APIError — even when the collapsed message contains
    the word 'maximum' (eg a max-length validation error). Plan-limit
    detection keys off the raw string detail, not the cleaned text, so this
    can't be misclassified as a PlanLimitError."""
    client, _ = _client_with(
        [
            _FakeResponse(
                403,
                {
                    "detail": [
                        {
                            "type": "string_too_long",
                            "loc": ["body", "payload", "name"],
                            "msg": "String should have at most 255 characters (maximum length)",
                        }
                    ]
                },
            )
        ]
    )
    with pytest.raises(APIError) as exc:
        client.create_component("foo", component_type="bom")
    assert not isinstance(exc.value, PlanLimitError)
    # The readable message is still surfaced.
    assert "name:" in str(exc.value)


def test_clean_validation_error_collapses_pydantic_list() -> None:
    """A pydantic/django-ninja 422 'detail' (list of per-field error dicts)
    collapses to readable '<field>: <msg>' text instead of a raw repr dump."""
    detail = [
        {
            "type": "enum",
            "loc": ["body", "payload", "component_type"],
            "msg": "Input should be 'document' or 'bom'",
            "ctx": {"expected": "'document' or 'bom'"},
        }
    ]
    cleaned = SbomifyApiClient._clean_validation_error(detail)
    assert cleaned == "component_type: Input should be 'document' or 'bom'"


def test_clean_validation_error_passthrough_and_none() -> None:
    assert SbomifyApiClient._clean_validation_error("plain message") == "plain message"
    assert SbomifyApiClient._clean_validation_error(None) is None
    assert SbomifyApiClient._clean_validation_error([]) is None


def test_create_component_422_renders_clean_detail() -> None:
    """An unexpected 422 (non-DUPLICATE_NAME) surfaces readable text in the
    raised APIError — not a raw Python dict repr."""
    client, _ = _client_with(
        [
            _FakeResponse(
                422,
                {
                    "detail": [
                        {
                            "type": "enum",
                            "loc": ["body", "payload", "component_type"],
                            "msg": "Input should be 'document' or 'bom'",
                        }
                    ]
                },
            )
        ]
    )
    with pytest.raises(APIError) as exc:
        client.create_component("foo", component_type="bom")
    message = str(exc.value)
    assert "component_type: Input should be 'document' or 'bom'" in message
    assert "{'type'" not in message  # no raw dict repr leaked to the user


def test_get_or_create_component_uses_cache() -> None:
    client, session = _client_with([])
    cache = {"foo": "cached-id"}
    comp_id, created = client.get_or_create_component("foo", cache, component_type="bom")
    assert comp_id == "cached-id"
    assert created is False
    session.request.assert_not_called()


def test_patch_component() -> None:
    client, _ = _client_with([_FakeResponse(200, {"id": "x", "visibility": "public"})])
    result = client.patch_component("x", visibility="public")
    assert result["visibility"] == "public"


def test_patch_component_visibility_swallows_errors() -> None:
    client, _ = _client_with([_FakeResponse(500)])
    # Should not raise — visibility is best-effort.
    client.patch_component_visibility("x", "public")


def test_get_augmentation_meta() -> None:
    client, _ = _client_with([_FakeResponse(200, {"supplier": {"name": "Acme"}})])
    meta = client.get_augmentation_meta("comp-1")
    assert meta == {"supplier": {"name": "Acme"}}


def test_get_augmentation_meta_404_raises() -> None:
    client, _ = _client_with([_FakeResponse(404, {"detail": "no such component"})])
    with pytest.raises(APIError):
        client.get_augmentation_meta("comp-1")


# ----------------------------------------------------------------------
# products


def test_list_products_paginates() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(
                200,
                {"items": [{"id": "p1", "name": "First"}], "pagination": {"has_next": False}},
            )
        ]
    )
    products = client.list_products()
    assert products[0]["id"] == "p1"


def test_create_product() -> None:
    client, _ = _client_with([_FakeResponse(201, {"id": "p1", "name": "X"})])
    product = client.create_product("X")
    assert product["id"] == "p1"


def test_attach_components_unions_existing() -> None:
    client, session = _client_with(
        [
            _FakeResponse(200, {"id": "p1", "component_ids": ["c1"]}),
            _FakeResponse(200, {"id": "p1"}),
        ]
    )
    client.attach_components_to_product("p1", ["c2", "c1"])
    patch_call = session.request.call_args_list[1]
    assert patch_call.kwargs["json"] == {"component_ids": ["c1", "c2"]}


def test_attach_components_noop_when_already_attached() -> None:
    client, session = _client_with([_FakeResponse(200, {"id": "p1", "component_ids": ["c1"]})])
    client.attach_components_to_product("p1", ["c1"])
    # Only the GET should have fired — the PATCH must be skipped.
    assert session.request.call_count == 1


def test_attach_components_empty_input_is_noop() -> None:
    client, session = _client_with([])
    client.attach_components_to_product("p1", [])
    session.request.assert_not_called()


# ----------------------------------------------------------------------
# contact profiles


def test_list_contact_profiles_404_returns_empty() -> None:
    client, _ = _client_with([_FakeResponse(404)])
    assert client.list_contact_profiles("acme-team") == []


def test_list_contact_profiles_success() -> None:
    # Real endpoint returns a bare list — `[{...}, {...}]` — not a
    # paginated envelope. Filtered out non-dict entries defensively.
    client, _ = _client_with([_FakeResponse(200, [{"id": "cp1", "name": "Team"}])])
    profiles = client.list_contact_profiles("acme-team")
    assert profiles[0]["id"] == "cp1"


def test_list_workspaces_returns_workspace_keys() -> None:
    client, _ = _client_with([_FakeResponse(200, [{"key": "acme", "name": "Acme Inc"}])])
    workspaces = client.list_workspaces()
    assert workspaces[0]["key"] == "acme"


def test_list_workspaces_handles_non_list_body() -> None:
    client, _ = _client_with([_FakeResponse(200, {"detail": "wrong shape"})])
    assert client.list_workspaces() == []


# ----------------------------------------------------------------------
# releases


def test_create_release_success() -> None:
    client, _ = _client_with([_FakeResponse(201, {"id": "r1"})])
    rid = client.create_release("p1", "1.0.0")
    assert rid == "r1"


def test_create_release_recovers_from_duplicate_name() -> None:
    client, _ = _client_with(
        [
            _FakeResponse(400, {"error_code": "DUPLICATE_NAME"}),
            _FakeResponse(200, {"items": [{"id": "existing-rid", "name": "1.0.0"}]}),
        ]
    )
    rid = client.create_release("p1", "1.0.0")
    assert rid == "existing-rid"


def test_check_release_exists() -> None:
    client, _ = _client_with([_FakeResponse(200, {"items": [{"id": "r1", "version": "1.0.0"}]})])
    assert client.check_release_exists("p1", "1.0.0") is True


def test_tag_sbom_with_release_idempotent_on_duplicate() -> None:
    client, _ = _client_with([_FakeResponse(409, {"error_code": "DUPLICATE_ARTIFACT"})])
    # Must NOT raise.
    client.tag_sbom_with_release("s1", "r1")


def test_tag_sbom_with_release_raises_other_errors() -> None:
    client, _ = _client_with([_FakeResponse(500, {"detail": "boom"})])
    with pytest.raises(APIError):
        client.tag_sbom_with_release("s1", "r1")


# ----------------------------------------------------------------------
# upload


def test_upload_sbom_returns_raw_response() -> None:
    client, session = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    response = client.upload_sbom("c1", b"{}", sbom_format="cyclonedx")
    assert response.ok is True
    call = session.request.call_args
    assert call.kwargs["data"] == b"{}"


def test_upload_sbom_sets_content_encoding_when_provided() -> None:
    client, session = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    client.upload_sbom("c1", b"x", content_encoding="gzip")
    call = session.request.call_args
    assert call.kwargs["headers"]["Content-Encoding"] == "gzip"


def test_upload_sbom_does_not_raise_on_non_2xx() -> None:
    # Destination layer needs the raw response to map errors itself; the
    # client must not raise on 409/404/etc here.
    client, _ = _client_with([_FakeResponse(409, {"error_code": "DUPLICATE_ARTIFACT"})])
    response = client.upload_sbom("c1", b"{}")
    assert response.status_code == 409


def test_upload_sbom_sends_bom_type_param() -> None:
    client, session = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    client.upload_sbom("c1", b"{}", sbom_format="cyclonedx", bom_type="vex")
    call = session.request.call_args
    assert call.kwargs["params"] == {"bom_type": "vex"}


def test_upload_sbom_non_string_bom_type_raises_value_error() -> None:
    """The public client fails a non-string bom_type as ValueError, matching
    UploadInput, instead of an AttributeError on .lower()."""
    client, _ = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    with pytest.raises(ValueError, match="Invalid bom_type"):
        client.upload_sbom("c1", b"{}", sbom_format="cyclonedx", bom_type=123)  # type: ignore[arg-type]


def test_upload_sbom_invalid_bom_type_raises_value_error() -> None:
    """The client rejects unknown bom_type values instead of forwarding
    ?bom_type=nope to the backend."""
    client, _ = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    with pytest.raises(ValueError, match="Invalid bom_type"):
        client.upload_sbom("c1", b"{}", sbom_format="cyclonedx", bom_type="nope")


def test_upload_sbom_normalizes_bom_type_case() -> None:
    """The public client API lower-cases bom_type like the rest of the stack;
    the backend enum is lowercase and would reject ?bom_type=VEX."""
    client, session = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    client.upload_sbom("c1", b"{}", sbom_format="cyclonedx", bom_type="VEX")
    call = session.request.call_args
    assert call.kwargs["params"] == {"bom_type": "vex"}


def test_upload_sbom_omits_bom_type_param_by_default() -> None:
    client, session = _client_with([_FakeResponse(200, {"sbom_id": "s1"})])
    client.upload_sbom("c1", b"{}", sbom_format="cyclonedx")
    call = session.request.call_args
    assert call.kwargs["params"] is None


# ----------------------------------------------------------------------
# OIDC trusted publishing


def test_create_oidc_binding_201_returns_true_and_posts_name_only() -> None:
    client, session = _client_with([_FakeResponse(201, {"id": "b1", "repository": "acme/widget"})])
    created = client.create_oidc_binding("comp-1", "acme/widget")
    assert created is True
    call = session.request.call_args
    assert call.args[0] == "POST"
    assert call.args[1].endswith("/api/v1/auth/oidc/github/bindings")
    # Name only — no GitHub IDs (the backend resolves public / defers private).
    # No `provider` field: GitHub is the only provider the wizard supports today and
    # the URL itself is provider-specific (a second provider gets its own method).
    assert call.kwargs["json"] == {"component_id": "comp-1", "repository": "acme/widget"}


def test_create_oidc_binding_409_already_bound_returns_false() -> None:
    """A 409 (repository already bound) is idempotent success, not an error —
    so re-running the wizard doesn't surface a scary failure."""
    client, _ = _client_with([_FakeResponse(409, {"detail": "This repository is already bound to this component."})])
    created = client.create_oidc_binding("comp-1", "acme/widget")
    assert created is False


@pytest.mark.parametrize("status", [400, 404, 500])
def test_create_oidc_binding_other_errors_raise(status: int) -> None:
    """400 (unresolvable/private repo), 404 (not owner/admin or no component),
    5xx → APIError, so the wizard logs a warning and falls back to manual
    instructions."""
    client, _ = _client_with([_FakeResponse(status, {"detail": "nope"})])
    with pytest.raises(APIError):
        client.create_oidc_binding("comp-1", "acme/widget")


def test_upload_sbom_explicit_sbom_sends_no_bom_type_param() -> None:
    """bom_type='sbom' is the default artifact kind; the request matches an unset bom_type."""
    from unittest.mock import MagicMock, patch

    from sbomify_action.sbomify_api import SbomifyApiClient

    client = SbomifyApiClient("https://api.example.com", "tok")
    with patch.object(client, "_request", return_value=MagicMock()) as req:
        client.upload_sbom(component_id="c1", sbom_payload=b"{}", sbom_format="cyclonedx", bom_type="sbom")
    assert req.call_args.kwargs["params"] is None
