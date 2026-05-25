"""Tests for sbomify_action.oidc — GitHub Actions trusted-publishing flow."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from sbomify_action import oidc
from sbomify_action.oidc import (
    DEFAULT_AUDIENCE,
    OIDCError,
    OIDCExchangeResult,
    exchange_oidc_token,
    is_oidc_available,
)


def _response(*, status: int = 200, json_body: Any = None, text: str = "") -> MagicMock:
    """Build a `requests.Response`-shaped mock."""
    response = MagicMock()
    response.status_code = status
    response.text = text or (str(json_body) if json_body else "")
    if isinstance(json_body, Exception):
        response.json.side_effect = json_body
    else:
        response.json.return_value = json_body if json_body is not None else {}
    return response


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry backoff would slow the suite for no benefit."""
    monkeypatch.setattr(oidc.time, "sleep", lambda _seconds: None)


@pytest.fixture
def gha_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for the GitHub Actions runtime env."""
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://gha-token.example/_apis/oidc")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha-request-token")
    monkeypatch.delenv("SBOMIFY_OIDC_AUDIENCE", raising=False)


# ---------------------------------------------------------------- detection


def test_is_oidc_available_requires_both_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    assert is_oidc_available() is False

    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example/oidc")
    assert is_oidc_available() is False  # only one half

    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x")
    assert is_oidc_available() is True


# ---------------------------------------------------------------- guard rails


def test_exchange_requires_component_id(gha_env: None) -> None:
    with pytest.raises(OIDCError, match="component_id is required"):
        exchange_oidc_token(component_id="", api_base_url="https://app.sbomify.test")


def test_exchange_requires_oidc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    with pytest.raises(OIDCError, match="id-token: write"):
        exchange_oidc_token(component_id="comp-1", api_base_url="https://app.sbomify.test")


# ---------------------------------------------------------------- happy path


def test_exchange_full_round_trip_calls_github_then_sbomify(gha_env: None) -> None:
    github_jwt = "eyJ.fake.jwt"
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        calls.append(("GET", {"url": url, **kwargs}))
        return _response(json_body={"value": github_jwt, "count": 1})

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        calls.append(("POST", {"url": url, **kwargs}))
        return _response(
            json_body={
                "access_token": "sbom-short-lived-xyz",
                "expires_in": 900,
                "component_id": "comp-1",
                "token_type": "Bearer",
            }
        )

    with (
        patch.object(oidc.requests, "get", side_effect=fake_get),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        result = exchange_oidc_token(component_id="comp-1", api_base_url="https://app.sbomify.test/")

    assert result == OIDCExchangeResult(
        access_token="sbom-short-lived-xyz",
        expires_in_seconds=900,
        component_id="comp-1",
    )

    assert [method for method, _ in calls] == ["GET", "POST"]

    gh_call = calls[0][1]
    assert gh_call["url"] == "https://gha-token.example/_apis/oidc"
    assert gh_call["params"] == {"audience": DEFAULT_AUDIENCE}
    assert gh_call["headers"]["Authorization"] == "Bearer gha-request-token"

    sbom_call = calls[1][1]
    # `api_base_url` had a trailing slash — it should be stripped.
    assert sbom_call["url"] == "https://app.sbomify.test/api/v1/auth/oidc/github/exchange"
    assert sbom_call["json"] == {"component_id": "comp-1"}
    assert sbom_call["headers"]["Authorization"] == f"Bearer {github_jwt}"
    assert sbom_call["headers"]["Content-Type"] == "application/json"


def test_audience_can_be_overridden_via_env(gha_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOMIFY_OIDC_AUDIENCE", "staging.sbomify.com")
    seen_audience: list[str] = []

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        seen_audience.append(kwargs["params"]["audience"])
        return _response(json_body={"value": "jwt"})

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        return _response(json_body={"access_token": "tok", "expires_in": 900, "component_id": "c"})

    with (
        patch.object(oidc.requests, "get", side_effect=fake_get),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert seen_audience == ["staging.sbomify.com"]


def test_audience_param_wins_over_env(gha_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOMIFY_OIDC_AUDIENCE", "env-audience")
    seen_audience: list[str] = []

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        seen_audience.append(kwargs["params"]["audience"])
        return _response(json_body={"value": "jwt"})

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        return _response(json_body={"access_token": "tok", "expires_in": 900, "component_id": "c"})

    with (
        patch.object(oidc.requests, "get", side_effect=fake_get),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        exchange_oidc_token(
            component_id="c",
            api_base_url="https://app.sbomify.test",
            audience="explicit-audience",
        )

    assert seen_audience == ["explicit-audience"]


# ---------------------------------------------------------------- GitHub mint failures


def test_github_returns_4xx_does_not_retry(gha_env: None) -> None:
    call_count = 0

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return _response(status=400, text="bad audience")

    with patch.object(oidc.requests, "get", side_effect=fake_get):
        with pytest.raises(OIDCError, match="GitHub OIDC mint rejected"):
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert call_count == 1, "4xx should not retry"


def test_github_returns_5xx_retries_then_fails(gha_env: None) -> None:
    call_count = 0

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return _response(status=503, text="upstream down")

    with patch.object(oidc.requests, "get", side_effect=fake_get):
        with pytest.raises(OIDCError, match="GitHub OIDC mint failed after"):
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert call_count == 3, "transient failures should retry up to _MAX_ATTEMPTS"


def test_github_returns_5xx_then_success_recovers(gha_env: None) -> None:
    responses = iter(
        [
            _response(status=500),
            _response(json_body={"value": "recovered-jwt"}),
        ]
    )

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        return _response(json_body={"access_token": "tok", "expires_in": 900, "component_id": "c"})

    with (
        patch.object(oidc.requests, "get", side_effect=lambda *a, **k: next(responses)),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        result = exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert result.access_token == "tok"


def test_github_network_error_retries(gha_env: None) -> None:
    call_count = 0

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise requests.exceptions.ConnectionError("temporarily down")
        return _response(json_body={"value": "jwt"})

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        return _response(json_body={"access_token": "tok", "expires_in": 900, "component_id": "c"})

    with (
        patch.object(oidc.requests, "get", side_effect=fake_get),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        result = exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert call_count == 3
    assert result.access_token == "tok"


def test_github_missing_value_in_payload_raises(gha_env: None) -> None:
    with patch.object(oidc.requests, "get", return_value=_response(json_body={"count": 1})):
        with pytest.raises(OIDCError, match="missing 'value'"):
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")


# ---------------------------------------------------------------- sbomify exchange failures


def test_exchange_403_no_binding_does_not_retry(gha_env: None) -> None:
    sbomify_calls = 0

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        nonlocal sbomify_calls
        sbomify_calls += 1
        return _response(status=403, json_body={"detail": "repository not bound to this component"})

    with (
        patch.object(oidc.requests, "get", return_value=_response(json_body={"value": "jwt"})),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        with pytest.raises(OIDCError, match="HTTP 403") as excinfo:
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert excinfo.value.status_code == 403
    assert "repository not bound to this component" in str(excinfo.value)
    assert sbomify_calls == 1


def test_exchange_429_retries(gha_env: None) -> None:
    sbomify_calls = 0

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        nonlocal sbomify_calls
        sbomify_calls += 1
        return _response(status=429, json_body={"detail": "too many requests"})

    with (
        patch.object(oidc.requests, "get", return_value=_response(json_body={"value": "jwt"})),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        with pytest.raises(OIDCError) as excinfo:
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert excinfo.value.status_code == 429
    assert sbomify_calls == 3


def test_exchange_503_jwks_unavailable_retries_then_fails(gha_env: None) -> None:
    sbomify_calls = 0

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        nonlocal sbomify_calls
        sbomify_calls += 1
        return _response(status=503, json_body={"detail": "OIDC verification temporarily unavailable"})

    with (
        patch.object(oidc.requests, "get", return_value=_response(json_body={"value": "jwt"})),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        with pytest.raises(OIDCError):
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert sbomify_calls == 3


def test_exchange_401_carries_status_code(gha_env: None) -> None:
    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        return _response(status=401, json_body={"detail": "invalid OIDC token"})

    with (
        patch.object(oidc.requests, "get", return_value=_response(json_body={"value": "jwt"})),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        with pytest.raises(OIDCError) as excinfo:
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")

    assert excinfo.value.status_code == 401


def test_exchange_missing_access_token_raises(gha_env: None) -> None:
    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        return _response(json_body={"expires_in": 900, "component_id": "c"})

    with (
        patch.object(oidc.requests, "get", return_value=_response(json_body={"value": "jwt"})),
        patch.object(oidc.requests, "post", side_effect=fake_post),
    ):
        with pytest.raises(OIDCError, match="missing 'access_token'"):
            exchange_oidc_token(component_id="c", api_base_url="https://app.sbomify.test")
