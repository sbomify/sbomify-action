"""GitHub Actions OIDC trusted publishing for sbomify.

When the action runs inside a GitHub Actions job with
``permissions: id-token: write``, two env vars become available:

* ``ACTIONS_ID_TOKEN_REQUEST_URL``   — endpoint to mint the JWT
* ``ACTIONS_ID_TOKEN_REQUEST_TOKEN`` — short-lived bearer for that endpoint

We mint a JWT scoped to ``audience=sbomify.com`` (overridable per
deployment), exchange it at sbomify's
``/api/v1/auth/oidc/github/exchange``, and hand back a short-lived
sbomify access token. The caller can then use that token wherever it
would have used a long-lived ``SBOMIFY_TOKEN`` secret.

Server contract: see ``sbomify/apps/oidc/apis.py``. Failure modes are
deliberately sparse on the server (401 doesn't say which sub-check
failed); we surface that opacity faithfully here.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Final

import requests

from .http_client import get_default_headers

logger = logging.getLogger(__name__)

# Server-side default — kept in sync with ``OIDC_GITHUB_AUDIENCE`` in
# sbomify settings. Self-hosted deployments can override via the
# ``SBOMIFY_OIDC_AUDIENCE`` env var without touching the action code.
DEFAULT_AUDIENCE: Final[str] = "sbomify.com"

_GH_ENV_URL: Final[str] = "ACTIONS_ID_TOKEN_REQUEST_URL"
_GH_ENV_TOKEN: Final[str] = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

# Retry policy: only transient classes (429, 5xx, network). Auth /
# binding / not-found errors get one shot — retrying won't help and
# burns rate-limit budget. The exchange endpoint is rate-limited at
# 60/m per client IP so we keep the burst very small.
_MAX_ATTEMPTS: Final[int] = 3
_BACKOFF_SECONDS: Final[tuple[float, ...]] = (1.0, 2.0, 4.0)
_HTTP_TIMEOUT: Final[float] = 10.0


class OIDCError(Exception):
    """Raised when OIDC trusted-publishing exchange fails.

    The ``status_code`` attribute carries the HTTP status from sbomify
    when the failure happened during exchange (None for transport-level
    or GitHub-mint failures). Status taxonomy on the sbomify side:

    * 400 — missing component_id (caller bug)
    * 401 — JWT rejected (audience / issuer / signature / expiry)
    * 403 — repo isn't bound to this Component on sbomify
    * 404 — Component doesn't exist
    * 429 — rate-limited (60/m per client IP)
    * 503 — GitHub's JWKS endpoint temporarily unreachable
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class OIDCExchangeResult:
    """Successful exchange payload — short-lived sbomify access token."""

    access_token: str
    expires_in_seconds: int
    component_id: str


def is_oidc_available() -> bool:
    """True iff the GitHub Actions OIDC env vars are both set.

    Both env vars are populated by GitHub only when the workflow
    declares ``permissions: id-token: write``. Their joint presence is
    the canonical signal; checking only one would surface a confusing
    half-state to the caller.
    """
    return bool(os.environ.get(_GH_ENV_URL)) and bool(os.environ.get(_GH_ENV_TOKEN))


def exchange_oidc_token(
    *,
    component_id: str,
    api_base_url: str,
    audience: str | None = None,
) -> OIDCExchangeResult:
    """Mint a GitHub OIDC JWT and exchange it for a sbomify access token.

    Raises ``OIDCError`` on any failure — caller decides whether to
    fall back to a long-lived token or abort.
    """
    if not component_id:
        raise OIDCError("component_id is required for OIDC exchange")
    if not is_oidc_available():
        raise OIDCError("GitHub Actions OIDC env vars not found — is `permissions: id-token: write` set on the job?")

    resolved_audience = audience or os.environ.get("SBOMIFY_OIDC_AUDIENCE") or DEFAULT_AUDIENCE
    jwt = _mint_github_id_token(resolved_audience)
    return _exchange_with_sbomify(jwt=jwt, component_id=component_id, api_base_url=api_base_url)


# ----------------------------------------------------------------------
# Step 1: ask GitHub's OIDC provider for a JWT scoped to ``audience``.
# ----------------------------------------------------------------------


def _mint_github_id_token(audience: str) -> str:
    request_url = os.environ[_GH_ENV_URL]
    request_token = os.environ[_GH_ENV_TOKEN]

    # GitHub returns ``{"value": "<jwt>", "count": N}`` on success.
    # The ``audience`` query param is required — without it GitHub
    # mints a generic token sbomify will reject with a 401.
    headers = {
        **get_default_headers(),
        "Authorization": f"Bearer {request_token}",
        "Accept": "application/json; api-version=2.0",
    }
    last_error: Exception | None = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            response = requests.get(
                request_url,
                headers=headers,
                params={"audience": audience},
                timeout=_HTTP_TIMEOUT,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_error = exc
            _sleep_backoff(attempt)
            continue

        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError as exc:
                raise OIDCError(f"GitHub OIDC response was not valid JSON: {exc}") from exc
            token = payload.get("value") if isinstance(payload, dict) else None
            if not isinstance(token, str) or not token:
                raise OIDCError("GitHub OIDC response missing 'value' field")
            return token

        if response.status_code >= 500 or response.status_code == 429:
            last_error = OIDCError(
                f"GitHub OIDC mint failed: HTTP {response.status_code}",
                status_code=response.status_code,
            )
            _sleep_backoff(attempt)
            continue

        # 4xx other than 429: definitively wrong (missing audience, expired
        # request token, malformed URL). Retry won't help.
        raise OIDCError(f"GitHub OIDC mint rejected (HTTP {response.status_code}): {_short_body(response)}")

    raise OIDCError(f"GitHub OIDC mint failed after {_MAX_ATTEMPTS} attempts: {last_error}")


# ----------------------------------------------------------------------
# Step 2: exchange the GitHub JWT for a short-lived sbomify token.
# ----------------------------------------------------------------------


def _exchange_with_sbomify(*, jwt: str, component_id: str, api_base_url: str) -> OIDCExchangeResult:
    url = f"{api_base_url.rstrip('/')}/api/v1/auth/oidc/github/exchange"
    headers = {
        **get_default_headers(content_type="application/json"),
        "Authorization": f"Bearer {jwt}",
    }
    body = {"component_id": component_id}

    last_error: Exception | None = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            response = requests.post(url, headers=headers, json=body, timeout=_HTTP_TIMEOUT)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_error = exc
            _sleep_backoff(attempt)
            continue

        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError as exc:
                raise OIDCError(f"sbomify exchange response was not valid JSON: {exc}") from exc
            access_token = payload.get("access_token") if isinstance(payload, dict) else None
            if not access_token or not isinstance(access_token, str):
                raise OIDCError("sbomify exchange response missing 'access_token'")
            return OIDCExchangeResult(
                access_token=access_token,
                expires_in_seconds=int(payload.get("expires_in") or 0),
                component_id=str(payload.get("component_id") or component_id),
            )

        # Retry on rate-limit and the documented 503 (GitHub JWKS down).
        # Everything else — 400/401/403/404 — is a config error that
        # retrying makes worse (429 enumeration risk + log noise).
        if response.status_code in (429, 503) or response.status_code >= 500:
            last_error = OIDCError(
                _exchange_error_message(response),
                status_code=response.status_code,
            )
            _sleep_backoff(attempt)
            continue

        raise OIDCError(_exchange_error_message(response), status_code=response.status_code)

    raise OIDCError(
        f"sbomify OIDC exchange failed after {_MAX_ATTEMPTS} attempts: {last_error}",
        status_code=getattr(last_error, "status_code", None),
    )


def _exchange_error_message(response: requests.Response) -> str:
    detail = "no detail"
    try:
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
            detail = payload["detail"]
    except ValueError:
        detail = _short_body(response)
    return f"sbomify OIDC exchange rejected (HTTP {response.status_code}): {detail}"


def _short_body(response: requests.Response) -> str:
    body = (response.text or "").strip()
    if len(body) > 200:
        return body[:200] + "…"
    return body or "(empty body)"


def _sleep_backoff(attempt: int) -> None:
    if attempt + 1 >= _MAX_ATTEMPTS:
        return
    delay = _BACKOFF_SECONDS[min(attempt, len(_BACKOFF_SECONDS) - 1)]
    logger.debug("OIDC retry backoff: sleeping %.1fs (attempt %d)", delay, attempt + 1)
    time.sleep(delay)
