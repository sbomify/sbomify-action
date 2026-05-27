"""OIDC trusted-publishing support.

Lets the action exchange a CI-provided OIDC JWT (currently GitHub Actions only)
for a short-lived sbomify access token, so users can publish SBOMs without
storing a long-lived sbomify API token as a CI secret.

Flow (GitHub Actions):
  1. Workflow grants `permissions: id-token: write`. The runner exposes
     `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
  2. `request_github_oidc_token(audience)` calls that URL to mint a JWT with
     the requested `aud` claim.
  3. `exchange_for_sbomify_token(jwt, component_id, api_base_url)` POSTs the
     JWT to `/api/v1/auth/oidc/github/exchange` and gets back a short-lived
     sbomify access token (default TTL: 15 minutes).
  4. The caller uses that token like any other sbomify API token.

The sbomify backend matches the OIDC token against an `OIDCBinding` configured
in the sbomify UI, which ties a component to a specific GitHub repository
(by immutable owner_id/repository_id). The binding must exist before trusted
publishing will work — otherwise the exchange returns 403.
"""

import os
from typing import Optional

import requests

from .exceptions import OIDCBindingMissingError, OIDCExchangeError
from .http_client import get_default_headers
from .logging_config import logger

DEFAULT_OIDC_AUDIENCE = "sbomify.com"
OIDC_REQUEST_TIMEOUT = 30
EXCHANGE_TIMEOUT = 30


def is_github_oidc_available() -> bool:
    """True iff the runner exposes a GitHub Actions OIDC token request endpoint.

    Requires `GITHUB_ACTIONS=true` plus both `ACTIONS_ID_TOKEN_REQUEST_URL`
    and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. The latter two are only present
    when the workflow declares `permissions: id-token: write`.
    """
    if os.environ.get("GITHUB_ACTIONS", "").lower() not in ("true", "1"):
        return False
    return bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))


def request_github_oidc_token(audience: str) -> str:
    """Fetch a GitHub Actions OIDC JWT for the given audience.

    Calls `${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=<audience>` with
    `Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}` and returns
    the JWT from the response body's `value` field.

    Raises:
        OIDCExchangeError: if the runner endpoint is unreachable or returns
            an unexpected payload. (We surface this as an exchange error
            because to the user it's part of the same "could not authenticate
            via OIDC" failure.)
    """
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise OIDCExchangeError(
            "GitHub Actions OIDC environment is not available. "
            "Ensure the workflow grants `permissions: id-token: write`."
        )

    try:
        response = requests.get(
            url,
            params={"audience": audience},
            headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
            timeout=OIDC_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OIDCExchangeError(f"Failed to reach GitHub OIDC token endpoint: {exc}") from exc

    if not response.ok:
        raise OIDCExchangeError(
            f"GitHub OIDC token endpoint returned HTTP {response.status_code}: {response.text[:200]}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise OIDCExchangeError("GitHub OIDC token endpoint returned non-JSON response") from exc

    token = payload.get("value")
    if not token:
        raise OIDCExchangeError("GitHub OIDC token endpoint response did not contain a 'value' field")
    return str(token)


def exchange_for_sbomify_token(
    oidc_jwt: str,
    component_id: str,
    api_base_url: str,
) -> tuple[str, int]:
    """Exchange a GitHub OIDC JWT for a short-lived sbomify access token.

    Args:
        oidc_jwt: The GitHub Actions OIDC JWT (from `request_github_oidc_token`)
        component_id: The sbomify component ID to scope the token to
        api_base_url: The sbomify API base URL (e.g. `https://app.sbomify.com`)

    Returns:
        (access_token, expires_in) — the access token to use as a Bearer
        credential, and its lifetime in seconds.

    Raises:
        OIDCBindingMissingError: 403 — no OIDC binding configured for this
            component+repository in sbomify. The user needs to create one in
            the sbomify UI.
        OIDCExchangeError: any other failure (invalid JWT, rate limit,
            backend error, etc.).
    """
    url = f"{api_base_url.rstrip('/')}/api/v1/auth/oidc/github/exchange"
    headers = get_default_headers(token=oidc_jwt, content_type="application/json")

    try:
        response = requests.post(
            url,
            headers=headers,
            json={"component_id": component_id},
            timeout=EXCHANGE_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OIDCExchangeError(f"Failed to reach sbomify OIDC exchange endpoint: {exc}") from exc

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError as exc:
            raise OIDCExchangeError("sbomify OIDC exchange returned non-JSON response") from exc
        access_token = payload.get("access_token")
        expires_in = int(payload.get("expires_in", 0) or 0)
        if not access_token:
            raise OIDCExchangeError("sbomify OIDC exchange response did not contain access_token")
        return access_token, expires_in

    # Best-effort detail extraction from the error body
    detail = ""
    try:
        body = response.json()
        if isinstance(body, dict):
            detail = body.get("detail") or body.get("error") or ""
    except ValueError:
        detail = response.text[:200]

    if response.status_code == 403:
        raise OIDCBindingMissingError(
            f"sbomify rejected the OIDC token (403): no binding found for component "
            f"'{component_id}' and this repository. Create an OIDC binding in the "
            f"sbomify UI (Component → Settings → Trusted Publishing). "
            f"{f'Detail: {detail}' if detail else ''}".strip()
        )
    if response.status_code == 404:
        raise OIDCExchangeError(
            f"sbomify component '{component_id}' was not found (404). "
            f"Verify COMPONENT_ID is correct. {f'Detail: {detail}' if detail else ''}".strip()
        )
    if response.status_code == 401:
        raise OIDCExchangeError(
            f"sbomify rejected the GitHub OIDC token (401). The token signature, "
            f"audience, or expiry did not validate. {f'Detail: {detail}' if detail else ''}".strip()
        )
    if response.status_code == 429:
        raise OIDCExchangeError(
            "sbomify OIDC exchange is rate-limited (429). Retry after a short delay. "
            f"{f'Detail: {detail}' if detail else ''}".strip()
        )
    raise OIDCExchangeError(
        f"sbomify OIDC exchange failed with HTTP {response.status_code}. "
        f"{f'Detail: {detail}' if detail else ''}".strip()
    )


def obtain_sbomify_token_via_oidc(
    component_id: str,
    api_base_url: str,
    audience: Optional[str] = None,
) -> str:
    """Convenience: request a GitHub OIDC JWT and exchange it for a sbomify token.

    Logs progress (without leaking the token). The audience defaults to
    `sbomify.com`, which matches the production backend's
    `OIDC_GITHUB_AUDIENCE`. Override for self-hosted instances.
    """
    requested_audience = audience or DEFAULT_OIDC_AUDIENCE
    logger.info(f"Authenticating to sbomify via GitHub OIDC (component={component_id}, audience={requested_audience})")
    oidc_jwt = request_github_oidc_token(requested_audience)
    access_token, expires_in = exchange_for_sbomify_token(oidc_jwt, component_id, api_base_url)
    logger.info(f"Obtained short-lived sbomify token via OIDC (expires in {expires_in}s)")
    return access_token
