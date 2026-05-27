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
import re
import time
from urllib.parse import urlparse

import requests

from .exceptions import OIDCBindingMissingError, OIDCExchangeError
from .http_client import get_default_headers
from .logging_config import logger

DEFAULT_OIDC_AUDIENCE = "sbomify.com"
SBOMIFY_PRODUCTION_API = "https://app.sbomify.com"
OIDC_REQUEST_TIMEOUT = 30
EXCHANGE_TIMEOUT = 30
EXCHANGE_RETRY_DELAY_SECONDS = 2

# Redact Bearer tokens and JWT-shaped substrings from upstream error bodies
# before we embed them in exception messages. Upstreams occasionally echo
# request payloads or include credentials in debug responses; CI log lines
# outlive the 15-minute token TTL.
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-+/=]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")


def _scrub_secrets(text: str) -> str:
    """Replace anything that looks like a Bearer token or JWT with [REDACTED]."""
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED-JWT]", text)
    return text


def is_github_oidc_available() -> bool:
    """True iff the runner exposes a GitHub Actions OIDC token request endpoint.

    Requires `GITHUB_ACTIONS=true` (any truthy form: 'true'/'1'/'yes'/'on',
    case- and whitespace-insensitive) plus both `ACTIONS_ID_TOKEN_REQUEST_URL`
    and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. The latter two are only present
    when the workflow declares `permissions: id-token: write`.
    """
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() not in ("true", "1", "yes", "on"):
        return False
    return bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))


def default_audience_for(api_base_url: str | None) -> str:
    """Pick a sensible OIDC audience default for the given sbomify deployment.

    - Production (https://app.sbomify.com) → 'sbomify.com' (legacy convention)
    - Any other deployment → the hostname of api_base_url (matches what
      operators conventionally set OIDC_GITHUB_AUDIENCE to on stage/self-hosted)
    - Missing/unparseable → 'sbomify.com' (final fallback)
    """
    if not api_base_url:
        return DEFAULT_OIDC_AUDIENCE
    if api_base_url.rstrip("/") == SBOMIFY_PRODUCTION_API:
        return DEFAULT_OIDC_AUDIENCE
    hostname = urlparse(api_base_url).hostname
    return hostname or DEFAULT_OIDC_AUDIENCE


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

    headers = get_default_headers(token=bearer)
    headers["Accept"] = "application/json"
    try:
        response = requests.get(
            url,
            params={"audience": audience},
            headers=headers,
            timeout=OIDC_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OIDCExchangeError(f"Failed to reach GitHub OIDC token endpoint: {exc}") from exc

    if not response.ok:
        raise OIDCExchangeError(
            f"GitHub OIDC token endpoint returned HTTP {response.status_code}: {_scrub_secrets(response.text[:200])}"
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
    request_body = {"component_id": component_id}

    try:
        response = requests.post(url, headers=headers, json=request_body, timeout=EXCHANGE_TIMEOUT)
    except requests.RequestException as exc:
        raise OIDCExchangeError(f"Failed to reach sbomify OIDC exchange endpoint: {exc}") from exc

    # 503 typically means the backend couldn't fetch GitHub's JWKS (rare, transient).
    # Retry once after a short delay before giving up.
    if response.status_code == 503:
        logger.warning("sbomify OIDC exchange returned 503; retrying once")
        time.sleep(EXCHANGE_RETRY_DELAY_SECONDS)
        try:
            response = requests.post(url, headers=headers, json=request_body, timeout=EXCHANGE_TIMEOUT)
        except requests.RequestException as exc:
            raise OIDCExchangeError(f"Failed to reach sbomify OIDC exchange endpoint on retry: {exc}") from exc

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError as exc:
            raise OIDCExchangeError("sbomify OIDC exchange returned non-JSON response") from exc
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OIDCExchangeError("sbomify OIDC exchange response did not contain access_token")
        # Be tolerant of non-int expires_in (string, float, missing) — the
        # access_token itself is what matters; TTL is only used for logging.
        try:
            expires_in = int(payload.get("expires_in") or 0)
        except (TypeError, ValueError):
            expires_in = 0
        return access_token, expires_in

    # Best-effort detail extraction from the error body. Scrub secrets in
    # case the backend ever echoes the JWT or another credential.
    detail = ""
    try:
        error_body = response.json()
        if isinstance(error_body, dict):
            detail = error_body.get("detail") or error_body.get("error") or ""
    except ValueError:
        detail = response.text[:200]
    detail = _scrub_secrets(str(detail)) if detail else ""

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
    audience: str | None = None,
) -> str:
    """Convenience: request a GitHub OIDC JWT and exchange it for a sbomify token.

    Logs progress (without leaking the token). When ``audience`` is unset,
    the default is derived from ``api_base_url`` so stage/self-hosted
    deployments work without the user having to set OIDC_AUDIENCE. The
    production deployment keeps the legacy `sbomify.com` value.
    """
    requested_audience = audience or default_audience_for(api_base_url)
    logger.info(f"Authenticating to sbomify via GitHub OIDC (component={component_id}, audience={requested_audience})")
    oidc_jwt = request_github_oidc_token(requested_audience)
    access_token, expires_in = exchange_for_sbomify_token(oidc_jwt, component_id, api_base_url)
    logger.info(f"Obtained short-lived sbomify token via OIDC (expires in {expires_in}s)")
    return access_token
