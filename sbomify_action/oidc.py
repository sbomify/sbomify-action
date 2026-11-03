"""OIDC trusted-publishing support — the sbomify half.

Lets the action exchange a CI-provided OIDC JWT for a short-lived sbomify access
token, so users can publish SBOMs without storing a long-lived sbomify API token
as a CI secret.

Minting the JWT is the CI platform's job and lives with that platform
(``_runtime/platforms/github.py`` for GitHub Actions). This module owns only the
sbomify side: the exchange call, its error handling, and the audience default.
A platform advertises itself to the exchange through its provider's
``exchange_slug``, so adding a second issuer means writing a provider, not
editing this file.

Flow:
  1. The platform's OIDC provider mints a JWT with the requested `aud` claim.
     On GitHub Actions that needs `permissions: id-token: write`.
  2. `exchange_for_sbomify_token(jwt, component_id, api_base_url)` POSTs the
     JWT to `/api/v1/auth/oidc/<slug>/exchange` and gets back a short-lived
     sbomify access token (default TTL: 15 minutes).
  3. The caller uses that token like any other sbomify API token.

The sbomify backend matches the OIDC token against an `OIDCBinding` configured
in the sbomify UI, which ties a component to a specific repository (by immutable
owner_id/repository_id). The binding must exist before trusted publishing will
work — otherwise the exchange returns 403.
"""

import re
import time
from urllib.parse import urlparse

import requests

from ._runtime import OidcProvider, get_platform
from ._runtime.redaction import scrub_secrets as _scrub_secrets
from .exceptions import OIDCBindingMissingError, OIDCExchangeError
from .http_client import get_default_headers
from .logging_config import logger

DEFAULT_OIDC_AUDIENCE = "sbomify.com"
SBOMIFY_PRODUCTION_API = "https://app.sbomify.com"
EXCHANGE_TIMEOUT = 30
EXCHANGE_RETRY_DELAY_SECONDS = 2

#: A provider slug is one path segment: lowercase letters, digits, hyphens.
#: Anything else -- a slash, a dot-dot, an encoded separator -- would move the
#: exchange request to a different endpoint.
_PROVIDER_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]*")

__all__ = [
    "DEFAULT_OIDC_AUDIENCE",
    "EXCHANGE_RETRY_DELAY_SECONDS",
    "EXCHANGE_TIMEOUT",
    "SBOMIFY_PRODUCTION_API",
    "default_audience_for",
    "exchange_for_sbomify_token",
    "get_oidc_provider",
    "is_github_oidc_available",
    "is_oidc_available",
    "obtain_sbomify_token_via_oidc",
    "request_github_oidc_token",
]


def get_oidc_provider() -> OidcProvider | None:
    """Return the active platform's OIDC provider, if it has a usable one.

    None when the platform issues no OIDC tokens, or when it does but this run
    was not granted one (on GitHub Actions, a workflow without
    ``permissions: id-token: write``).
    """
    return get_platform().oidc()


def is_oidc_available() -> bool:
    """True when the current platform can mint an OIDC token for this run."""
    return get_oidc_provider() is not None


def is_github_oidc_available() -> bool:
    """True iff the runner exposes a GitHub Actions OIDC token request endpoint.

    Kept as the GitHub-named entry point; prefer :func:`is_oidc_available`,
    which asks whichever platform is active.
    """
    provider = get_oidc_provider()
    return provider is not None and provider.exchange_slug == "github"


def request_github_oidc_token(audience: str) -> str:
    """Mint a GitHub Actions OIDC JWT for ``audience``.

    Thin wrapper over the GitHub platform's OIDC provider, kept so existing
    callers and tests keep working.

    Raises:
        OIDCExchangeError: if the runner endpoint is unavailable, unreachable,
            or returns an unexpected payload.
    """
    from ._runtime.platforms import GitHubOidcProvider

    return GitHubOidcProvider().request_token(audience)


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


def exchange_for_sbomify_token(
    oidc_jwt: str,
    component_id: str,
    api_base_url: str,
    provider_slug: str = "github",
) -> tuple[str, int]:
    """Exchange a CI-issued OIDC JWT for a short-lived sbomify access token.

    Args:
        oidc_jwt: The OIDC JWT minted by the platform's OIDC provider
        component_id: The sbomify component ID to scope the token to
        api_base_url: The sbomify API base URL (e.g. `https://app.sbomify.com`)
        provider_slug: Issuer path segment, from the provider's
            ``exchange_slug``. Defaults to GitHub, the only issuer the backend
            currently accepts.

    Returns:
        (access_token, expires_in) — the access token to use as a Bearer
        credential, and its lifetime in seconds.

    Raises:
        OIDCBindingMissingError: 403 — no OIDC binding configured for this
            component+repository in sbomify. The user needs to create one in
            the sbomify UI.
        OIDCExchangeError: any other failure (invalid JWT, rate limit,
            backend error, etc.), or a provider_slug that is not a bare slug.
    """
    # The slug is interpolated into the request path, and that path is where a
    # short-lived credential gets issued. Today every caller passes a constant
    # from a platform's OidcProvider, so nothing hostile reaches it -- but
    # "today" is the only thing holding that, and a slug containing `/` or `..`
    # would quietly retarget the request at a different endpoint. Cheap to rule
    # out, so rule it out.
    if not _PROVIDER_SLUG_RE.fullmatch(provider_slug):
        raise OIDCExchangeError(
            f"Refusing to build an OIDC exchange URL from provider slug {provider_slug!r}: "
            "expected a bare slug of lowercase letters, digits and hyphens."
        )

    url = f"{api_base_url.rstrip('/')}/api/v1/auth/oidc/{provider_slug}/exchange"
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
    """Convenience: mint an OIDC JWT via the active platform and exchange it.

    Logs progress (without leaking the token). When ``audience`` is unset,
    the default is derived from ``api_base_url`` so stage/self-hosted
    deployments work without the user having to set OIDC_AUDIENCE. The
    production deployment keeps the legacy `sbomify.com` value.

    Raises:
        OIDCExchangeError: if the platform offers no OIDC token for this run.
    """
    provider = get_oidc_provider()
    if provider is None:
        raise OIDCExchangeError(
            f"No OIDC token is available on {get_platform().name}. On GitHub Actions, "
            "ensure the workflow grants `permissions: id-token: write`."
        )

    requested_audience = audience or default_audience_for(api_base_url)
    logger.info(
        f"Authenticating to sbomify via {provider.exchange_slug} OIDC "
        f"(component={component_id}, audience={requested_audience})"
    )
    oidc_jwt = provider.request_token(requested_audience)
    access_token, expires_in = exchange_for_sbomify_token(
        oidc_jwt, component_id, api_base_url, provider_slug=provider.exchange_slug
    )
    logger.info(f"Obtained short-lived sbomify token via OIDC (expires in {expires_in}s)")
    return access_token
