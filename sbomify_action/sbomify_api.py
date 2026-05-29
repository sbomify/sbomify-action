"""Shared HTTP client for the sbomify REST API.

This module is the single place where the action talks to sbomify. Yocto,
upload, augmentation, releases, and the wizard all delegate here instead of
hand-rolling their own ``requests`` calls. Centralising the plumbing keeps
session reuse, header construction, pagination, and error handling in one
spot, and gives every caller the same ``APIError`` / ``AuthError`` shape.

The client is intentionally narrow: every method is a thin wrapper over a
single REST endpoint. Higher-level orchestration (get-or-create on name
collisions, contact-profile resolution, etc.) lives on top, not inside.
"""

from __future__ import annotations

from typing import Any, Iterator

import requests

from sbomify_action.exceptions import APIError, AuthError, PlanLimitError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

DEFAULT_TIMEOUT = 60
DEFAULT_PAGE_SIZE = 100
MAX_PAGES = 500  # Safety limit against runaway pagination.

# Component types the sbomify backend accepts (mirrors
# ``core.schemas.ComponentType``: BOM="bom", DOCUMENT="document"). There is
# NO "sbom" value — passing one trips a server-side 422. We validate
# client-side so a wrong literal fails fast with a clear message at the
# call site instead of an opaque enum-validation dump from the API.
VALID_COMPONENT_TYPES = frozenset({"bom", "document"})


def clean_validation_error(detail: Any) -> str | None:
    """Render an API error ``detail`` into human-readable text.

    django-ninja / pydantic 422 responses put a *list* of per-field error
    dicts (``{type, loc, msg, ctx}``) in ``detail``. Stringifying that list
    dumps raw Python reprs — eg ``[{'type': 'enum', 'loc': ['body', 'payload',
    'component_type'], 'msg': "Input should be 'document' or 'bom'", ...}]`` —
    at the user. Collapse it to ``<field>: <msg>`` lines instead. A plain-string
    detail (the common case) passes through unchanged; ``None`` stays ``None``
    so callers can treat "no detail" as falsy.

    Module-level (not just a client method) so other code paths that handle raw
    API responses — eg the upload destination, which never goes through
    ``SbomifyApiClient`` — can reuse it without depending on the class (and
    without breaking when tests mock the class wholesale).
    """
    if detail is None:
        return None
    if isinstance(detail, list):
        parts: list[str] = []
        for item in detail:
            if isinstance(item, dict):
                msg = item.get("msg") or item.get("detail") or ""
                loc = item.get("loc")
                field = None
                if isinstance(loc, (list, tuple)) and loc:
                    # ``loc`` is a path like ['body', 'payload', '<field>'];
                    # the trailing element is the field the user cares about.
                    field = str(loc[-1])
                if field and msg:
                    parts.append(f"{field}: {msg}")
                elif msg:
                    parts.append(str(msg))
            elif item:
                parts.append(str(item))
        return "; ".join(parts) if parts else None
    return str(detail)


class SbomifyApiClient:
    """Thin wrapper around the sbomify REST API.

    One instance per thread. ``requests.Session`` is not thread-safe; do not
    share a client across threads — pass the base URL + token instead and let
    each thread build its own.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.session = session or requests.Session()

    # ------------------------------------------------------------------
    # plumbing

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        data: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> requests.Response:
        """Issue one HTTP request and return the response.

        ``json_body`` and ``data`` are mutually exclusive — ``data`` is for
        raw payloads (SBOM upload), ``json_body`` for normal JSON requests.
        Connection / timeout failures and 401s raise immediately; other
        non-2xx responses are returned to the caller so they can build
        endpoint-specific error messages from the body.
        """
        url = f"{self.base_url}{path}"
        content_type = "application/json" if json_body is not None else None
        headers = get_default_headers(self.token, content_type=content_type)
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                data=data,
                timeout=timeout if timeout is not None else self.timeout,
            )
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to sbomify API")
        except requests.exceptions.Timeout:
            raise APIError("API request timed out")

        if response.status_code == 401:
            raise AuthError(self._build_error("Authentication failed", response))
        return response

    @staticmethod
    def _build_error(prefix: str, response: requests.Response) -> str:
        """Format ``prefix [status] - detail`` from a non-2xx response."""
        message = f"{prefix} [{response.status_code}]"
        body = SbomifyApiClient._safe_json_dict(response)
        if body is not None:
            detail = SbomifyApiClient._clean_validation_error(body.get("detail"))
            if detail:
                message += f" - {detail}"
        return message

    @staticmethod
    def _clean_validation_error(detail: Any) -> str | None:
        """Backwards-compatible alias for the module-level
        :func:`clean_validation_error`. Kept so existing call sites and tests
        that reference ``SbomifyApiClient._clean_validation_error`` keep working.
        """
        return clean_validation_error(detail)

    @staticmethod
    def _safe_json_dict(response: requests.Response) -> dict[str, Any] | None:
        """Parse the response body as a JSON dict, returning None on failure."""
        try:
            data = response.json()
        except ValueError:
            return None
        if isinstance(data, dict):
            return data
        return None

    def _paginate(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        error_context: str = "paginate",
    ) -> Iterator[dict[str, Any]]:
        """Iterate over every item in a paginated endpoint.

        Yields one dict per item. Stops when the response indicates no more
        pages (either ``has_next: False`` in a ``pagination`` block, or an
        empty page, or a missing ``next``/``items``). Raises ``APIError`` on
        transport/HTTP/JSON failure or if the safety limit is hit.
        """
        page = 1
        while page <= MAX_PAGES:
            page_params = dict(params or {})
            page_params["page"] = page
            page_params["page_size"] = page_size

            response = self._request("GET", path, params=page_params)
            if not response.ok:
                raise APIError(self._build_error(f"Failed to {error_context}.", response))

            try:
                data = response.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                raise APIError(f"Failed to {error_context}: invalid JSON response from API")

            if isinstance(data, list):
                # Some endpoints return a bare list rather than {items: [...]}.
                # Bare-list endpoints don't carry pagination metadata, so we
                # treat the response as authoritative: yield once and stop.
                # Re-requesting would loop forever against any endpoint that
                # ignores ?page= and returns the same list every time.
                for item in data:
                    if isinstance(item, dict):
                        yield item
                return

            if not isinstance(data, dict):
                raise APIError(f"Failed to {error_context}: unexpected response type ({type(data).__name__})")

            raw_items = data.get("items")
            if not isinstance(raw_items, list):
                # Envelope without `items` — treat as a single-page response
                # with no items and stop. Yielding the envelope dict would
                # poison callers like list_components_by_name that .get('id')
                # on every yielded element.
                return

            for item in raw_items:
                if isinstance(item, dict):
                    yield item

            # Stop logic. Trust explicit pagination signals where present;
            # otherwise assume single-page so we don't loop against an
            # endpoint that ignores ?page= and returns the same items
            # every request.
            pagination = data.get("pagination")
            # 1. Explicit "no next page" markers — stop.
            if isinstance(pagination, dict) and pagination.get("has_next") is False:
                return
            if "next" in data and not data.get("next"):
                return
            # 2. Empty page — nothing more to consume.
            if not raw_items:
                return
            # 3. No pagination metadata at all → single-page response. Stop.
            #    A server that wanted us to paginate would have shipped either
            #    a ``pagination`` block or a ``next`` link.
            if not isinstance(pagination, dict) and "next" not in data:
                return
            page += 1

        raise APIError(
            f"Failed to {error_context}: pagination safety limit reached ({MAX_PAGES} pages × {page_size} items)"
        )

    # ------------------------------------------------------------------
    # auth probe

    def whoami(self) -> None:
        """Cheap probe that confirms the token is valid.

        Raises ``AuthError`` on 401, ``APIError`` on anything else non-2xx.
        Lists one component (cheapest endpoint with no side effects).
        """
        response = self._request("GET", "/api/v1/components", params={"page": 1, "page_size": 1})
        if not response.ok:
            raise APIError(self._build_error("Failed to authenticate with sbomify", response))

    # ------------------------------------------------------------------
    # components

    def iter_components(self, error_context: str = "list components") -> Iterator[dict[str, Any]]:
        """Yield every component the token has access to."""
        yield from self._paginate("/api/v1/components", error_context=error_context)

    def list_components(self) -> list[dict[str, Any]]:
        """Materialise the full list of components."""
        return list(self.iter_components())

    def list_components_by_name(self) -> dict[str, str]:
        """Fetch all components and return a ``{name: id}`` mapping."""
        mapping: dict[str, str] = {}
        for item in self.iter_components():
            name = item.get("name")
            comp_id = item.get("id")
            if name and comp_id:
                mapping[str(name)] = str(comp_id)
        logger.info(f"Cached {len(mapping)} existing components")
        return mapping

    def get_component_id_by_name(self, name: str) -> str | None:
        """Find a component ID by exact name match, paging until found."""
        for item in self.iter_components(error_context=f"look up component '{name}'"):
            if item.get("name") == name:
                comp_id = item.get("id")
                if comp_id is not None:
                    return str(comp_id)
        return None

    def create_component(
        self,
        name: str,
        *,
        component_type: str,
    ) -> tuple[str, bool]:
        """Create a component with get-or-create semantics.

        Returns ``(component_id, was_created)``. Recovers from
        ``DUPLICATE_NAME`` (status 400 or 409) by looking the existing
        component up by name. Raises ``PlanLimitError`` when the team has
        hit their component-count limit.

        Raises ``ValueError`` if ``component_type`` isn't a value the
        backend accepts — a hardcoded-literal mistake (the only way a bad
        type reaches here) should fail loud at the call site / in CI, not
        ship and surface as an opaque 422 at runtime.
        """
        if component_type not in VALID_COMPONENT_TYPES:
            raise ValueError(
                f"Invalid component_type {component_type!r}; expected one of {sorted(VALID_COMPONENT_TYPES)}."
            )
        response = self._request(
            "POST",
            "/api/v1/components",
            json_body={"name": name, "component_type": component_type},
        )

        if response.ok:
            data = self._safe_json_dict(response)
            if data is None:
                raise APIError(f"Invalid JSON response when creating component '{name}'")
            comp_id = data.get("id")
            if comp_id is None:
                raise APIError(f"Invalid response when creating component '{name}': no id returned")
            return str(comp_id), True

        body = self._safe_json_dict(response) or {}
        # ``raw_detail`` drives plan-limit detection; ``detail`` (cleaned) is for
        # the human-facing message only. Keep them separate: the backend's
        # plan-limit 403 sends a plain string ("maximum components reached"),
        # whereas a pydantic 422 sends a list. Matching "maximum" against the
        # *cleaned* string would misfire on a list-detail whose collapsed text
        # happens to contain "maximum" (eg "name: ...maximum length 255"),
        # raising PlanLimitError for a plain validation error.
        raw_detail = body.get("detail")
        detail = self._clean_validation_error(raw_detail) or ""
        error_code = body.get("error_code") or ""
        err_msg = f"Failed to create component '{name}'. [{response.status_code}]"
        if detail:
            err_msg += f" - {detail}"

        if response.status_code in (400, 409) and error_code == "DUPLICATE_NAME":
            logger.info(f"Component '{name}' already exists, retrieving existing component ID")
            existing_id = self.get_component_id_by_name(name)
            if existing_id is not None:
                return existing_id, False
            raise APIError(f"Component '{name}' reported as duplicate by API but could not be found via lookup")

        if response.status_code == 403 and isinstance(raw_detail, str) and "maximum" in raw_detail.lower():
            raise PlanLimitError(err_msg)
        raise APIError(err_msg)

    def get_or_create_component(
        self,
        name: str,
        cache: dict[str, str],
        *,
        component_type: str,
    ) -> tuple[str, bool]:
        """Look the name up in ``cache``; on miss, create it (updating cache)."""
        if name in cache:
            return cache[name], False
        comp_id, was_created = self.create_component(name, component_type=component_type)
        cache[name] = comp_id
        if was_created:
            logger.info(f"Created component '{name}' -> {comp_id}")
        else:
            logger.info(f"Recovered existing component '{name}' -> {comp_id}")
        return comp_id, was_created

    def patch_component(self, component_id: str, **fields: Any) -> dict[str, Any]:
        """Partial-update a component. Raises on non-2xx."""
        response = self._request("PATCH", f"/api/v1/components/{component_id}", json_body=fields)
        if not response.ok:
            raise APIError(self._build_error(f"Failed to patch component {component_id}.", response))
        data = self._safe_json_dict(response)
        return data or {}

    def patch_component_visibility(self, component_id: str, visibility: str) -> None:
        """Set a component's visibility, logging (not raising) on failure.

        Visibility is best-effort; the action should not abort if the API
        rejects it (eg. when the token can't modify the component, or 401s
        on a long-running Yocto pipeline whose token expired). AuthError /
        APIError from ``_request`` are caught and logged so the caller's
        upload-then-set-visibility flow always completes.
        """
        try:
            response = self._request(
                "PATCH",
                f"/api/v1/components/{component_id}",
                json_body={"visibility": visibility},
            )
        except APIError as e:
            logger.warning(f"Failed to set visibility for component {component_id}: {e}")
            return
        if not response.ok:
            logger.warning(f"Failed to set visibility for component {component_id}: [{response.status_code}]")

    def get_augmentation_meta(self, component_id: str) -> dict[str, Any]:
        """Fetch augmentation metadata for a component.

        Uses ``/api/v1/sboms/component/{id}/meta`` (the legacy augmentation
        endpoint). The newer ``/api/v1/components/{id}/metadata`` endpoint
        carries different fields and is not interchangeable yet.
        """
        response = self._request("GET", f"/api/v1/sboms/component/{component_id}/meta")
        if not response.ok:
            raise APIError(self._build_error("Failed to retrieve component metadata from sbomify.", response))
        data = self._safe_json_dict(response)
        return data or {}

    # ------------------------------------------------------------------
    # products

    def list_products(self) -> list[dict[str, Any]]:
        return list(self._paginate("/api/v1/products", error_context="list products"))

    def get_product(self, product_id: str) -> dict[str, Any]:
        response = self._request("GET", f"/api/v1/products/{product_id}")
        if not response.ok:
            raise APIError(self._build_error(f"Failed to fetch product {product_id}.", response))
        return self._safe_json_dict(response) or {}

    def create_product(self, name: str) -> dict[str, Any]:
        response = self._request("POST", "/api/v1/products", json_body={"name": name})
        if not response.ok:
            raise APIError(self._build_error(f"Failed to create product '{name}'.", response))
        return self._safe_json_dict(response) or {}

    def attach_components_to_product(self, product_id: str, component_ids: list[str]) -> None:
        """Set the full component list on a product.

        sbomify's ``PATCH /products/{id}`` with ``component_ids`` *replaces*
        the existing set, so we read the current set first and PATCH the
        union back. Workspace-scoped components (``is_global=True``) trigger
        a 400 from the backend — we surface that as ``APIError``.
        """
        if not component_ids:
            return
        product = self.get_product(product_id)
        existing = product.get("component_ids") or product.get("components") or []
        existing_ids: list[str] = []
        for entry in existing:
            if isinstance(entry, str):
                existing_ids.append(entry)
            elif isinstance(entry, dict) and entry.get("id"):
                existing_ids.append(str(entry["id"]))

        merged = list(existing_ids)
        for cid in component_ids:
            if cid not in merged:
                merged.append(cid)
        if merged == existing_ids:
            return  # Nothing to add — backend would no-op anyway.

        response = self._request(
            "PATCH",
            f"/api/v1/products/{product_id}",
            json_body={"component_ids": merged},
        )
        if not response.ok:
            raise APIError(self._build_error(f"Failed to attach components to product {product_id}.", response))

    # ------------------------------------------------------------------
    # contact profiles

    def list_workspaces(self) -> list[dict[str, Any]]:
        """List workspaces the token can see.

        Each item carries a ``key`` field used to scope workspace-nested
        endpoints like ``/api/v1/workspaces/{team_key}/contact-profiles``.
        Returns a bare JSON list (no pagination envelope) directly from
        the API. The route is mounted at ``/workspaces`` (not
        ``/teams``) despite the legacy ``team_key`` parameter naming.

        Note: this is the ONLY workspaces-router endpoint where a
        trailing slash is REQUIRED — verified against stage,
        ``/api/v1/workspaces`` returns 301 (redirect, may drop bodies on
        non-GET). The nested routes (``/{key}/contact-profiles`` etc.)
        do NOT accept a trailing slash; they 404 when one is present.
        Do not "normalise" the slashes here — each route's shape is
        dictated by the backend's mount config and verified by
        integration probing.

        Accepts both shapes the API might return: a bare list (current
        production shape) OR a paginated envelope (``{items: [...],
        pagination: {...}}``) — the latter is the shape every other
        list endpoint already uses, so a future migration of this
        route would otherwise silently return [] and break team_key
        resolution.
        """
        response = self._request("GET", "/api/v1/workspaces/")
        if not response.ok:
            raise APIError(self._build_error("Failed to list workspaces.", response))
        try:
            data = response.json()
        except ValueError:
            raise APIError("Failed to list workspaces: invalid JSON response from API")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items")
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def list_contact_profiles(self, team_key: str) -> list[dict[str, Any]]:
        """List contact profiles for a workspace.

        Hits ``GET /api/v1/workspaces/{team_key}/contact-profiles``.
        Returns a bare JSON list (no pagination envelope), filtered
        server-side to workspace-level profiles (the backend excludes
        ``is_component_private`` ones). Returns ``[]`` on 404 — some
        deployments don't expose the endpoint, and callers treat
        absence as "no profiles configured".

        ``team_key`` must come from a prior ``list_workspaces()`` call
        (or be otherwise known to the caller); the API has no "current
        workspace" notion for token-scoped requests, so it can't be
        omitted.
        """
        response = self._request("GET", f"/api/v1/workspaces/{team_key}/contact-profiles")
        if response.status_code == 404:
            logger.debug("Contact profiles endpoint not available for workspace %s", team_key)
            return []
        if not response.ok:
            raise APIError(self._build_error("Failed to list contact profiles.", response))
        try:
            data = response.json()
        except ValueError:
            raise APIError("Failed to list contact profiles: invalid JSON response from API")
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    def create_contact_profile(self, team_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a contact profile in a workspace.

        Hits ``POST /api/v1/workspaces/{team_key}/contact-profiles``.
        ``payload`` is the CycloneDX-aligned ``ContactProfileCreateSchema``
        — at minimum ``name`` is required; ``entities`` (with at least
        one of ``is_manufacturer``/``is_supplier``/``is_author`` set)
        and ``authors`` cover the supplier + author metadata that NTIA /
        CISA / EU CRA list as minimum elements. Returns the created
        profile dict (with the new ``id``) on 201; raises ``APIError``
        on validation / permission failure.
        """
        response = self._request(
            "POST",
            f"/api/v1/workspaces/{team_key}/contact-profiles",
            json_body=payload,
        )
        if not response.ok:
            raise APIError(self._build_error("Failed to create contact profile.", response))
        data = self._safe_json_dict(response)
        return data or {}

    # ------------------------------------------------------------------
    # releases

    def _fetch_releases(
        self,
        params: dict[str, str],
        error_context: str,
    ) -> list[dict[str, Any]]:
        """Query the releases endpoint, paginating until every release matching
        ``params`` has been collected.

        Pagination matters for DUPLICATE_NAME recovery: when the backend
        rejects a create_release call, the existing release we need to look
        up may be on page 2+ of a busy product. A single-page fetch silently
        missed those releases and turned a "you already have this release"
        into a hard APIError.

        Returns ``[]`` on 404 (endpoint not available on every deployment).
        Inlines the pagination loop (rather than calling ``_paginate``) so
        the 404-tolerant first-page probe doesn't cost a duplicate round
        trip.
        """
        items: list[dict[str, Any]] = []
        page = 1
        while page <= MAX_PAGES:
            page_params = {**params, "page": str(page), "page_size": str(DEFAULT_PAGE_SIZE)}
            response = self._request("GET", "/api/v1/releases", params=page_params)
            if response.status_code == 404:
                # Endpoint not available on this deployment. Treat as
                # "no releases" rather than raising — preserves the soft-
                # fail contract callers rely on.
                return []
            if not response.ok:
                raise APIError(self._build_error(f"Failed to {error_context}.", response))
            data = self._safe_json_dict(response)
            if data is None:
                return items
            raw_items = data.get("items")
            if not isinstance(raw_items, list):
                return items
            for item in raw_items:
                if isinstance(item, dict):
                    items.append(item)
            # Same stop conditions as _paginate's dict branch: trust
            # explicit pagination metadata when present, otherwise stop
            # after one page so we don't loop against an endpoint that
            # ignores ?page=.
            pagination = data.get("pagination")
            if isinstance(pagination, dict) and pagination.get("has_next") is False:
                return items
            if "next" in data and not data.get("next"):
                return items
            if len(raw_items) < DEFAULT_PAGE_SIZE:
                return items
            if not isinstance(pagination, dict) and "next" not in data:
                return items
            page += 1
        raise APIError(f"Failed to {error_context}: pagination safety limit reached ({MAX_PAGES} pages)")

    def check_release_exists(self, product_id: str, version: str) -> bool:
        params = {"product_id": product_id, "version": version}
        releases = self._fetch_releases(params, "check release existence")
        return any(release.get("version") == version for release in releases)

    def get_release_id(self, product_id: str, version: str) -> str | None:
        params = {"product_id": product_id, "version": version}
        for release in self._fetch_releases(params, "get release ID"):
            if release.get("version") == version:
                rid = release.get("id")
                if rid is not None:
                    return str(rid)
        return None

    def get_release_id_by_name(self, product_id: str, name: str) -> str | None:
        """Look up a release by ``name`` (not ``version``).

        Used to recover from DUPLICATE_NAME errors: the API enforces
        uniqueness on the name field, not the version field.
        """
        params = {"product_id": product_id}
        for release in self._fetch_releases(params, "get release ID by name"):
            if release.get("name") == name:
                rid = release.get("id")
                if rid is not None:
                    return str(rid)
        return None

    def get_release_details(self, product_id: str, version: str) -> dict[str, Any] | None:
        params = {"product_id": product_id, "version": version}
        for release in self._fetch_releases(params, "get release details"):
            if release.get("version") == version:
                return release
        return None

    def list_releases(self, product_id: str) -> list[dict[str, Any]]:
        return self._fetch_releases({"product_id": product_id}, "list releases")

    def create_release(
        self,
        product_id: str,
        version: str,
        *,
        name: str | None = None,
        description: str | None = None,
        is_prerelease: bool | None = None,
    ) -> str:
        """Create a release. Returns the release ID; recovers from DUPLICATE_NAME."""
        payload: dict[str, Any] = {
            "product_id": product_id,
            "version": version,
            "name": name if name is not None else version,
            "description": description if description is not None else f"{version} created by sbomify-action",
        }
        if is_prerelease is not None:
            payload["is_prerelease"] = is_prerelease

        response = self._request("POST", "/api/v1/releases", json_body=payload)
        if response.ok:
            data = self._safe_json_dict(response)
            if data is not None:
                rid = data.get("id")
                if rid is not None:
                    return str(rid)
            raise APIError("Invalid response format when creating release")

        # Duplicate-name recovery: the backend rejects with 400 +
        # DUPLICATE_NAME if another release on the product already uses
        # this name. Look it up and return that ID instead.
        if response.status_code == 400:
            error_data = self._safe_json_dict(response)
            if error_data is not None and error_data.get("error_code") == "DUPLICATE_NAME":
                logger.info(
                    f"Release '{version}' for product {product_id} already exists, retrieving existing release ID"
                )
                existing = self.get_release_id_by_name(product_id, version)
                if existing:
                    return existing
                legacy = self.get_release_id_by_name(product_id, f"Release {version}")
                if legacy:
                    logger.info(f"Found existing legacy-named release 'Release {version}' for product {product_id}")
                    return legacy

        err_msg = f"Failed to create release. [{response.status_code}]"
        body = self._safe_json_dict(response)
        if body is not None:
            if "detail" in body:
                err_msg += f" - {body['detail']}"
            else:
                err_msg += f" - {body}"
        elif response.text:
            err_msg += f" - Response: {response.text[:500]}"
        raise APIError(err_msg)

    def tag_sbom_with_release(self, sbom_id: str, release_id: str) -> None:
        """Associate an SBOM with a release. Idempotent on DUPLICATE_ARTIFACT."""
        response = self._request(
            "POST",
            f"/api/v1/releases/{release_id}/artifacts",
            json_body={"sbom_id": sbom_id},
        )
        if response.ok:
            return
        if response.status_code == 409:
            error_data = self._safe_json_dict(response)
            if error_data is not None and error_data.get("error_code") == "DUPLICATE_ARTIFACT":
                logger.info(f"SBOM {sbom_id} already tagged with release {release_id}")
                return

        err_msg = f"Failed to tag SBOM with release. [{response.status_code}]"
        body = self._safe_json_dict(response)
        if body is not None and "detail" in body:
            err_msg += f" - {body['detail']}"
        raise APIError(err_msg)

    # ------------------------------------------------------------------
    # upload

    def upload_sbom(
        self,
        component_id: str,
        sbom_payload: bytes,
        *,
        sbom_format: str = "cyclonedx",
        content_encoding: str | None = None,
        timeout: int | None = None,
    ) -> requests.Response:
        """POST raw SBOM bytes to ``/api/v1/sboms/artifact/{format}/{id}``.

        The destination layer owns error-to-``UploadResult`` translation, so
        this method returns the raw response (including non-2xx) instead of
        raising. Network/timeout failures still bubble up as ``APIError``.
        """
        path = f"/api/v1/sboms/artifact/{sbom_format}/{component_id}"
        extra: dict[str, str] = {"Content-Type": "application/json"}
        if content_encoding:
            extra["Content-Encoding"] = content_encoding
        return self._request(
            "POST",
            path,
            data=sbom_payload,
            extra_headers=extra,
            timeout=timeout,
        )
