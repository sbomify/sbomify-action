"""Thin sbomify REST client used by the wizard.

This client only covers the surface needed to set up Products,
Components, and Releases from the wizard. It is intentionally small and
hand-rolled — no generated OpenAPI client.

The Project layer is required by the API today but hidden from wizard
users. ``ensure_default_project`` and ``attach_component_to_product``
encapsulate that workaround so it can be removed in one diff once a
direct product->component link ships server-side.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import requests

from sbomify_action.exceptions import APIError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

DEFAULT_TIMEOUT = 30


class SbomifyAPIError(APIError):
    """Raised on any non-2xx response from sbomify."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"[{status}] {detail}")
        self.status = status
        self.detail = detail


class SbomifyAuthError(SbomifyAPIError):
    """Raised on 401 — token rejected."""


def _slugify(value: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "default"


class SbomifyClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.session = session or requests.Session()
        self._project_cache: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # internal helpers

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        headers = get_default_headers(self.token, content_type="application/json" if json_body is not None else None)
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as e:
            raise SbomifyAPIError(0, f"Failed to connect to {self.base_url}: {e}")
        except requests.exceptions.Timeout:
            raise SbomifyAPIError(0, f"Request to {url} timed out")

        if response.ok:
            return response

        detail = self._extract_detail(response)
        if response.status_code == 401:
            raise SbomifyAuthError(401, detail or "Token rejected")
        raise SbomifyAPIError(response.status_code, detail or response.reason or "")

    @staticmethod
    def _extract_detail(response: requests.Response) -> str:
        if response.headers.get("content-type", "").startswith("application/json"):
            try:
                payload = response.json()
            except ValueError:
                return ""
            if isinstance(payload, dict):
                detail = payload.get("detail") or payload.get("message")
                # sbomify returns per-field validation errors under `errors`
                # (shape: {"<field>": ["<msg>", ...]}). Surface them inline so
                # the wizard can show "name: already exists" instead of just
                # "Validation error". See sbomify PR #961 (issue #952).
                field_errors = payload.get("errors")
                field_summary = ""
                if isinstance(field_errors, dict) and field_errors:
                    parts: list[str] = []
                    for field, messages in field_errors.items():
                        if isinstance(messages, list):
                            joined = "; ".join(str(m) for m in messages)
                        else:
                            joined = str(messages)
                        parts.append(f"{field}: {joined}")
                    field_summary = " (" + "; ".join(parts) + ")"
                if isinstance(detail, str):
                    return detail + field_summary
                if field_summary:
                    return field_summary.strip(" ()")
                return str(payload)
            return str(payload)
        return response.text[:500]

    def _paginate(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            page_params = dict(params or {})
            page_params["page"] = page
            response = self._request("GET", path, params=page_params)
            data: Any
            try:
                data = response.json()
            except ValueError:
                break

            items: list[Any]
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and isinstance(data.get("items"), list):
                items = data["items"]
            elif isinstance(data, dict) and isinstance(data.get("results"), list):
                items = data["results"]
            else:
                # Unknown shape — return what we have.
                if isinstance(data, dict):
                    return [data]
                return results

            results.extend(item for item in items if isinstance(item, dict))

            if not items:
                break

            if isinstance(data, dict):
                pagination = data.get("pagination")
                if isinstance(pagination, dict) and pagination.get("has_next") is False:
                    break

            page += 1
        return results

    # ------------------------------------------------------------------
    # auth probe

    def whoami(self) -> dict[str, Any]:
        """Cheap auth probe — list one component."""
        params = urlencode({"page": 1, "page_size": 1})
        self._request("GET", f"/api/v1/components?{params}")
        return {"authenticated": True}

    # ------------------------------------------------------------------
    # products

    def list_products(self) -> list[dict[str, Any]]:
        return self._paginate("/api/v1/products")

    def create_product(self, name: str) -> dict[str, Any]:
        response = self._request("POST", "/api/v1/products", json_body={"name": name})
        result: dict[str, Any] = response.json()
        return result

    # ------------------------------------------------------------------
    # projects (hidden helper layer)

    def list_projects(self) -> list[dict[str, Any]]:
        return self._paginate("/api/v1/projects")

    def create_project(self, name: str) -> dict[str, Any]:
        response = self._request("POST", "/api/v1/projects", json_body={"name": name})
        result: dict[str, Any] = response.json()
        return result

    def link_project_to_product(self, product_id: str, project_id: str) -> None:
        self._request(
            "POST",
            f"/api/v1/products/{product_id}/projects",
            json_body={"project_ids": [project_id]},
        )

    def patch_project_components(self, project_id: str, component_ids: list[str]) -> None:
        """Set the full component list on a project."""
        self._request(
            "PATCH",
            f"/api/v1/projects/{project_id}",
            json_body={"component_ids": component_ids},
        )

    def ensure_default_project(self, product: dict[str, Any]) -> dict[str, Any]:
        """Find or create the helper project for ``product`` and link it.

        The helper project is named ``<product-slug>-default``. We cache the
        result per-product to avoid repeated list/link calls inside one
        wizard run. This whole method goes away once a direct
        product<->component link is exposed by the API.
        """
        product_id = str(product["id"])
        cached = self._project_cache.get(product_id)
        if cached is not None:
            return cached

        target_name = f"{_slugify(str(product.get('name') or 'product'))}-default"

        # Reuse if a project with the target name already exists.
        for project in self.list_projects():
            if project.get("name") == target_name:
                if not self._project_linked_to_product(project, product_id):
                    try:
                        self.link_project_to_product(product_id, str(project["id"]))
                    except SbomifyAPIError as e:
                        logger.debug(f"Could not link existing helper project: {e}")
                self._project_cache[product_id] = project
                return project

        project = self.create_project(target_name)
        try:
            self.link_project_to_product(product_id, str(project["id"]))
        except SbomifyAPIError as e:
            logger.warning(f"Helper project created but link failed: {e}")
        self._project_cache[product_id] = project
        return project

    @staticmethod
    def _project_linked_to_product(project: dict[str, Any], product_id: str) -> bool:
        products = project.get("products") or project.get("product_ids") or []
        for entry in products:
            if isinstance(entry, str) and entry == product_id:
                return True
            if isinstance(entry, dict) and str(entry.get("id")) == product_id:
                return True
        return False

    # ------------------------------------------------------------------
    # components

    def list_components(self, *, component_type: str = "bom") -> list[dict[str, Any]]:
        return self._paginate("/api/v1/components", params={"component_type": component_type})

    def create_component(self, name: str, *, component_type: str = "bom") -> dict[str, Any]:
        response = self._request(
            "POST",
            "/api/v1/components",
            json_body={"name": name, "component_type": component_type},
        )
        result: dict[str, Any] = response.json()
        return result

    def patch_component(self, component_id: str, **fields: Any) -> dict[str, Any]:
        response = self._request("PATCH", f"/api/v1/components/{component_id}", json_body=fields)
        result: dict[str, Any] = response.json()
        return result

    def attach_component_to_product(self, product: dict[str, Any], component_id: str) -> None:
        """Attach a component to a product via the helper project."""
        project = self.ensure_default_project(product)
        existing = project.get("components") or []
        existing_ids: list[str] = []
        for entry in existing:
            if isinstance(entry, str):
                existing_ids.append(entry)
            elif isinstance(entry, dict) and entry.get("id"):
                existing_ids.append(str(entry["id"]))

        if component_id in existing_ids:
            return

        new_ids = existing_ids + [component_id]
        self.patch_project_components(str(project["id"]), new_ids)
        # Update cached project so subsequent attaches see the new state.
        project_components = list(existing)
        project_components.append({"id": component_id})
        project["components"] = project_components

    # ------------------------------------------------------------------
    # contact profiles

    def list_contact_profiles(self) -> list[dict[str, Any]]:
        try:
            return self._paginate("/api/v1/contact-profiles")
        except SbomifyAPIError as e:
            if e.status == 404:
                logger.debug("Contact profiles endpoint not available")
                return []
            raise

    # ------------------------------------------------------------------
    # releases

    def list_releases(self, product_id: str) -> list[dict[str, Any]]:
        return self._paginate("/api/v1/releases", params={"product_id": product_id})

    def create_release(
        self,
        product_id: str,
        name: str,
        *,
        version: str | None = None,
        is_prerelease: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "product_id": product_id,
            "name": name,
            "is_prerelease": is_prerelease,
        }
        if version is not None:
            body["version"] = version
        response = self._request("POST", "/api/v1/releases", json_body=body)
        result: dict[str, Any] = response.json()
        return result
