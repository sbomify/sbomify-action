"""sbomify API provider for augmentation metadata.

This provider fetches organizational metadata from the sbomify backend API,
including supplier, authors, licenses, lifecycle phase, security contact,
and lifecycle dates (release_date, end_of_support, end_of_life).

Note: The API uses 'end_of_support' which maps to 'support_period_end' internally.
The API uses 'contact_profile' with nested contacts that have 'is_security_contact'
flags, which we extract and convert to 'security_contact'.
"""

from typing import Any, Dict, List, Optional

import requests

from sbomify_action.exceptions import APIError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata


class SbomifyApiProvider:
    """
    Provider that fetches augmentation metadata from the sbomify API.

    This provider has lower priority (50) so local config can override
    API data when needed.
    """

    name: str = "sbomify-api"
    priority: int = 50

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        """
        Fetch augmentation metadata from the sbomify API.

        Args:
            component_id: Component ID to fetch metadata for (required)
            api_base_url: Base URL for the API (required)
            token: Authentication token (required)
            config_path: Ignored (not needed for API provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata if API call succeeds, None otherwise
        """
        # Validate required parameters
        if not component_id:
            logger.debug("sbomify API provider: component_id not provided, skipping")
            return None
        if not api_base_url:
            logger.debug("sbomify API provider: api_base_url not provided, skipping")
            return None
        if not token:
            logger.debug("sbomify API provider: token not provided, skipping")
            return None

        # Fetch from API
        try:
            data = self._fetch_backend_metadata(api_base_url, token, component_id)
            if not data:
                return None

            # Extract data from contact_profile structure if direct fields are not present
            # The API may provide data via contact_profile instead of direct fields
            self._extract_from_contact_profile(data)

            # Create metadata from API response
            metadata = AugmentationMetadata.from_dict(data, source=self.name)

            if metadata.has_data():
                logger.info(f"Fetched augmentation metadata from sbomify API for component {component_id}")
                return metadata
            else:
                logger.debug("No augmentation metadata returned from sbomify API")
                return None

        except APIError as e:
            logger.warning(f"sbomify API error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error fetching from sbomify API: {e}")
            return None

    def _fetch_backend_metadata(
        self,
        api_base_url: str,
        token: str,
        component_id: str,
    ) -> Dict[str, Any]:
        """
        Fetch metadata from backend API.

        Args:
            api_base_url: Base URL for the API
            token: Authentication token
            component_id: Component ID to fetch metadata for

        Returns:
            Backend metadata dict

        Raises:
            APIError: If API call fails
        """
        url = f"{api_base_url}/api/v1/sboms/component/{component_id}/meta"
        headers = get_default_headers(token)

        try:
            response = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to sbomify API")
        except requests.exceptions.Timeout:
            raise APIError("API request timed out")

        if not response.ok:
            err_msg = f"Failed to retrieve component metadata from sbomify. [{response.status_code}]"
            if response.headers.get("content-type") == "application/json":
                try:
                    error_data = response.json()
                    if "detail" in error_data:
                        err_msg += f" - {error_data['detail']}"
                except (ValueError, KeyError):
                    pass
            raise APIError(err_msg)

        result: Dict[str, Any] = response.json()
        return result

    def _extract_from_contact_profile(self, data: Dict[str, Any]) -> None:
        """
        Extract supplier, manufacturer, authors, and security_contact from contact_profile.

        The API may provide organizational data via contact_profile instead of direct fields.
        This method extracts and populates the missing direct fields from contact_profile.

        Args:
            data: API response data (modified in-place)
        """
        contact_profile = data.get("contact_profile")
        if not contact_profile:
            return

        # Extract supplier if not present
        if "supplier" not in data or not data["supplier"]:
            supplier = self._extract_entity_by_role(contact_profile, "is_supplier")
            if supplier:
                data["supplier"] = supplier
                logger.debug(f"Extracted supplier from contact_profile: {supplier.get('name')}")

        # Extract manufacturer if not present
        if "manufacturer" not in data or not data["manufacturer"]:
            manufacturer = self._extract_entity_by_role(contact_profile, "is_manufacturer")
            if manufacturer:
                data["manufacturer"] = manufacturer
                logger.debug(f"Extracted manufacturer from contact_profile: {manufacturer.get('name')}")

        # Extract authors if not present
        if "authors" not in data or not data["authors"]:
            authors = self._extract_authors(contact_profile)
            if authors:
                data["authors"] = authors
                logger.debug(f"Extracted {len(authors)} author(s) from contact_profile")

        # Extract security_contact if not present
        if "security_contact" not in data or not data["security_contact"]:
            security_contact = self._extract_security_contact(data)
            if security_contact:
                data["security_contact"] = security_contact
                logger.debug(f"Extracted security_contact from contact_profile: {security_contact}")

    def _extract_entity_by_role(self, contact_profile: Dict[str, Any], role_flag: str) -> Dict[str, Any] | None:
        """
        Extract an entity (supplier/manufacturer) from contact_profile by role flag.

        Args:
            contact_profile: The contact_profile structure
            role_flag: The role flag to look for (e.g., 'is_supplier', 'is_manufacturer')

        Returns:
            Entity dict in the format expected by AugmentationMetadata, or None
        """
        for entity in contact_profile.get("entities", []):
            if entity.get(role_flag):
                # Convert to the format expected by augmentation
                result: Dict[str, Any] = {}

                if entity.get("name"):
                    result["name"] = entity["name"]

                # Convert website_urls to url list
                urls = entity.get("website_urls", [])
                if urls:
                    result["url"] = urls

                if entity.get("address"):
                    result["address"] = entity["address"]

                # Convert entity contacts to contacts list
                contacts = []
                for contact in entity.get("contacts", []):
                    contact_dict: Dict[str, Any] = {}
                    if contact.get("name"):
                        contact_dict["name"] = contact["name"]
                    if contact.get("email"):
                        contact_dict["email"] = contact["email"]
                    if contact.get("phone"):
                        contact_dict["phone"] = contact["phone"]
                    if contact_dict:
                        contacts.append(contact_dict)

                if contacts:
                    result["contacts"] = contacts

                return result if result else None

        return None

    def _extract_authors(self, contact_profile: Dict[str, Any]) -> List[Dict[str, Any]] | None:
        """
        Extract authors from contact_profile.

        Authors can come from:
        1. contact_profile.authors (AuthorContactSchema[])
        2. contact_profile.entities where is_author=true

        Args:
            contact_profile: The contact_profile structure

        Returns:
            List of author dicts in the format expected by AugmentationMetadata, or None
        """
        authors: List[Dict[str, Any]] = []

        # Extract from profile-level authors
        for author in contact_profile.get("authors", []):
            author_dict: Dict[str, Any] = {}
            if author.get("name"):
                author_dict["name"] = author["name"]
            if author.get("email"):
                author_dict["email"] = author["email"]
            if author.get("phone"):
                author_dict["phone"] = author["phone"]
            if author_dict:
                authors.append(author_dict)

        # Also check entities with is_author flag
        for entity in contact_profile.get("entities", []):
            if entity.get("is_author"):
                # For entities marked as author, add their contacts as authors
                for contact in entity.get("contacts", []):
                    author_dict = {}
                    if contact.get("name"):
                        author_dict["name"] = contact["name"]
                    if contact.get("email"):
                        author_dict["email"] = contact["email"]
                    if contact.get("phone"):
                        author_dict["phone"] = contact["phone"]
                    if author_dict and author_dict not in authors:
                        authors.append(author_dict)

        return authors if authors else None

    def _extract_security_contact(self, data: Dict[str, Any]) -> str | None:
        """
        Extract security contact from contact_profile structure.

        The API returns contact_profile with nested contacts that have
        'is_security_contact' flags to identify security contacts.

        Args:
            data: API response data containing contact_profile

        Returns:
            Security contact as mailto: URI, or None if not found
        """
        contact_profile = data.get("contact_profile")
        if not contact_profile:
            return None

        # Check profile-level contacts first
        security_contact = self._find_security_contact_in_list(contact_profile.get("contacts", []))
        if security_contact:
            return security_contact

        # Check entity-level contacts
        for entity in contact_profile.get("entities", []):
            security_contact = self._find_security_contact_in_list(entity.get("contacts", []))
            if security_contact:
                return security_contact

        return None

    def _find_security_contact_in_list(self, contacts: List[Dict[str, Any]]) -> str | None:
        """
        Find security contact in a list of contacts.

        Args:
            contacts: List of contact dictionaries

        Returns:
            Security contact as mailto: URI, or None if not found
        """
        for contact in contacts:
            if contact.get("is_security_contact") and contact.get("email"):
                email = contact["email"]
                # Return as mailto: URI for CycloneDX externalReference compatibility
                if not email.startswith("mailto:"):
                    return f"mailto:{email}"
                return str(email)
        return None
