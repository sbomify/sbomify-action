"""Tests for augmentation providers (JSON config and sbomify API)."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from sbomify_action._augmentation import (
    AugmentationMetadata,
    ProviderRegistry,
    create_default_registry,
)
from sbomify_action._augmentation.providers import JsonConfigProvider, SbomifyApiProvider


class TestAugmentationMetadata:
    """Tests for AugmentationMetadata dataclass."""

    def test_has_data_with_supplier(self):
        """Test has_data returns True when supplier is present."""
        metadata = AugmentationMetadata(supplier={"name": "Test"})
        assert metadata.has_data() is True

    def test_has_data_with_manufacturer(self):
        """Test has_data returns True when manufacturer is present."""
        metadata = AugmentationMetadata(manufacturer={"name": "Test Manufacturer"})
        assert metadata.has_data() is True

    def test_has_data_with_lifecycle(self):
        """Test has_data returns True when lifecycle_phase is present."""
        metadata = AugmentationMetadata(lifecycle_phase="build")
        assert metadata.has_data() is True

    def test_has_data_empty(self):
        """Test has_data returns False when empty."""
        metadata = AugmentationMetadata()
        assert metadata.has_data() is False

    def test_has_data_with_security_contact(self):
        """Test has_data returns True when security_contact is present."""
        metadata = AugmentationMetadata(security_contact="https://example.com/security")
        assert metadata.has_data() is True

    def test_has_data_with_support_period_end(self):
        """Test has_data returns True when support_period_end is present."""
        metadata = AugmentationMetadata(support_period_end="2028-12-31")
        assert metadata.has_data() is True

    def test_has_data_with_release_date(self):
        """Test has_data returns True when release_date is present."""
        metadata = AugmentationMetadata(release_date="2024-06-15")
        assert metadata.has_data() is True

    def test_has_data_with_end_of_life(self):
        """Test has_data returns True when end_of_life is present."""
        metadata = AugmentationMetadata(end_of_life="2028-12-31")
        assert metadata.has_data() is True

    def test_merge_prefers_existing(self):
        """Test merge keeps existing values over new ones."""
        existing = AugmentationMetadata(
            supplier={"name": "Existing"},
            lifecycle_phase="build",
            source="existing-source",
        )
        new = AugmentationMetadata(
            supplier={"name": "New"},
            authors=[{"name": "Author"}],
            lifecycle_phase="operations",
            source="new-source",
        )

        merged = existing.merge(new)

        assert merged.supplier["name"] == "Existing"
        assert merged.lifecycle_phase == "build"
        assert merged.authors == [{"name": "Author"}]
        assert "existing-source" in merged.source
        assert "new-source" in merged.source

    def test_merge_manufacturer(self):
        """Test merge handles manufacturer field correctly."""
        existing = AugmentationMetadata(
            manufacturer={"name": "Existing Mfg"},
            source="existing-source",
        )
        new = AugmentationMetadata(
            manufacturer={"name": "New Mfg"},
            supplier={"name": "New Supplier"},
            source="new-source",
        )

        merged = existing.merge(new)

        # Existing manufacturer should be preserved
        assert merged.manufacturer["name"] == "Existing Mfg"
        # New supplier should be filled in
        assert merged.supplier["name"] == "New Supplier"

    def test_merge_fills_missing_manufacturer(self):
        """Test merge fills in missing manufacturer from other."""
        existing = AugmentationMetadata(
            supplier={"name": "Existing Supplier"},
            source="existing-source",
        )
        new = AugmentationMetadata(
            manufacturer={"name": "New Mfg"},
            source="new-source",
        )

        merged = existing.merge(new)

        # Manufacturer should be filled from new
        assert merged.manufacturer["name"] == "New Mfg"
        # Existing supplier should be preserved
        assert merged.supplier["name"] == "Existing Supplier"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        metadata = AugmentationMetadata(
            supplier={"name": "Test"},
            lifecycle_phase="build",
        )

        result = metadata.to_dict()

        assert result["supplier"]["name"] == "Test"
        assert result["lifecycle_phase"] == "build"

    def test_to_dict_with_manufacturer(self):
        """Test conversion to dictionary includes manufacturer."""
        metadata = AugmentationMetadata(
            supplier={"name": "Test Supplier"},
            manufacturer={"name": "Test Manufacturer", "url": ["https://mfg.com"]},
            lifecycle_phase="build",
        )

        result = metadata.to_dict()

        assert result["supplier"]["name"] == "Test Supplier"
        assert result["manufacturer"]["name"] == "Test Manufacturer"
        assert result["manufacturer"]["url"] == ["https://mfg.com"]
        assert result["lifecycle_phase"] == "build"

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "supplier": {"name": "Test"},
            "lifecycle_phase": "build",
            "extra_field": "extra_value",
        }

        metadata = AugmentationMetadata.from_dict(data, source="test")

        assert metadata.supplier["name"] == "Test"
        assert metadata.lifecycle_phase == "build"
        assert metadata.source == "test"
        assert metadata._extra["extra_field"] == "extra_value"

    def test_from_dict_with_manufacturer(self):
        """Test creation from dictionary with manufacturer."""
        data = {
            "supplier": {"name": "Test Supplier"},
            "manufacturer": {
                "name": "Test Manufacturer",
                "url": ["https://mfg.com"],
                "contacts": [{"name": "Mfg Contact", "email": "contact@mfg.com"}],
            },
            "lifecycle_phase": "build",
        }

        metadata = AugmentationMetadata.from_dict(data, source="test")

        assert metadata.supplier["name"] == "Test Supplier"
        assert metadata.manufacturer["name"] == "Test Manufacturer"
        assert metadata.manufacturer["url"] == ["https://mfg.com"]
        assert len(metadata.manufacturer["contacts"]) == 1
        assert metadata.lifecycle_phase == "build"
        assert metadata.source == "test"

    def test_to_dict_with_security_fields(self):
        """Test conversion to dictionary includes security_contact and support_period_end."""
        metadata = AugmentationMetadata(
            supplier={"name": "Test Supplier"},
            security_contact="https://example.com/.well-known/security.txt",
            support_period_end="2028-12-31",
        )

        result = metadata.to_dict()

        assert result["supplier"]["name"] == "Test Supplier"
        assert result["security_contact"] == "https://example.com/.well-known/security.txt"
        assert result["support_period_end"] == "2028-12-31"

    def test_from_dict_with_security_fields(self):
        """Test creation from dictionary with security_contact and support_period_end."""
        data = {
            "supplier": {"name": "Test Supplier"},
            "security_contact": "mailto:security@example.com",
            "support_period_end": "2028-12-31",
        }

        metadata = AugmentationMetadata.from_dict(data, source="test")

        assert metadata.supplier["name"] == "Test Supplier"
        assert metadata.security_contact == "mailto:security@example.com"
        assert metadata.support_period_end == "2028-12-31"
        assert metadata.source == "test"

    def test_merge_security_fields(self):
        """Test merge handles security_contact and support_period_end correctly."""
        existing = AugmentationMetadata(
            security_contact="https://existing.com/security",
            source="existing-source",
        )
        new = AugmentationMetadata(
            security_contact="https://new.com/security",
            support_period_end="2028-12-31",
            source="new-source",
        )

        merged = existing.merge(new)

        # Existing security_contact should be preserved
        assert merged.security_contact == "https://existing.com/security"
        # New support_period_end should be filled in
        assert merged.support_period_end == "2028-12-31"

    def test_merge_lifecycle_date_fields(self):
        """Test merge handles release_date and end_of_life correctly."""
        existing = AugmentationMetadata(
            release_date="2024-06-15",
            source="existing-source",
        )
        new = AugmentationMetadata(
            release_date="2024-01-01",  # Different release date
            end_of_life="2028-12-31",
            support_period_end="2026-12-31",
            source="new-source",
        )

        merged = existing.merge(new)

        # Existing release_date should be preserved
        assert merged.release_date == "2024-06-15"
        # New end_of_life should be filled in
        assert merged.end_of_life == "2028-12-31"
        # New support_period_end should be filled in
        assert merged.support_period_end == "2026-12-31"

    def test_to_dict_with_lifecycle_date_fields(self):
        """Test conversion to dictionary includes release_date and end_of_life."""
        metadata = AugmentationMetadata(
            supplier={"name": "Test Supplier"},
            release_date="2024-06-15",
            support_period_end="2026-12-31",
            end_of_life="2028-12-31",
        )

        result = metadata.to_dict()

        assert result["supplier"]["name"] == "Test Supplier"
        assert result["release_date"] == "2024-06-15"
        assert result["support_period_end"] == "2026-12-31"
        assert result["end_of_life"] == "2028-12-31"

    def test_from_dict_with_lifecycle_date_fields(self):
        """Test creation from dictionary with release_date and end_of_life."""
        data = {
            "supplier": {"name": "Test Supplier"},
            "release_date": "2024-06-15",
            "support_period_end": "2026-12-31",
            "end_of_life": "2028-12-31",
        }

        metadata = AugmentationMetadata.from_dict(data, source="test")

        assert metadata.supplier["name"] == "Test Supplier"
        assert metadata.release_date == "2024-06-15"
        assert metadata.support_period_end == "2026-12-31"
        assert metadata.end_of_life == "2028-12-31"
        assert metadata.source == "test"

    def test_from_dict_maps_api_field_names(self):
        """Test from_dict maps sbomify API field names to internal names.

        The sbomify API uses 'end_of_support' while we use 'support_period_end'.
        """
        data = {
            "supplier": {"name": "API Supplier"},
            "end_of_support": "2026-12-31",  # API field name
            "release_date": "2024-06-15",
            "end_of_life": "2028-12-31",
        }

        metadata = AugmentationMetadata.from_dict(data, source="sbomify-api")

        # API field 'end_of_support' should map to 'support_period_end'
        assert metadata.support_period_end == "2026-12-31"
        assert metadata.release_date == "2024-06-15"
        assert metadata.end_of_life == "2028-12-31"

    def test_from_dict_prefers_internal_field_name(self):
        """Test that internal field name takes precedence over API field name.

        If both 'support_period_end' and 'end_of_support' are present,
        'support_period_end' should take precedence.
        """
        data = {
            "support_period_end": "2027-06-30",  # Internal field name
            "end_of_support": "2026-12-31",  # API field name
        }

        metadata = AugmentationMetadata.from_dict(data, source="test")

        # Internal field name should take precedence
        assert metadata.support_period_end == "2027-06-30"


class TestJsonConfigProvider:
    """Tests for JsonConfigProvider."""

    def test_provider_properties(self):
        """Test provider has correct name and priority."""
        provider = JsonConfigProvider()
        assert provider.name == "json-config"
        assert provider.priority == 10

    def test_fetch_with_config_file(self):
        """Test fetching from a JSON config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            config_data = {
                "lifecycle_phase": "build",
                "supplier": {"name": "Test Corp"},
                "manufacturer": {"name": "Test Manufacturer", "url": ["https://mfg.test"]},
            }
            with open(config_file, "w") as f:
                json.dump(config_data, f)

            provider = JsonConfigProvider()
            result = provider.fetch(config_path=str(config_file))

            assert result is not None
            assert result.lifecycle_phase == "build"
            assert result.supplier["name"] == "Test Corp"
            assert result.manufacturer["name"] == "Test Manufacturer"
            assert result.manufacturer["url"] == ["https://mfg.test"]
            assert result.source == "json-config"

    def test_fetch_no_config_file(self):
        """Test returns None when no config file exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Change to empty directory
            import os

            original_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                provider = JsonConfigProvider()
                result = provider.fetch()
                assert result is None
            finally:
                os.chdir(original_cwd)

    def test_fetch_invalid_json(self):
        """Test returns None for invalid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            with open(config_file, "w") as f:
                f.write("{invalid json")

            provider = JsonConfigProvider()
            result = provider.fetch(config_path=str(config_file))

            assert result is None

    def test_fetch_empty_config(self):
        """Test returns None for empty config (no meaningful data)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            with open(config_file, "w") as f:
                json.dump({}, f)

            provider = JsonConfigProvider()
            result = provider.fetch(config_path=str(config_file))

            assert result is None


class TestSbomifyApiProvider:
    """Tests for SbomifyApiProvider."""

    def test_provider_properties(self):
        """Test provider has correct name and priority."""
        provider = SbomifyApiProvider()
        assert provider.name == "sbomify-api"
        assert provider.priority == 50

    def test_fetch_without_required_params(self):
        """Test returns None without required parameters."""
        provider = SbomifyApiProvider()

        # Missing component_id
        assert provider.fetch(api_base_url="https://api.test.com", token="test") is None

        # Missing api_base_url
        assert provider.fetch(component_id="test-id", token="test") is None

        # Missing token
        assert provider.fetch(component_id="test-id", api_base_url="https://api.test.com") is None

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_success(self, mock_get):
        """Test successful API fetch."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "API Supplier"},
            "lifecycle_phase": "post-build",
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        assert result.supplier["name"] == "API Supplier"
        assert result.lifecycle_phase == "post-build"
        assert result.source == "sbomify-api"

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_api_error(self, mock_get):
        """Test returns None on API error."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.headers = {}
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is None

    def test_extract_security_contact_from_profile_contacts(self):
        """Test extraction of security contact from contact_profile.contacts."""
        provider = SbomifyApiProvider()
        data = {
            "contact_profile": {
                "contacts": [
                    {"name": "Regular Contact", "email": "info@example.com", "is_security_contact": False},
                    {"name": "Security Team", "email": "security@example.com", "is_security_contact": True},
                ]
            }
        }

        result = provider._extract_security_contact(data)

        assert result == "mailto:security@example.com"

    def test_extract_security_contact_from_entity_contacts(self):
        """Test extraction of security contact from contact_profile.entities[].contacts."""
        provider = SbomifyApiProvider()
        data = {
            "contact_profile": {
                "contacts": [],  # No profile-level contacts
                "entities": [
                    {
                        "name": "Company Inc",
                        "contacts": [
                            {"name": "Security Officer", "email": "cso@company.com", "is_security_contact": True},
                        ],
                    }
                ],
            }
        }

        result = provider._extract_security_contact(data)

        assert result == "mailto:cso@company.com"

    def test_extract_security_contact_profile_takes_precedence(self):
        """Test that profile-level contacts take precedence over entity-level."""
        provider = SbomifyApiProvider()
        data = {
            "contact_profile": {
                "contacts": [
                    {"name": "Profile Security", "email": "profile@example.com", "is_security_contact": True},
                ],
                "entities": [
                    {
                        "name": "Entity",
                        "contacts": [
                            {"name": "Entity Security", "email": "entity@example.com", "is_security_contact": True},
                        ],
                    }
                ],
            }
        }

        result = provider._extract_security_contact(data)

        # Profile-level contact should be returned (checked first)
        assert result == "mailto:profile@example.com"

    def test_extract_security_contact_no_contact_profile(self):
        """Test returns None when no contact_profile exists."""
        provider = SbomifyApiProvider()
        data = {"supplier": {"name": "Test"}}

        result = provider._extract_security_contact(data)

        assert result is None

    def test_extract_security_contact_no_security_contact_flag(self):
        """Test returns None when no contact has is_security_contact=True."""
        provider = SbomifyApiProvider()
        data = {
            "contact_profile": {
                "contacts": [
                    {"name": "Regular", "email": "regular@example.com", "is_security_contact": False},
                ]
            }
        }

        result = provider._extract_security_contact(data)

        assert result is None

    def test_extract_security_contact_preserves_existing_mailto(self):
        """Test that mailto: prefix is not doubled if already present."""
        provider = SbomifyApiProvider()
        data = {
            "contact_profile": {
                "contacts": [
                    {"name": "Security", "email": "mailto:security@example.com", "is_security_contact": True},
                ]
            }
        }

        result = provider._extract_security_contact(data)

        assert result == "mailto:security@example.com"

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_extracts_security_contact_from_contact_profile(self, mock_get):
        """Test that fetch() extracts security_contact from contact_profile."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "Test Supplier"},
            "contact_profile": {
                "contacts": [
                    {"name": "Security Team", "email": "security@test.com", "is_security_contact": True},
                ]
            },
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        assert result.security_contact == "mailto:security@test.com"

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_preserves_explicit_security_contact(self, mock_get):
        """Test that explicit security_contact takes precedence over contact_profile."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "Test Supplier"},
            "security_contact": "https://example.com/security.txt",
            "contact_profile": {
                "contacts": [
                    {"name": "Security Team", "email": "security@test.com", "is_security_contact": True},
                ]
            },
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        # Explicit security_contact should be preserved
        assert result.security_contact == "https://example.com/security.txt"

    def test_extract_entity_by_role_supplier(self):
        """Test extraction of supplier entity from contact_profile."""
        provider = SbomifyApiProvider()
        contact_profile = {
            "entities": [
                {
                    "name": "Acme Corp",
                    "is_supplier": True,
                    "is_manufacturer": False,
                    "website_urls": ["https://acme.com"],
                    "address": "123 Main St",
                    "contacts": [{"name": "Support", "email": "support@acme.com", "phone": "555-1234"}],
                }
            ]
        }

        result = provider._extract_entity_by_role(contact_profile, "is_supplier")

        assert result is not None
        assert result["name"] == "Acme Corp"
        assert result["url"] == ["https://acme.com"]
        assert result["address"] == "123 Main St"
        assert len(result["contacts"]) == 1
        assert result["contacts"][0]["name"] == "Support"
        assert result["contacts"][0]["email"] == "support@acme.com"

    def test_extract_entity_by_role_manufacturer(self):
        """Test extraction of manufacturer entity from contact_profile."""
        provider = SbomifyApiProvider()
        contact_profile = {
            "entities": [
                {
                    "name": "Manufacturer Inc",
                    "is_manufacturer": True,
                    "is_supplier": False,
                    "website_urls": ["https://mfg.com"],
                    "contacts": [{"name": "Contact", "email": "contact@mfg.com"}],
                }
            ]
        }

        result = provider._extract_entity_by_role(contact_profile, "is_manufacturer")

        assert result is not None
        assert result["name"] == "Manufacturer Inc"
        assert result["url"] == ["https://mfg.com"]
        assert len(result["contacts"]) == 1

    def test_extract_entity_by_role_not_found(self):
        """Test returns None when entity role not found."""
        provider = SbomifyApiProvider()
        contact_profile = {"entities": [{"name": "Some Entity", "is_supplier": False, "is_manufacturer": False}]}

        result = provider._extract_entity_by_role(contact_profile, "is_supplier")

        assert result is None

    def test_extract_authors_from_profile(self):
        """Test extraction of authors from contact_profile.authors."""
        provider = SbomifyApiProvider()
        contact_profile = {
            "authors": [
                {"name": "John Doe", "email": "john@example.com"},
                {"name": "Jane Smith", "email": "jane@example.com", "phone": "555-9876"},
            ],
            "entities": [],
        }

        result = provider._extract_authors(contact_profile)

        assert result is not None
        assert len(result) == 2
        assert result[0]["name"] == "John Doe"
        assert result[0]["email"] == "john@example.com"
        assert result[1]["name"] == "Jane Smith"
        assert result[1]["phone"] == "555-9876"

    def test_extract_authors_from_entities(self):
        """Test extraction of authors from entities with is_author=True."""
        provider = SbomifyApiProvider()
        contact_profile = {
            "authors": [],
            "entities": [
                {
                    "name": "Author Org",
                    "is_author": True,
                    "contacts": [{"name": "Bob Author", "email": "bob@author.org"}],
                }
            ],
        }

        result = provider._extract_authors(contact_profile)

        assert result is not None
        assert len(result) == 1
        assert result[0]["name"] == "Bob Author"
        assert result[0]["email"] == "bob@author.org"

    def test_extract_authors_combined(self):
        """Test extraction of authors from both profile-level and entities."""
        provider = SbomifyApiProvider()
        contact_profile = {
            "authors": [{"name": "Profile Author", "email": "profile@example.com"}],
            "entities": [
                {
                    "name": "Author Entity",
                    "is_author": True,
                    "contacts": [{"name": "Entity Author", "email": "entity@example.com"}],
                }
            ],
        }

        result = provider._extract_authors(contact_profile)

        assert result is not None
        assert len(result) == 2
        names = [a["name"] for a in result]
        assert "Profile Author" in names
        assert "Entity Author" in names

    def test_extract_authors_empty(self):
        """Test returns None when no authors found."""
        provider = SbomifyApiProvider()
        contact_profile = {"authors": [], "entities": []}

        result = provider._extract_authors(contact_profile)

        assert result is None

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_extracts_supplier_from_contact_profile(self, mock_get):
        """Test that fetch() extracts supplier from contact_profile when not directly provided."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "contact_profile": {
                "entities": [
                    {
                        "name": "Contact Profile Supplier",
                        "is_supplier": True,
                        "website_urls": ["https://supplier.com"],
                        "contacts": [{"name": "Support", "email": "support@supplier.com"}],
                    }
                ],
                "authors": [],
                "contacts": [],
            }
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        assert result.supplier is not None
        assert result.supplier["name"] == "Contact Profile Supplier"
        assert result.supplier["url"] == ["https://supplier.com"]

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_preserves_explicit_supplier(self, mock_get):
        """Test that explicit supplier takes precedence over contact_profile."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "Direct Supplier"},
            "contact_profile": {
                "entities": [{"name": "Contact Profile Supplier", "is_supplier": True}],
                "authors": [],
                "contacts": [],
            },
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        # Explicit supplier should be preserved
        assert result.supplier["name"] == "Direct Supplier"

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_extracts_manufacturer_from_contact_profile(self, mock_get):
        """Test that fetch() extracts manufacturer from contact_profile when not directly provided."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "contact_profile": {
                "entities": [
                    {
                        "name": "Contact Profile Manufacturer",
                        "is_manufacturer": True,
                        "contacts": [{"name": "Mfg Contact", "email": "contact@mfg.com"}],
                    }
                ],
                "authors": [],
                "contacts": [],
            }
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        assert result.manufacturer is not None
        assert result.manufacturer["name"] == "Contact Profile Manufacturer"

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_extracts_authors_from_contact_profile(self, mock_get):
        """Test that fetch() extracts authors from contact_profile when not directly provided."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "contact_profile": {
                "entities": [],
                "authors": [{"name": "Jane Developer", "email": "jane@dev.com"}],
                "contacts": [],
            }
        }
        mock_get.return_value = mock_response

        provider = SbomifyApiProvider()
        result = provider.fetch(
            component_id="test-component",
            api_base_url="https://api.test.com",
            token="test-token",
        )

        assert result is not None
        assert result.authors is not None
        assert len(result.authors) == 1
        assert result.authors[0]["name"] == "Jane Developer"


class TestProviderRegistry:
    """Tests for ProviderRegistry."""

    def test_register_and_list(self):
        """Test registering and listing providers."""
        registry = ProviderRegistry()
        registry.register(JsonConfigProvider())
        registry.register(SbomifyApiProvider())

        providers = registry.list_providers()

        assert len(providers) == 2
        # Should be sorted by priority
        assert providers[0]["name"] == "json-config"
        assert providers[0]["priority"] == 10
        assert providers[1]["name"] == "sbomify-api"
        assert providers[1]["priority"] == 50

    def test_get_providers_sorted(self):
        """Test providers are returned sorted by priority."""
        registry = ProviderRegistry()
        # Register in reverse order
        registry.register(SbomifyApiProvider())  # priority 50
        registry.register(JsonConfigProvider())  # priority 10

        providers = registry.get_providers()

        assert providers[0].priority == 10
        assert providers[1].priority == 50

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_metadata_merges_results(self, mock_get):
        """Test that metadata from multiple providers is merged."""
        # Setup API mock
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "API Supplier"},
            "authors": [{"name": "API Author"}],
        }
        mock_get.return_value = mock_response

        # Create config file with lifecycle_phase
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            config_data = {"lifecycle_phase": "build"}
            with open(config_file, "w") as f:
                json.dump(config_data, f)

            registry = create_default_registry()
            result = registry.fetch_metadata(
                component_id="test-component",
                api_base_url="https://api.test.com",
                token="test-token",
                config_path=str(config_file),
            )

            # lifecycle_phase from JSON config (higher priority)
            assert result.lifecycle_phase == "build"
            # supplier from API (lower priority, fills in missing)
            assert result.supplier["name"] == "API Supplier"
            # authors from API
            assert result.authors == [{"name": "API Author"}]

    def test_fetch_metadata_no_providers(self):
        """Test returns None when no providers registered."""
        registry = ProviderRegistry()
        result = registry.fetch_metadata()
        assert result is None


class TestCreateDefaultRegistry:
    """Tests for create_default_registry factory function."""

    def test_creates_registry_with_default_providers(self):
        """Test factory creates registry with all default providers."""
        registry = create_default_registry()
        providers = registry.list_providers()

        # 6 providers: json-config, docker-image, github-actions,
        # gitlab-ci, bitbucket-pipelines, sbomify-api
        assert len(providers) == 6
        provider_names = [p["name"] for p in providers]
        assert "json-config" in provider_names
        assert "docker-image" in provider_names
        assert "github-actions" in provider_names
        assert "gitlab-ci" in provider_names
        assert "bitbucket-pipelines" in provider_names
        assert "sbomify-api" in provider_names

        # Verify priority ordering (lower = higher priority)
        priorities = {p["name"]: p["priority"] for p in providers}
        assert priorities["json-config"] == 10  # Highest priority
        assert priorities["docker-image"] == 15  # Container-image input
        assert priorities["github-actions"] == 20
        assert priorities["gitlab-ci"] == 20
        assert priorities["bitbucket-pipelines"] == 20
        assert priorities["sbomify-api"] == 50  # Lowest priority


class TestLifecyclePhasePrecedence:
    """End-to-end precedence tests for lifecycle_phase across the registry.

    These pin the spec-correct defaults that the providers emit in
    realistic input/environment combinations, so a future refactor can't
    silently regress the CDX 1.7 meta:enum alignment (pre-build for
    lockfile scans, post-build for built-image scans, build only when
    the operator explicitly opts in via sbomify.json).
    """

    @pytest.fixture(autouse=True)
    def _restore_cwd(self):
        """Save and restore working directory around each test.

        JsonConfigProvider reads ``sbomify.json`` from cwd, so these
        tests ``chdir`` into an isolated tmpdir. Without this fixture
        the chdir leaks into sibling tests and breaks anything that
        relies on the real project cwd.
        """
        original = os.getcwd()
        try:
            yield
        finally:
            os.chdir(original)

    def _registry_no_api(self):
        """Registry without the sbomify-api provider so tests don't hit
        the network. Returns the same 5 providers that actually decide
        lifecycle_phase today."""
        from sbomify_action._augmentation.providers import (
            BitbucketPipelinesProvider,
            DockerImageProvider,
            GitHubActionsProvider,
            GitLabCIProvider,
            JsonConfigProvider,
        )
        from sbomify_action._augmentation.registry import ProviderRegistry

        registry = ProviderRegistry()
        registry.register(JsonConfigProvider())
        registry.register(DockerImageProvider())
        registry.register(GitHubActionsProvider())
        registry.register(GitLabCIProvider())
        registry.register(BitbucketPipelinesProvider())
        return registry

    def test_ci_lockfile_scan_defaults_to_pre_build(self):
        """GitHub Actions env alone (no json config, no docker image)
        yields pre-build — the schema-correct default for a lockfile /
        manifest scan on CI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)  # no sbomify.json here
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
            }
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "pre-build"

    def test_docker_image_overrides_ci_default_to_post_build(self):
        """DOCKER_IMAGE set alongside GITHUB_ACTIONS yields post-build.
        DockerImageProvider (priority 15) wins over the CI providers
        (priority 20) so a container-image scan lands in the correct
        phase even when running on GitHub Actions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
                "DOCKER_IMAGE": "ubuntu:24.04",
            }
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "post-build"

    def test_json_config_overrides_both_ci_and_docker(self):
        """Operator-supplied sbomify.json (priority 10) is the final
        word — operators who truly emit a BOM mid-compilation can
        opt into ``lifecycle_phase="build"`` regardless of CI /
        docker-image detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            config_file.write_text(json.dumps({"lifecycle_phase": "build"}))
            os.chdir(tmpdir)
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
                "DOCKER_IMAGE": "ubuntu:24.04",
            }
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "build"

    def test_gitlab_defaults_to_pre_build(self):
        """Same spec-alignment applies to GitLab CI and Bitbucket
        Pipelines — parametrise-style coverage without the pytest
        parametrise boilerplate since patch.dict with different
        env sets doesn't compose cleanly as parameters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {
                "GITLAB_CI": "true",
                "CI_PROJECT_URL": "https://gitlab.com/group/proj",
                "CI_COMMIT_SHA": "a" * 40,
                "CI_COMMIT_REF_NAME": "main",
            }
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "pre-build"

    def test_bitbucket_defaults_to_pre_build(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {
                "BITBUCKET_PIPELINE_UUID": "{abc-123}",
                "BITBUCKET_GIT_HTTP_ORIGIN": "https://bitbucket.org/ws/repo",
                "BITBUCKET_COMMIT": "a" * 40,
                "BITBUCKET_BRANCH": "main",
            }
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "pre-build"

    def test_docker_image_alone_without_ci_still_emits_post_build(self):
        """DOCKER_IMAGE set with no CI env vars and no sbomify.json must
        still emit ``post-build`` — a user running the action locally
        against a built image deserves the same spec-correct phase as
        a CI run against the same image."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {"DOCKER_IMAGE": "ubuntu:24.04"}
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "post-build"

    def test_json_config_overrides_docker_image_without_ci(self):
        """sbomify.json beats docker-image provider even without a CI
        provider in the mix. Mirrors the real-world case where a user
        is running locally and wants the container-image scan classified
        as something other than ``post-build``."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            config_file.write_text(json.dumps({"lifecycle_phase": "operations"}))
            os.chdir(tmpdir)
            env = {"DOCKER_IMAGE": "ubuntu:24.04"}
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "operations"

    def test_no_input_signals_yields_no_lifecycle_phase(self):
        """No CI env, no DOCKER_IMAGE, no sbomify.json → no provider
        has a lifecycle_phase to contribute, so the merged metadata's
        lifecycle_phase is None. The compliance plugins will then
        correctly report "missing generation context" rather than
        inventing a phase."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            with patch.dict(os.environ, {}, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            # Registry may return None or a metadata object with no
            # fields set — either signals "nothing to augment".
            assert metadata is None or metadata.lifecycle_phase is None

    def test_disable_vcs_augmentation_still_lets_docker_image_fire(self):
        """DISABLE_VCS_AUGMENTATION only silences the CI providers' VCS
        side of things; the DockerImageProvider (which doesn't touch
        VCS metadata) must still emit its lifecycle_phase signal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {
                "DISABLE_VCS_AUGMENTATION": "true",
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
                "DOCKER_IMAGE": "ubuntu:24.04",
            }
            with patch.dict(os.environ, env, clear=True):
                registry = self._registry_no_api()
                metadata = registry.fetch_metadata()

            assert metadata is not None
            assert metadata.lifecycle_phase == "post-build"


class TestLifecyclePhaseSpdxCdxParity:
    """End-to-end parity tests: CI provider default → both SPDX and
    CycloneDX outputs carry the same lifecycle phase.

    The augmentation code writes the phase to different spec-native
    locations:
      * CycloneDX: ``metadata.lifecycles[].phase`` (1.5+)
      * SPDX 2.x: ``creationInfo.creatorComment`` as ``"Lifecycle phase: <phase>"``

    The sbomify CISA plugin reads both, so any drift between the two
    paths would give the same BOM different compliance verdicts in
    CDX vs SPDX. These tests pin the parity explicitly.
    """

    @pytest.fixture(autouse=True)
    def _restore_cwd(self):
        original = os.getcwd()
        try:
            yield
        finally:
            os.chdir(original)

    def _fetch_from_registry(self, env):
        """Run the real registry (minus sbomify-api) with ``env`` as
        the only env vars and return the merged AugmentationMetadata."""
        from sbomify_action._augmentation.providers import (
            BitbucketPipelinesProvider,
            DockerImageProvider,
            GitHubActionsProvider,
            GitLabCIProvider,
            JsonConfigProvider,
        )
        from sbomify_action._augmentation.registry import ProviderRegistry

        registry = ProviderRegistry()
        registry.register(JsonConfigProvider())
        registry.register(DockerImageProvider())
        registry.register(GitHubActionsProvider())
        registry.register(GitLabCIProvider())
        registry.register(BitbucketPipelinesProvider())

        with patch.dict(os.environ, env, clear=True):
            return registry.fetch_metadata()

    def _minimal_spdx_doc(self):
        """Build a minimal SPDX 2.3 Document suitable for augmentation."""
        from datetime import datetime

        from spdx_tools.spdx.model import CreationInfo, Document, Package

        return Document(
            creation_info=CreationInfo(
                spdx_version="SPDX-2.3",
                spdx_id="SPDXRef-DOCUMENT",
                name="test-parity-sbom",
                document_namespace="https://example.com/parity",
                creators=[],
                created=datetime(2026, 4, 20, 12, 0, 0),
            ),
            packages=[
                Package(
                    spdx_id="SPDXRef-root",
                    name="parity-app",
                    download_location="https://example.com/download",
                    version="1.0.0",
                )
            ],
            relationships=[],
        )

    def _minimal_cdx_bom(self):
        """Build a minimal CycloneDX 1.6 BOM suitable for augmentation."""
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType

        bom = Bom()
        bom.metadata.component = Component(
            name="parity-app",
            version="1.0.0",
            type=ComponentType.APPLICATION,
            bom_ref="parity-app@1.0.0",
        )
        return bom

    def test_github_ci_lockfile_writes_pre_build_to_both_formats(self):
        """GitHub Actions + lockfile scan → both SPDX creatorComment
        and CDX metadata.lifecycles[0].phase hold ``pre-build``."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
            }
            metadata = self._fetch_from_registry(env)

        assert metadata is not None
        augmentation_data = metadata.to_dict()
        assert augmentation_data["lifecycle_phase"] == "pre-build"

        from sbomify_action.augmentation import augment_cyclonedx_sbom, augment_spdx_sbom

        # CDX path
        bom = self._minimal_cdx_bom()
        augmented_bom = augment_cyclonedx_sbom(bom, augmentation_data, spec_version="1.6")
        phases = [lc.phase.value for lc in augmented_bom.metadata.lifecycles if lc.phase is not None]
        assert "pre-build" in phases, f"CDX lifecycles should carry pre-build; got {phases}"

        # SPDX path
        doc = self._minimal_spdx_doc()
        augmented_doc = augment_spdx_sbom(doc, augmentation_data)
        creator_comment = augmented_doc.creation_info.creator_comment or ""
        assert "Lifecycle phase: pre-build" in creator_comment, (
            f"SPDX creator comment should carry pre-build; got {creator_comment!r}"
        )

    def test_docker_image_writes_post_build_to_both_formats(self):
        """``--docker-image`` on CI → both formats hold ``post-build``."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
                "DOCKER_IMAGE": "ubuntu:24.04",
            }
            metadata = self._fetch_from_registry(env)

        assert metadata is not None
        augmentation_data = metadata.to_dict()
        assert augmentation_data["lifecycle_phase"] == "post-build"

        from sbomify_action.augmentation import augment_cyclonedx_sbom, augment_spdx_sbom

        bom = self._minimal_cdx_bom()
        augmented_bom = augment_cyclonedx_sbom(bom, augmentation_data, spec_version="1.6")
        phases = [lc.phase.value for lc in augmented_bom.metadata.lifecycles if lc.phase is not None]
        assert "post-build" in phases

        doc = self._minimal_spdx_doc()
        augmented_doc = augment_spdx_sbom(doc, augmentation_data)
        creator_comment = augmented_doc.creation_info.creator_comment or ""
        assert "Lifecycle phase: post-build" in creator_comment

    def test_json_config_override_writes_build_to_both_formats(self):
        """Operator override via sbomify.json → both formats carry the
        operator-chosen ``build`` value, confirming the merge order
        survives all the way to the emitted BOM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "sbomify.json"
            config_file.write_text(json.dumps({"lifecycle_phase": "build"}))
            os.chdir(tmpdir)
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
                "DOCKER_IMAGE": "ubuntu:24.04",
            }
            metadata = self._fetch_from_registry(env)

        assert metadata is not None
        augmentation_data = metadata.to_dict()
        assert augmentation_data["lifecycle_phase"] == "build"

        from sbomify_action.augmentation import augment_cyclonedx_sbom, augment_spdx_sbom

        bom = self._minimal_cdx_bom()
        augmented_bom = augment_cyclonedx_sbom(bom, augmentation_data, spec_version="1.6")
        phases = [lc.phase.value for lc in augmented_bom.metadata.lifecycles if lc.phase is not None]
        assert "build" in phases

        doc = self._minimal_spdx_doc()
        augmented_doc = augment_spdx_sbom(doc, augmentation_data)
        creator_comment = augmented_doc.creation_info.creator_comment or ""
        assert "Lifecycle phase: build" in creator_comment


class TestCliDockerImageEnvMirror:
    """Tests for the CLI's DOCKER_IMAGE env-mirror logic.

    The typer ``envvar="DOCKER_IMAGE"`` binding reads env → flag, but
    does not write flag → env. The CLI mirrors ``--docker-image`` into
    the environment so the DockerImageProvider (which reads the env
    var) sees the flag-form input. The logic is small and isolated,
    so test it directly rather than through the full CLI entrypoint.
    """

    @pytest.fixture(autouse=True)
    def _restore_cwd_and_env(self):
        original_cwd = os.getcwd()
        original_docker = os.environ.get("DOCKER_IMAGE")
        try:
            yield
        finally:
            os.chdir(original_cwd)
            if original_docker is None:
                os.environ.pop("DOCKER_IMAGE", None)
            else:
                os.environ["DOCKER_IMAGE"] = original_docker

    @staticmethod
    def _apply_mirror(docker_image):
        """Replicates the CLI's mirror logic verbatim so the test
        doesn't have to spin up the full Click context.
        """
        if docker_image:
            os.environ["DOCKER_IMAGE"] = docker_image

    def test_flag_writes_env_when_env_not_set(self):
        """--docker-image flag without DOCKER_IMAGE env set → env is
        populated so the provider fires."""
        os.environ.pop("DOCKER_IMAGE", None)
        self._apply_mirror("ubuntu:24.04")
        assert os.environ.get("DOCKER_IMAGE") == "ubuntu:24.04"

    def test_flag_overwrites_existing_env_for_consistency(self):
        """Click already resolved CLI flag vs env var before the CLI
        body runs, so ``docker_image`` here IS the effective value.
        Mirror it unconditionally so the DockerImageProvider sees the
        same image the rest of the pipeline scans — otherwise a user
        who runs with a stale ``DOCKER_IMAGE=old:tag`` in the shell and
        passes ``--docker-image new:tag`` would see the provider log
        ``old:tag`` while the actual SBOM is generated from ``new:tag``."""
        os.environ["DOCKER_IMAGE"] = "old:tag"
        self._apply_mirror("new:tag")
        assert os.environ["DOCKER_IMAGE"] == "new:tag"

    def test_none_flag_does_not_touch_env(self):
        """No flag and no env → mirror is a no-op, env stays absent."""
        os.environ.pop("DOCKER_IMAGE", None)
        self._apply_mirror(None)
        assert "DOCKER_IMAGE" not in os.environ

    def test_empty_flag_does_not_touch_env(self):
        """Empty-string flag is not a valid image reference; treat it
        as absent so the mirror does not shadow a later env lookup."""
        os.environ.pop("DOCKER_IMAGE", None)
        self._apply_mirror("")
        assert "DOCKER_IMAGE" not in os.environ


class TestJsonConfigProviderIntegration:
    """Integration tests for JSON config provider with augmentation."""

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_json_config_lifecycle_takes_precedence(self, mock_get):
        """Test that lifecycle_phase from JSON config takes precedence over API."""
        # Setup API mock with different lifecycle
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "lifecycle_phase": "operations",  # API says operations
            "supplier": {"name": "API Supplier"},
        }
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            # JSON config says build
            config_file = Path(tmpdir) / "sbomify.json"
            config_data = {"lifecycle_phase": "build"}
            with open(config_file, "w") as f:
                json.dump(config_data, f)

            from sbomify_action.augmentation import fetch_augmentation_metadata

            result = fetch_augmentation_metadata(
                component_id="test-component",
                api_base_url="https://api.test.com",
                token="test-token",
                config_path=str(config_file),
            )

            # JSON config should win for lifecycle_phase
            assert result["lifecycle_phase"] == "build"
            # API should provide supplier
            assert result["supplier"]["name"] == "API Supplier"
