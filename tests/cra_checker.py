"""
Shared CRA (Cyber Resilience Act) compliance checker for tests.

Reference: EU Cyber Resilience Act (CRA) 2024

CRA requires manufacturers to provide:
1. Security Contact - Point of contact for vulnerability reporting
2. Support Period - Clear indication of security support duration

Additionally, lifecycle dates help with compliance:
3. Release Date - When the component was released
4. End of Life - When all support ends

Field Mappings:

CycloneDX (1.5+ for full support, 1.3-1.4 partial):
- Security Contact: metadata.component.externalReferences[type=security-contact] (1.5+)
                   OR metadata.supplier.contacts[] (1.3-1.4 fallback)
- Release Date: metadata.properties[name=cdx:lifecycle:milestone:generalAvailability]
- Support Period End: metadata.properties[name=cdx:lifecycle:milestone:endOfSupport]
- End of Life: metadata.properties[name=cdx:lifecycle:milestone:endOfLife]

SPDX (2.2 and 2.3):
- Security Contact: packages[].externalRefs[referenceType=security-contact]
- Release Date: packages[].externalRefs[referenceType=release-date]
- Support Period End: packages[].validUntilDate (2.3) OR externalRefs[referenceType=support-end-date]
- End of Life: packages[].externalRefs[referenceType=end-of-life-date]
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from sbomify_action.serialization import get_spdx_json_root_package

# ISO-8601 date regex (YYYY-MM-DD format)
# Reserved for future date validation of lifecycle fields
ISO8601_DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class CRAComplianceChecker:
    """Utility class to check CRA (Cyber Resilience Act) compliance."""

    # CRA Required Fields
    REQUIRED_FIELDS = ["Security Contact", "Support Period End"]

    # CRA Recommended Fields (lifecycle dates)
    RECOMMENDED_FIELDS = ["Release Date", "End of Life"]

    @staticmethod
    def _find_named_lifecycle(lifecycles: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
        """Find a named lifecycle entry by name."""
        for lc in lifecycles:
            if lc.get("name") == name:
                return lc
        return None

    @staticmethod
    def _find_property(properties: List[Dict[str, Any]], name: str) -> Optional[str]:
        """Find a property value by name."""
        for prop in properties:
            if prop.get("name") == name:
                return prop.get("value")
        return None

    @staticmethod
    def _find_external_ref_cdx(ext_refs: List[Dict[str, Any]], ref_type: str) -> Optional[str]:
        """Find a CycloneDX external reference by type."""
        for ref in ext_refs:
            if ref.get("type") == ref_type:
                return ref.get("url")
        return None

    @staticmethod
    def _find_external_ref_spdx(ext_refs: List[Dict[str, Any]], ref_type: str) -> Optional[str]:
        """Find an SPDX external reference by referenceType."""
        for ref in ext_refs:
            if ref.get("referenceType") == ref_type:
                return ref.get("referenceLocator") or ref.get("locator")
        return None

    @classmethod
    def check_cyclonedx(
        cls,
        data: Dict[str, Any],
    ) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
        """
        Check CycloneDX SBOM for CRA compliance.

        Args:
            data: The CycloneDX SBOM as a dictionary.

        Returns:
            Tuple of (is_compliant, present_fields, missing_fields, field_values)
            - is_compliant: True if all required CRA fields are present
            - present_fields: List of present CRA fields
            - missing_fields: List of missing CRA fields
            - field_values: Dict mapping field names to their values
        """
        present: List[str] = []
        missing: List[str] = []
        values: Dict[str, Any] = {}

        metadata = data.get("metadata", {})
        component = metadata.get("component", {})
        lifecycles = metadata.get("lifecycles", [])
        properties = metadata.get("properties", [])
        supplier = metadata.get("supplier", {})

        # Get external references from root component
        component_ext_refs = component.get("externalReferences", [])

        # 1. Security Contact (Required for CRA)
        # Primary: security-contact external reference (CDX 1.5+)
        security_contact = cls._find_external_ref_cdx(component_ext_refs, "security-contact")

        # Fallback: support external reference (CDX 1.3-1.4)
        if not security_contact:
            security_contact = cls._find_external_ref_cdx(component_ext_refs, "support")

        # Fallback: supplier contact email
        if not security_contact:
            contacts = supplier.get("contact", []) or supplier.get("contacts", [])
            for contact in contacts:
                if contact.get("email"):
                    security_contact = contact.get("email")
                    break

        if security_contact:
            present.append("Security Contact")
            values["Security Contact"] = security_contact
        else:
            missing.append("Security Contact")

        # 2. Release Date (Recommended)
        # Check property first (official CycloneDX taxonomy), then lifecycle for backward compat
        release_date = cls._find_property(properties, "cdx:lifecycle:milestone:generalAvailability")
        if not release_date:
            release_lifecycle = cls._find_named_lifecycle(lifecycles, "release")
            if release_lifecycle:
                release_date = release_lifecycle.get("description", "")

        if release_date:
            present.append("Release Date")
            values["Release Date"] = release_date
        else:
            missing.append("Release Date")

        # 3. Support Period End (Required for CRA)
        # Check property first (official CycloneDX taxonomy), then lifecycle for backward compat
        support_end = cls._find_property(properties, "cdx:lifecycle:milestone:endOfSupport")
        if not support_end:
            support_lifecycle = cls._find_named_lifecycle(lifecycles, "support-end")
            if support_lifecycle:
                support_end = support_lifecycle.get("description", "")

        if support_end:
            present.append("Support Period End")
            values["Support Period End"] = support_end
        else:
            missing.append("Support Period End")

        # 4. End of Life (Recommended)
        # Check property first (official CycloneDX taxonomy), then lifecycle for backward compat
        end_of_life = cls._find_property(properties, "cdx:lifecycle:milestone:endOfLife")
        if not end_of_life:
            eol_lifecycle = cls._find_named_lifecycle(lifecycles, "end-of-life")
            if eol_lifecycle:
                end_of_life = eol_lifecycle.get("description", "")

        if end_of_life:
            present.append("End of Life")
            values["End of Life"] = end_of_life
        else:
            missing.append("End of Life")

        # CRA compliance requires security contact and support period
        required_present = all(f in present for f in cls.REQUIRED_FIELDS)
        is_compliant = required_present

        return (is_compliant, present, missing, values)

    @classmethod
    def check_spdx(
        cls,
        data: Dict[str, Any],
    ) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
        """
        Check SPDX SBOM for CRA compliance.

        Args:
            data: The SPDX SBOM as a dictionary.

        Returns:
            Tuple of (is_compliant, present_fields, missing_fields, field_values)
            - is_compliant: True if all required CRA fields are present
            - present_fields: List of present CRA fields
            - missing_fields: List of missing CRA fields
            - field_values: Dict mapping field names to their values
        """
        present: List[str] = []
        missing: List[str] = []
        values: Dict[str, Any] = {}

        # The package the document describes; packages[0] is usually a dependency
        main_package = get_spdx_json_root_package(data)
        if main_package is None:
            return (False, [], cls.REQUIRED_FIELDS + cls.RECOMMENDED_FIELDS, {})

        ext_refs = main_package.get("externalRefs", [])

        # 1. Security Contact (Required for CRA)
        security_contact = cls._find_external_ref_spdx(ext_refs, "security-contact")

        if security_contact:
            present.append("Security Contact")
            values["Security Contact"] = security_contact
        else:
            missing.append("Security Contact")

        # 2. Release Date (Recommended)
        release_date = cls._find_external_ref_spdx(ext_refs, "release-date")

        if release_date:
            present.append("Release Date")
            values["Release Date"] = release_date
        else:
            missing.append("Release Date")

        # 3. Support Period End (Required for CRA)
        # Primary: validUntilDate (SPDX 2.3)
        support_end = main_package.get("validUntilDate")

        # Fallback: external reference
        if not support_end:
            support_end = cls._find_external_ref_spdx(ext_refs, "support-end-date")

        if support_end:
            present.append("Support Period End")
            values["Support Period End"] = support_end
        else:
            missing.append("Support Period End")

        # 4. End of Life (Recommended)
        end_of_life = cls._find_external_ref_spdx(ext_refs, "end-of-life-date")

        if end_of_life:
            present.append("End of Life")
            values["End of Life"] = end_of_life
        else:
            missing.append("End of Life")

        # CRA compliance requires security contact and support period
        required_present = all(f in present for f in cls.REQUIRED_FIELDS)
        is_compliant = required_present

        return (is_compliant, present, missing, values)
