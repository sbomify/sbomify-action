"""SBOM augmentation with organizational metadata using plugin architecture.

This module augments SBOMs with organizational metadata from multiple sources,
addressing NTIA Minimum Elements and CISA 2025 requirements.

Metadata Providers (in priority order):
    1. JSON config file (sbomify.json) - local config takes precedence
    2. sbomify API - backend organizational metadata

NTIA Minimum Elements (July 2021):
    https://sbomify.com/compliance/ntia-minimum-elements/

    Augmentation adds:
    - Supplier Name: CycloneDX metadata.supplier / SPDX packages[].supplier
    - SBOM Author: CycloneDX metadata.authors[] / SPDX creationInfo.creators[]
    - Tool Name/Version: CycloneDX metadata.tools / SPDX creationInfo.creators[]

CISA 2025 Additional Fields:
    https://sbomify.com/compliance/cisa-minimum-elements/

    Augmentation adds:
    - Generation Context: CycloneDX metadata.lifecycles[].phase (1.5+ only)
                         SPDX creationInfo.creatorComment

Field mappings per schema crosswalk:
    https://sbomify.com/compliance/schema-crosswalk/

Version support:
    - CycloneDX: 1.3, 1.4, 1.5, 1.6, 1.7
    - SPDX: 2.2, 2.3
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from cyclonedx.model import AttachedText, BomRef, ExternalReference, ExternalReferenceType, Property, XsUri
from cyclonedx.model.bom import Bom, OrganizationalContact, OrganizationalEntity, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from cyclonedx.model.lifecycle import LifecyclePhase, PredefinedLifecycle
from cyclonedx.model.service import Service
from packageurl import PackageURL
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    ExtractedLicensingInfo,
    Package,
)
from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

# Import augmentation plugin architecture
from ._augmentation import create_default_registry
from ._augmentation.utils import build_vcs_url_with_commit, truncate_sha

# Import lockfile constants from generation utils (single source of truth)
from ._generation.utils import ALL_LOCK_FILES
from .console import get_audit_trail
from .exceptions import SBOMValidationError
from .logging_config import logger
from .serialization import (
    link_root_dependencies,
    sanitize_dependency_graph,
    sanitize_spdx_json_file,
    serialize_cyclonedx_bom,
)
from .spdx3 import is_spdx3
from .validation import validate_sbom_file_auto

# Constants for SPDX license parsing
SPDX_LOGICAL_OPERATORS = [" OR ", " AND ", " WITH "]

# Convert to set for O(1) lookup
LOCKFILE_NAMES = set(ALL_LOCK_FILES)


def _is_lockfile_component(component: Component) -> bool:
    """Check if a CycloneDX component represents a lockfile artifact."""
    if component.type != ComponentType.APPLICATION:
        return False
    if component.purl:
        return False
    if component.name and component.name in LOCKFILE_NAMES:
        return True
    return False


def _propagate_supplier_to_lockfile_components(bom: Bom) -> None:
    """
    Propagate supplier from metadata to lockfile components.

    Lockfile components (e.g., requirements.txt, uv.lock) are metadata artifacts
    that don't have their own supplier. After augmentation sets the metadata
    supplier from the backend, we propagate it to these components for NTIA compliance.
    """
    if not bom.metadata.supplier or not bom.components:
        return

    propagated_count = 0
    for component in bom.components:
        if _is_lockfile_component(component) and not component.supplier:
            component.supplier = bom.metadata.supplier
            propagated_count += 1
            logger.debug(f"Propagated supplier to lockfile component: {component.name}")

    if propagated_count > 0:
        logger.info(f"Propagated supplier to {propagated_count} lockfile component(s)")


def _is_lockfile_package(package: Package) -> bool:
    """Check if an SPDX package represents a lockfile artifact.

    Handles full paths like /github/workspace/uv.lock by extracting the basename.
    """
    if not package.name:
        return False
    # Extract basename to handle full paths (e.g., /github/workspace/uv.lock -> uv.lock)
    basename = os.path.basename(package.name)
    if basename in LOCKFILE_NAMES:
        # Check if it has a PURL - lockfiles typically don't have PURLs
        has_purl = any(ref.reference_type == "purl" for ref in package.external_references)
        if not has_purl:
            return True
    return False


def _propagate_supplier_to_lockfile_packages(document: Document, supplier: Actor) -> None:
    """
    Propagate supplier to lockfile packages in SPDX document.

    Lockfile packages (e.g., requirements.txt, uv.lock) are metadata artifacts
    that don't have their own supplier. After augmentation sets the main package
    supplier from the backend, we propagate it to lockfile packages for NTIA compliance.
    """
    if not supplier or not document.packages:
        return

    propagated_count = 0
    for package in document.packages:
        if _is_lockfile_package(package) and not package.supplier:
            package.supplier = supplier
            propagated_count += 1
            logger.debug(f"Propagated supplier to lockfile package: {package.name}")

    if propagated_count > 0:
        logger.info(f"Propagated supplier to {propagated_count} lockfile package(s)")


def _update_component_purl_version(component: Component, new_version: str) -> bool:
    """
    Update the version in a CycloneDX component's PURL and bom-ref if present.

    When COMPONENT_VERSION is set to override the component version, this function
    ensures the PURL and bom-ref are also updated to maintain consistency between
    the component's version field, PURL, and bom-ref.

    Args:
        component: The CycloneDX Component object with optional purl attribute
        new_version: The new version to set in the PURL and bom-ref

    Returns:
        True if PURL was updated, False if component has no PURL or update failed
    """
    if not component.purl:
        return False

    try:
        old_purl = component.purl

        # Guard against PURLs without version (e.g., pkg:npm/lodash)
        if old_purl.version is None:
            logger.debug(f"Skipping PURL version update - no existing version: {old_purl}")
            return False

        old_version = old_purl.version

        # Create new PURL with updated version, preserving all other fields
        new_purl = PackageURL(
            type=old_purl.type,
            namespace=old_purl.namespace,
            name=old_purl.name,
            version=new_version,
            qualifiers=old_purl.qualifiers,
            subpath=old_purl.subpath,
        )
        component.purl = new_purl
        logger.debug(f"Updated component PURL version: {old_purl} -> {new_purl}")

        # Also update bom-ref if it is a PURL-based bom-ref with a matching version
        if component.bom_ref and component.bom_ref.value:
            old_bom_ref = component.bom_ref.value
            try:
                bom_ref_purl = PackageURL.from_string(old_bom_ref)
            except ValueError:
                bom_ref_purl = None

            if bom_ref_purl and bom_ref_purl.version == old_version:
                new_bom_ref_purl = PackageURL(
                    type=bom_ref_purl.type,
                    namespace=bom_ref_purl.namespace,
                    name=bom_ref_purl.name,
                    version=new_version,
                    qualifiers=bom_ref_purl.qualifiers,
                    subpath=bom_ref_purl.subpath,
                )
                new_bom_ref = str(new_bom_ref_purl)
                component.bom_ref = BomRef(new_bom_ref)
                logger.debug(f"Updated component bom-ref: {old_bom_ref} -> {new_bom_ref}")

        return True
    except Exception as e:
        logger.warning(f"Failed to update component PURL version: {e}")
        return False


def _update_spdx_package_purl_version(package: Package, new_version: str) -> bool:
    """
    Update the version in an SPDX package's PURL external reference if present.

    When COMPONENT_VERSION is set to override the package version, this function
    ensures the PURL in external_references is also updated to maintain consistency
    between the package's version field and its PURL.

    Args:
        package: The SPDX Package object with external_references
        new_version: The new version to set in the PURL

    Returns:
        True if PURL was updated, False if package has no PURL ref or update failed
    """
    for ref in package.external_references:
        if ref.reference_type == "purl":
            try:
                old_purl = PackageURL.from_string(ref.locator)
                new_purl = PackageURL(
                    type=old_purl.type,
                    namespace=old_purl.namespace,
                    name=old_purl.name,
                    version=new_version,
                    qualifiers=old_purl.qualifiers,
                    subpath=old_purl.subpath,
                )
                old_locator = ref.locator
                ref.locator = str(new_purl)
                logger.debug(f"Updated SPDX package PURL version: {old_locator} -> {ref.locator}")
                return True
            except Exception as e:
                logger.warning(f"Failed to update SPDX package PURL version: {e}")
                return False
    return False


def _get_package_version() -> str:
    """Get the package version for tool metadata."""
    try:
        from importlib.metadata import version

        return version("sbomify-action")
    except Exception:
        try:
            from pathlib import Path

            import tomllib

            pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                return pyproject_data.get("project", {}).get("version", "unknown")
        except Exception:
            return "unknown"


SBOMIFY_VERSION = _get_package_version()
SBOMIFY_TOOL_NAME = "sbomify action"
SBOMIFY_VENDOR_NAME = "sbomify"


def fetch_augmentation_metadata(
    api_base_url: Optional[str] = None,
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fetch augmentation metadata from multiple providers.

    Uses the plugin architecture to query metadata from multiple sources
    in priority order:
    1. JSON config file (sbomify.json) - priority 10
    2. sbomify API - priority 50

    Higher priority providers' values take precedence. This allows local
    config to override backend settings.

    Args:
        api_base_url: Base URL for the sbomify API (optional)
        token: Authentication token for sbomify API (optional)
        component_id: Component ID for sbomify API (optional)
        config_path: Path to JSON config file (optional, defaults to sbomify.json)

    Returns:
        Merged augmentation metadata dict from all providers
    """
    registry = create_default_registry()

    # Log registered providers
    providers = registry.list_providers()
    logger.debug(f"Registered augmentation providers: {[p['name'] for p in providers]}")

    # Fetch from all providers (merged by priority)
    metadata = registry.fetch_metadata(
        component_id=component_id,
        api_base_url=api_base_url,
        token=token,
        config_path=config_path,
    )

    if metadata and metadata.has_data():
        logger.info(f"Fetched augmentation metadata from: {metadata.source}")
        return metadata.to_dict()
    else:
        logger.debug("No augmentation metadata available from any provider")
        return {}


def _normalize_urls_to_list(urls: Any) -> List[str]:
    """Normalize URL field to a list format.

    Handles both single URL strings and lists of URLs from augmentation
    metadata sources (API responses and JSON config files).

    Args:
        urls: URL data - can be None, a string, or a list of strings

    Returns:
        List of URL strings (empty list if no URLs provided)
    """
    if not urls:
        return []
    if isinstance(urls, list):
        return urls
    return [urls]


def _is_cdx_version_at_least(spec_version: Optional[str], min_major: int, min_minor: int) -> bool:
    """Check if CycloneDX spec version meets minimum requirement.

    Args:
        spec_version: CycloneDX spec version string (e.g., "1.4", "1.6")
        min_major: Minimum major version required
        min_minor: Minimum minor version required (when major equals min_major)

    Returns:
        True if spec_version >= min_major.min_minor
    """
    if spec_version is None:
        spec_version = "1.4"
    spec_parts = spec_version.split(".")
    major = int(spec_parts[0]) if len(spec_parts) > 0 else 1
    minor = int(spec_parts[1]) if len(spec_parts) > 1 else 4
    return (major > min_major) or (major == min_major and minor >= min_minor)


def _process_license_data(license_data: Any) -> Optional[Any]:
    """
    Process license data from backend into CycloneDX license objects.

    Supports:
    - String: SPDX expression (e.g., "MIT OR GPL-3.0", "Apache-2.0 WITH Commons-Clause")
    - Dict: Custom license with name, url, text

    Args:
        license_data: License data from backend (string or dict)

    Returns:
        License object for CycloneDX or None if invalid
    """
    if isinstance(license_data, str):
        # Handle SPDX license expressions
        if any(op in license_data for op in SPDX_LOGICAL_OPERATORS):
            # Complex SPDX expression
            try:
                return LicenseExpression(value=license_data)
            except Exception:
                # If expression parsing fails, treat as simple name
                return DisjunctiveLicense(name=license_data)
        else:
            # Simple license name
            return DisjunctiveLicense(name=license_data)

    elif isinstance(license_data, dict):
        # Custom license object with name, url, text
        license_name = license_data.get("name", "")
        license_url = license_data.get("url")
        license_text = license_data.get("text")

        if not license_name:
            return None

        # Create DisjunctiveLicense with additional details
        license_obj = DisjunctiveLicense(name=license_name)

        if license_url:
            try:
                license_obj.url = XsUri(license_url)
            except Exception:
                pass  # Skip invalid URLs

        if license_text:
            try:
                license_obj.text = AttachedText(content=license_text)
            except Exception:
                pass  # Skip if text attachment fails

        return license_obj

    return None


def _add_sbomify_tool_to_cyclonedx(bom: Bom, spec_version: Optional[str] = None) -> None:
    """
    Add sbomify as a tool in the CycloneDX SBOM metadata.

    Args:
        bom: The Bom object to update with tool metadata
        spec_version: CycloneDX spec version (e.g., "1.4", "1.5", "1.6", "1.7")
                     If None, defaults to "1.4" (legacy format)

    Note:
        Version-specific behavior:
        - CycloneDX 1.4: Uses legacy Tool format (tools array) with string vendor
        - CycloneDX 1.5+: Uses modern format (components/services) - sbomify added as Service

        According to CycloneDX spec:
        - Tool.vendor should be STRING (not OrganizationalEntity) in legacy format
        - Component.group should be STRING (represents vendor) in modern format
        - Service-based tools (like sbomify API) should go in tools.services for 1.5+
        - NEVER use OrganizationalEntity for tools in any version

        See: https://github.com/CycloneDX/cyclonedx-python-lib/issues/917
        See: https://cyclonedx.org/docs/1.7/json/#metadata_tools
    """
    if _is_cdx_version_at_least(spec_version, 1, 5):
        # Modern format (1.5+): Use services for API/service-based tools
        # Keep existing components and services, add sbomify as a service
        logger.debug(f"Using modern tools format for CycloneDX {spec_version}")

        # Create sbomify as a Service (not a legacy Tool)
        # Services are appropriate for API/service-based tools like sbomify
        sbomify_service = Service(
            name=SBOMIFY_TOOL_NAME,
            version=SBOMIFY_VERSION,
        )

        # Add group field (equivalent to vendor in legacy format)
        sbomify_service.group = SBOMIFY_VENDOR_NAME

        # Add external references for the service
        try:
            # Website - main product page
            sbomify_service.external_references.add(
                ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://sbomify.com"))
            )
            # VCS - source code repository
            sbomify_service.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.VCS, url=XsUri("https://github.com/sbomify/sbomify-action")
                )
            )
            # Issue tracker - where to report bugs
            sbomify_service.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.ISSUE_TRACKER,
                    url=XsUri("https://github.com/sbomify/sbomify-action/issues"),
                )
            )
        except Exception as e:
            logger.debug(f"Failed to add external references to sbomify service: {e}")

        # Add to tools.services (do NOT clear existing services or components)
        bom.metadata.tools.services.add(sbomify_service)

    else:
        # Legacy format (1.4): Convert all to Tool objects
        logger.debug(f"Using legacy tools format for CycloneDX {spec_version}")

        # Convert components to Tools and add to tools collection
        # Tool.from_component() uses component.group (string) as vendor (string)
        for component in list(bom.metadata.tools.components):
            tool = Tool.from_component(component)
            bom.metadata.tools.tools.add(tool)

        # Clear components since we've converted them all to tools
        bom.metadata.tools.components.clear()

        # Convert services to Tools and add to tools collection
        for service in list(bom.metadata.tools.services):
            tool = Tool.from_service(service)
            bom.metadata.tools.tools.add(tool)

        # Clear services since we've converted them all to tools
        bom.metadata.tools.services.clear()

        # Create sbomify tool entry with STRING vendor (per spec)
        # This matches the format used by other tools (e.g., Trivy uses group="aquasecurity")
        sbomify_tool = Tool(vendor=SBOMIFY_VENDOR_NAME, name=SBOMIFY_TOOL_NAME, version=SBOMIFY_VERSION)

        # Add external references for the tool
        try:
            # Website - main product page
            sbomify_tool.external_references.add(
                ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://sbomify.com"))
            )
            # VCS - source code repository
            sbomify_tool.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.VCS, url=XsUri("https://github.com/sbomify/sbomify-action")
                )
            )
            # Issue tracker - where to report bugs
            sbomify_tool.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.ISSUE_TRACKER,
                    url=XsUri("https://github.com/sbomify/sbomify-action/issues"),
                )
            )
        except Exception as e:
            logger.debug(f"Failed to add external references to sbomify tool: {e}")

        # Add the tool to the metadata
        bom.metadata.tools.tools.add(sbomify_tool)

    # Record to audit trail (after both branches)
    audit_trail = get_audit_trail()
    audit_trail.record_tool_added(SBOMIFY_TOOL_NAME, SBOMIFY_VERSION)


def augment_cyclonedx_sbom(
    bom: Bom,
    augmentation_data: Dict[str, Any],
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    spec_version: Optional[str] = None,
) -> Bom:
    """
    Augment CycloneDX SBOM with backend metadata using native library.

    Note: PURL override is handled separately in main.py via _apply_sbom_purl_override()
    to ensure it works regardless of augmentation settings.

    Args:
        bom: The Bom object to augment
        augmentation_data: Metadata from backend
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override
        spec_version: CycloneDX spec version (e.g., "1.4", "1.5", "1.6", "1.7")
                     Used to determine tool format (legacy vs modern)

    Returns:
        Augmented Bom object
    """
    # Add sbomify as a processing tool (version-aware)
    _add_sbomify_tool_to_cyclonedx(bom, spec_version)

    # Add supplier information
    audit_trail = get_audit_trail()

    if "supplier" in augmentation_data:
        supplier_data = augmentation_data["supplier"]
        supplier_name = supplier_data.get("name", "Unknown")

        # Create backend supplier entity
        backend_supplier = OrganizationalEntity(
            name=supplier_data.get("name"),
            urls=supplier_data.get("url", [])
            if isinstance(supplier_data.get("url"), list)
            else ([supplier_data.get("url")] if supplier_data.get("url") else []),
            contacts=[],
        )

        # Add contacts if present
        if "contact" in supplier_data:
            for contact_data in supplier_data["contact"]:
                contact = OrganizationalContact(
                    name=contact_data.get("name"), email=contact_data.get("email"), phone=contact_data.get("phone")
                )
                backend_supplier.contacts.add(contact)

        # Merge with existing supplier or replace
        if bom.metadata.supplier and not override_sbom_metadata:
            # Preserve existing supplier, merge with backend data
            existing_supplier = bom.metadata.supplier

            # Keep existing name if present, otherwise use backend
            merged_name = existing_supplier.name if existing_supplier.name else backend_supplier.name

            # Merge URLs
            merged_urls = set()
            if existing_supplier.urls:
                for url in existing_supplier.urls:
                    merged_urls.add(str(url))
            if backend_supplier.urls:
                for url in backend_supplier.urls:
                    merged_urls.add(str(url))

            # Merge contacts (avoid duplicates by email)
            merged_contacts = set()
            existing_emails = set()

            if existing_supplier.contacts:
                for contact in existing_supplier.contacts:
                    merged_contacts.add(contact)
                    if contact.email:
                        existing_emails.add(contact.email)

            if backend_supplier.contacts:
                for contact in backend_supplier.contacts:
                    if not contact.email or contact.email not in existing_emails:
                        merged_contacts.add(contact)

            # Create merged supplier
            bom.metadata.supplier = OrganizationalEntity(
                name=merged_name,
                urls=list(merged_urls),
                contacts=list(merged_contacts),
            )
        else:
            # Use backend supplier
            bom.metadata.supplier = backend_supplier

        # Record to audit trail
        audit_trail.record_supplier_added(supplier_name)

        # Also propagate supplier to the root component (metadata.component) if it exists
        # This is needed for NTIA compliance - the root component needs its own supplier field
        if bom.metadata.component and not bom.metadata.component.supplier:
            bom.metadata.component.supplier = bom.metadata.supplier
            logger.debug("Propagated supplier to root component (metadata.component)")

        # Propagate supplier to lockfile components that don't have one
        # Lockfile components (e.g., requirements.txt, uv.lock) are metadata artifacts
        # that inherit supplier from the root/metadata supplier
        if bom.metadata.supplier and bom.components:
            _propagate_supplier_to_lockfile_components(bom)

    # Add manufacturer information (version-aware field naming)
    # CycloneDX 1.3-1.5: metadata.manufacture (no 'r')
    # CycloneDX 1.6+: metadata.component.manufacturer (with 'r')
    if "manufacturer" in augmentation_data:
        manufacturer_data = augmentation_data["manufacturer"]
        manufacturer_name = manufacturer_data.get("name")

        # Skip if no manufacturer name provided
        if manufacturer_name:
            # Create backend manufacturer entity
            backend_manufacturer = OrganizationalEntity(
                name=manufacturer_name,
                urls=_normalize_urls_to_list(manufacturer_data.get("url")),
                contacts=[],
            )

            # Add contacts if present
            if "contacts" in manufacturer_data:
                for contact_data in manufacturer_data["contacts"]:
                    contact = OrganizationalContact(
                        name=contact_data.get("name"), email=contact_data.get("email"), phone=contact_data.get("phone")
                    )
                    backend_manufacturer.contacts.add(contact)

            # Determine version for field assignment
            is_v16_or_later = _is_cdx_version_at_least(spec_version, 1, 6)
            manufacturer_added = False

            if is_v16_or_later:
                # CycloneDX 1.6+: Use metadata.component.manufacturer
                if bom.metadata.component:
                    if not bom.metadata.component.manufacturer or override_sbom_metadata:
                        bom.metadata.component.manufacturer = backend_manufacturer
                        manufacturer_added = True
            else:
                # CycloneDX 1.3-1.5: Use metadata.manufacture (no 'r')
                if not bom.metadata.manufacture or override_sbom_metadata:
                    bom.metadata.manufacture = backend_manufacturer
                    manufacturer_added = True

            if manufacturer_added:
                audit_trail.record_manufacturer_added(manufacturer_name)

    # Add authors if present
    if "authors" in augmentation_data:
        for author_data in augmentation_data["authors"]:
            author = OrganizationalContact(
                name=author_data.get("name"), email=author_data.get("email"), phone=author_data.get("phone")
            )
            bom.metadata.authors.add(author)
            audit_trail.record_author_added(author_data.get("name", "Unknown"), author_data.get("email"))

    # Add licenses if present
    # Note: CycloneDX spec requires that if LicenseExpression is used, there can be ONLY ONE license
    # See: https://github.com/CycloneDX/specification/pull/205
    if "licenses" in augmentation_data:
        license_count = len(augmentation_data["licenses"])

        # Check if any license contains operators (is an expression)
        has_expressions = any(
            isinstance(lic, str) and any(op in lic for op in SPDX_LOGICAL_OPERATORS)
            for lic in augmentation_data["licenses"]
        )

        if license_count == 0:
            # No licenses to add
            pass
        elif has_expressions or license_count > 1:
            # Combine all licenses into a single LicenseExpression
            # This is required when: (a) any license has operators, or (b) we have multiple licenses
            license_parts = []
            for license_data in augmentation_data["licenses"]:
                if isinstance(license_data, str):
                    license_parts.append(license_data)
                elif isinstance(license_data, dict):
                    license_name = license_data.get("name", "")
                    if license_name:
                        license_parts.append(license_name)

            if license_parts:
                # Combine all licenses with OR (common pattern for dual/multi-licensing)
                combined_expression = " OR ".join(license_parts)
                bom.metadata.licenses.add(LicenseExpression(value=combined_expression))
                audit_trail.record_license_added(combined_expression)
        else:
            # Single license, no operators - safe to use DisjunctiveLicense
            license_data = augmentation_data["licenses"][0]
            license_obj = _process_license_data(license_data)
            if license_obj:
                bom.metadata.licenses.add(license_obj)
                license_str = license_data if isinstance(license_data, str) else license_data.get("name", "Unknown")
                audit_trail.record_license_added(license_str)

    # Apply component name override if specified
    if component_name:
        if hasattr(bom.metadata, "component") and bom.metadata.component:
            existing_name = bom.metadata.component.name or "unknown"
            if existing_name != component_name:
                bom.metadata.component.name = component_name
                logger.info(f"Overriding component name: '{existing_name}' -> '{component_name}'")
        else:
            # Create component if it doesn't exist
            bom.metadata.component = Component(
                name=component_name, type=ComponentType.APPLICATION, version=component_version or "unknown"
            )
            logger.info(f"Overriding component name: 'none (creating new component)' -> '{component_name}'")

    # Apply component version override if specified
    if component_version:
        if hasattr(bom.metadata, "component") and bom.metadata.component:
            bom.metadata.component.version = component_version
            # Also update the PURL version to maintain consistency
            _update_component_purl_version(bom.metadata.component, component_version)
        else:
            # Create component if it doesn't exist
            bom.metadata.component = Component(
                name=component_name or "unknown", type=ComponentType.APPLICATION, version=component_version
            )
        logger.info(f"Set component version from configuration: {component_version}")

    # Add lifecycle phase if present (CISA 2025 Generation Context requirement)
    # See: https://sbomify.com/compliance/cisa-minimum-elements/
    # Crosswalk: https://sbomify.com/compliance/schema-crosswalk/
    # Only supported in CycloneDX 1.5+ (metadata.lifecycles field not available in 1.3/1.4)
    if "lifecycle_phase" in augmentation_data and augmentation_data["lifecycle_phase"]:
        # Only supported in CycloneDX 1.5+
        if _is_cdx_version_at_least(spec_version, 1, 5):
            phase_value = augmentation_data["lifecycle_phase"].lower().replace("_", "-")
            # Map to CycloneDX LifecyclePhase enum
            phase_mapping = {
                "design": LifecyclePhase.DESIGN,
                "pre-build": LifecyclePhase.PRE_BUILD,
                "build": LifecyclePhase.BUILD,
                "post-build": LifecyclePhase.POST_BUILD,
                "operations": LifecyclePhase.OPERATIONS,
                "discovery": LifecyclePhase.DISCOVERY,
                "decommission": LifecyclePhase.DECOMMISSION,
            }
            if phase_value in phase_mapping:
                lifecycle = PredefinedLifecycle(phase=phase_mapping[phase_value])
                bom.metadata.lifecycles.add(lifecycle)
                audit_trail.record_lifecycle_added(phase_value)

    # Add VCS information if present (from CI providers or sbomify.json config)
    # This adds repository URL and commit info to the root component
    _add_vcs_info_to_cyclonedx(bom, augmentation_data)

    # Add security contact (uses native CycloneDX structures)
    # This satisfies CRA vulnerability contact requirements
    if "security_contact" in augmentation_data and augmentation_data["security_contact"]:
        contact_url = augmentation_data["security_contact"]

        # Primary: Add as security-contact external reference (CDX 1.5+)
        # This is the dedicated, semantic field for security contacts
        if _is_cdx_version_at_least(spec_version, 1, 5):
            if bom.metadata.component:
                # Check if security-contact already exists
                existing = [
                    ref
                    for ref in bom.metadata.component.external_references
                    if ref.type == ExternalReferenceType.SECURITY_CONTACT
                ]
                if not existing:
                    try:
                        security_ref = ExternalReference(
                            type=ExternalReferenceType.SECURITY_CONTACT,
                            url=XsUri(contact_url),
                        )
                        bom.metadata.component.external_references.add(security_ref)
                        audit_trail.record_augmentation("security_contact", contact_url, source="config")
                        logger.info(f"Added security contact to CycloneDX: {contact_url}")
                    except ValueError:
                        logger.warning(
                            f"Invalid security_contact URL '{contact_url}'. "
                            "Expected a valid URI (https://, mailto:, or tel: scheme)."
                        )

        # Fallback for CDX 1.3/1.4: Add to supplier contact if it's an email,
        # or add as support external reference if it's a URL
        else:
            if "@" in contact_url and not contact_url.startswith("mailto:"):
                # It's an email address - add to supplier contacts if supplier exists
                if bom.metadata.supplier:
                    contact = OrganizationalContact(email=contact_url)
                    bom.metadata.supplier.contacts.add(contact)
                    audit_trail.record_augmentation("security_contact", contact_url, source="config")
                    logger.info(f"Added security contact email to supplier: {contact_url}")
            else:
                # It's a URL - add as support external reference
                if bom.metadata.component:
                    try:
                        support_ref = ExternalReference(
                            type=ExternalReferenceType.SUPPORT,
                            url=XsUri(contact_url),
                        )
                        bom.metadata.component.external_references.add(support_ref)
                        audit_trail.record_augmentation("security_contact", contact_url, source="config")
                        logger.info(f"Added security contact as support URL: {contact_url}")
                    except ValueError:
                        logger.warning(
                            f"Invalid security_contact URL '{contact_url}'. "
                            "Expected a valid URI (https://, mailto:, or tel: scheme)."
                        )

    # Add support period end date
    # This satisfies CRA support period requirements
    # Add support period end date using official CycloneDX property taxonomy
    # See: https://cyclonedx.github.io/cyclonedx-property-taxonomy/cdx/lifecycle.html
    if "support_period_end" in augmentation_data and augmentation_data["support_period_end"]:
        end_date = augmentation_data["support_period_end"]
        support_prop = Property(name="cdx:lifecycle:milestone:endOfSupport", value=end_date)
        bom.metadata.properties.add(support_prop)
        logger.info(f"Added cdx:lifecycle:milestone:endOfSupport property: {end_date}")
        audit_trail.record_augmentation("support_period_end", end_date, source="config")

    # Add release date using official CycloneDX property taxonomy
    if "release_date" in augmentation_data and augmentation_data["release_date"]:
        release_date = augmentation_data["release_date"]
        release_prop = Property(name="cdx:lifecycle:milestone:generalAvailability", value=release_date)
        bom.metadata.properties.add(release_prop)
        logger.info(f"Added cdx:lifecycle:milestone:generalAvailability property: {release_date}")
        audit_trail.record_augmentation("release_date", release_date, source="config")

    # Add end of life date using official CycloneDX property taxonomy
    if "end_of_life" in augmentation_data and augmentation_data["end_of_life"]:
        eol_date = augmentation_data["end_of_life"]
        eol_prop = Property(name="cdx:lifecycle:milestone:endOfLife", value=eol_date)
        bom.metadata.properties.add(eol_prop)
        logger.info(f"Added cdx:lifecycle:milestone:endOfLife property: {eol_date}")
        audit_trail.record_augmentation("end_of_life", eol_date, source="config")

    return bom


def _add_vcs_info_to_cyclonedx(bom: Bom, augmentation_data: Dict[str, Any]) -> None:
    """
    Add VCS information to CycloneDX SBOM.

    Adds:
    - VCS external reference with repository URL to root component
    - Commit SHA encoded in the URL (git+URL@sha format)

    Args:
        bom: The Bom object to augment
        augmentation_data: Metadata containing VCS fields
    """
    vcs_url = augmentation_data.get("vcs_url")
    vcs_commit_sha = augmentation_data.get("vcs_commit_sha")
    vcs_ref = augmentation_data.get("vcs_ref")

    if not vcs_url:
        return

    # Ensure we have a root component to attach VCS info to
    if not bom.metadata.component:
        return

    # Build VCS URL with commit pinning (git+https://...@sha format)
    vcs_url_with_commit = build_vcs_url_with_commit(vcs_url, vcs_commit_sha)

    # Check if VCS external reference already exists
    existing_vcs_refs = [
        ref for ref in bom.metadata.component.external_references if ref.type == ExternalReferenceType.VCS
    ]

    if existing_vcs_refs:
        return

    # Add VCS external reference to root component
    try:
        vcs_ref_obj = ExternalReference(
            type=ExternalReferenceType.VCS,
            url=XsUri(vcs_url_with_commit),
        )

        # Add comment with branch/ref info if available
        if vcs_ref:
            vcs_ref_obj.comment = f"Branch/ref: {vcs_ref}"

        bom.metadata.component.external_references.add(vcs_ref_obj)

        # Record to audit trail
        audit_trail = get_audit_trail()
        audit_trail.record_vcs_info_added(vcs_url, vcs_commit_sha, source="ci-provider")

    except Exception as e:
        logger.warning(f"Failed to add VCS external reference: {e}")


def _sanitize_license_ref_id(name: str) -> str:
    """
    Sanitize a license name to create a valid SPDX LicenseRef identifier.

    SPDX spec requires LicenseRef-[idstring] where idstring contains only:
    - Letters (a-z, A-Z)
    - Numbers (0-9)
    - Period (.)
    - Hyphen (-)

    Args:
        name: Original license name

    Returns:
        Sanitized identifier suitable for LicenseRef

    Raises:
        ValueError: If name cannot be sanitized to valid identifier
    """
    import re

    if not name or not name.strip():
        raise ValueError("License name cannot be empty")

    # Replace spaces and common separators with hyphens
    sanitized = name.strip()
    sanitized = re.sub(r"[\s_/\\]+", "-", sanitized)

    # Remove all characters that aren't alphanumeric, period, or hyphen
    sanitized = re.sub(r"[^a-zA-Z0-9.-]", "", sanitized)

    # Replace multiple consecutive hyphens/periods with single hyphen
    sanitized = re.sub(r"[-\.]{2,}", "-", sanitized)

    # Remove leading/trailing hyphens or periods
    sanitized = sanitized.strip("-.")

    # Ensure we have something left
    if not sanitized:
        raise ValueError(f"License name '{name}' cannot be sanitized to valid SPDX identifier")

    # Limit length to something reasonable (SPDX doesn't specify, but let's be practical)
    if len(sanitized) > 64:
        # Keep first part and add hash to ensure uniqueness
        import hashlib

        name_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        sanitized = f"{sanitized[:50]}-{name_hash}"

    return sanitized


def _convert_backend_licenses_to_spdx_expression(licenses: list) -> Tuple[str, List[ExtractedLicensingInfo]]:
    """
    Convert backend license data to SPDX license expression and ExtractedLicensingInfo objects.

    When multiple licenses are provided, they are combined with OR to indicate
    alternatives (dual/multi-licensing), not requirements.

    Args:
        licenses: List of license data from backend (strings or dicts)

    Returns:
        Tuple of (SPDX license expression string, list of ExtractedLicensingInfo objects for custom licenses)
    """
    spdx_parts = []
    extracted_licensing_infos = []
    seen_refs = set()  # Track custom license refs to avoid duplicates

    for license_item in licenses:
        if isinstance(license_item, str):
            # Already SPDX expression or simple license name
            spdx_parts.append(license_item)
        elif isinstance(license_item, dict) and license_item.get("name"):
            # Custom license - create LicenseRef with proper sanitization
            original_name = license_item["name"]
            try:
                sanitized_id = _sanitize_license_ref_id(original_name)
                license_ref = f"LicenseRef-{sanitized_id}"

                # Handle collisions by appending counter
                if license_ref in seen_refs:
                    counter = 2
                    while f"{license_ref}-{counter}" in seen_refs:
                        counter += 1
                    license_ref = f"{license_ref}-{counter}"

                seen_refs.add(license_ref)
                spdx_parts.append(license_ref)
                logger.debug(f"Created SPDX license reference: {license_ref} for '{original_name}'")

                # Create ExtractedLicensingInfo object for this custom license
                extracted_info = ExtractedLicensingInfo(
                    license_id=license_ref,
                    extracted_text=license_item.get("text", "License text not provided"),
                    license_name=original_name,
                    cross_references=[license_item["url"]] if license_item.get("url") else [],
                    comment=license_item.get("comment"),
                )
                extracted_licensing_infos.append(extracted_info)
                logger.debug(f"Created ExtractedLicensingInfo for {license_ref}")

            except ValueError as e:
                logger.warning(f"Skipping invalid license name '{original_name}': {e}")
                continue

    if not spdx_parts:
        return "NOASSERTION", []

    # Join with OR (common pattern for multi-licensing - user can choose any)
    expression = " OR ".join(spdx_parts) if len(spdx_parts) > 1 else spdx_parts[0]
    return expression, extracted_licensing_infos


def augment_spdx_sbom(
    document: Document,
    augmentation_data: Dict[str, Any],
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
) -> Document:
    """
    Augment SPDX SBOM with backend metadata using native library.

    Note: PURL override is handled separately in main.py via _apply_sbom_purl_override()
    to ensure it works regardless of augmentation settings.

    Args:
        document: The SPDX Document object to augment
        augmentation_data: Metadata from backend
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override

    Returns:
        Augmented Document object
    """
    # Add sbomify tool to creators
    sbomify_tool_creator = Actor(ActorType.TOOL, f"{SBOMIFY_TOOL_NAME}-{SBOMIFY_VERSION}")
    if sbomify_tool_creator not in document.creation_info.creators:
        document.creation_info.creators.append(sbomify_tool_creator)
        logger.info("Added sbomify as processing tool to SPDX creators")

    # Apply supplier information
    if "supplier" in augmentation_data:
        supplier_data = augmentation_data["supplier"]
        supplier_name = supplier_data.get("name")
        logger.info(f"Adding supplier information: {supplier_name or 'Unknown'}")

        # Add to document creators
        if supplier_name:
            supplier_creator = Actor(ActorType.ORGANIZATION, supplier_name)
            if supplier_creator not in document.creation_info.creators:
                document.creation_info.creators.append(supplier_creator)

        # Apply supplier to main package only (first package represents the described component)
        # Dependencies in the SBOM have their own suppliers, not the backend's supplier
        if document.packages:
            main_package = document.packages[0]

            if supplier_name and (not main_package.supplier or override_sbom_metadata):
                main_package.supplier = Actor(ActorType.ORGANIZATION, supplier_name)

            # Add homepage from supplier URLs
            if supplier_data.get("url") and not main_package.homepage:
                urls = supplier_data["url"] if isinstance(supplier_data["url"], list) else [supplier_data["url"]]
                if urls and urls[0]:
                    main_package.homepage = urls[0]

            # Add external references for supplier info
            if supplier_data.get("url"):
                urls = supplier_data["url"] if isinstance(supplier_data["url"], list) else [supplier_data["url"]]
                for url in urls:
                    if url:
                        # Check if this URL already exists
                        existing_refs = [ref.locator for ref in main_package.external_references]
                        if url not in existing_refs:
                            ext_ref = ExternalPackageRef(
                                category=ExternalPackageRefCategory.OTHER,
                                reference_type="website",
                                locator=url,
                                comment="Supplier website",
                            )
                            main_package.external_references.append(ext_ref)

            # Propagate supplier to lockfile packages (parity with CycloneDX)
            # Lockfile packages (e.g., requirements.txt, uv.lock) are metadata artifacts
            # that inherit supplier from the root/main package
            if main_package.supplier:
                _propagate_supplier_to_lockfile_packages(document, main_package.supplier)

    # Apply manufacturer information
    # SPDX has no dedicated manufacturer field - use originator which means
    # "The person or organization that originally created the package"
    # Track if manufacturer sets originator so authors section can respect precedence
    manufacturer_set_originator = False
    if "manufacturer" in augmentation_data:
        manufacturer_data = augmentation_data["manufacturer"]
        manufacturer_name = manufacturer_data.get("name")
        logger.info(f"Adding manufacturer information: {manufacturer_name or 'Unknown'}")

        # Add manufacturer to document creators as organization
        if manufacturer_name:
            manufacturer_creator = Actor(ActorType.ORGANIZATION, manufacturer_name)
            if manufacturer_creator not in document.creation_info.creators:
                document.creation_info.creators.append(manufacturer_creator)

        # Apply manufacturer as originator on main package (manufacturer takes precedence)
        if document.packages and manufacturer_name:
            main_package = document.packages[0]
            if not main_package.originator or override_sbom_metadata:
                main_package.originator = Actor(ActorType.ORGANIZATION, manufacturer_name)
                manufacturer_set_originator = True
                logger.info(f"Set manufacturer as originator: {manufacturer_name}")
            else:
                logger.debug(f"Preserving existing originator: {main_package.originator}")

            # Add manufacturer URLs as external references
            for url in _normalize_urls_to_list(manufacturer_data.get("url")):
                if url:
                    existing_refs = [ref.locator for ref in main_package.external_references]
                    if url not in existing_refs:
                        ext_ref = ExternalPackageRef(
                            category=ExternalPackageRefCategory.OTHER,
                            reference_type="website",
                            locator=url,
                            comment="Manufacturer website",
                        )
                        main_package.external_references.append(ext_ref)

    # Apply authors information
    if "authors" in augmentation_data and augmentation_data["authors"]:
        authors_data = augmentation_data["authors"]
        logger.info(f"Adding {len(authors_data)} author(s) from sbomify")

        # Add authors to document creators
        for author_data in authors_data:
            author_name = author_data.get("name")
            author_email = author_data.get("email", "")
            if author_name:
                person_name = author_name
                if author_email:
                    person_name += f" ({author_email})"
                person_creator = Actor(ActorType.PERSON, person_name)
                if person_creator not in document.creation_info.creators:
                    document.creation_info.creators.append(person_creator)

        # Add first author as originator for main package only
        # Dependencies have their own originators, not the backend's authors
        # Note: manufacturer takes precedence over authors for originator
        if authors_data and document.packages:
            first_author = authors_data[0]
            author_name = first_author.get("name")
            author_email = first_author.get("email", "")

            if author_name:
                main_package = document.packages[0]
                # Skip if manufacturer already set originator (manufacturer takes precedence)
                if manufacturer_set_originator:
                    logger.debug("Skipping author as originator: manufacturer takes precedence")
                elif not main_package.originator or override_sbom_metadata:
                    originator_name = author_name
                    if author_email:
                        originator_name += f" ({author_email})"
                    main_package.originator = Actor(ActorType.PERSON, originator_name)

    # Apply license information
    if "licenses" in augmentation_data and augmentation_data["licenses"]:
        licenses_data = augmentation_data["licenses"]
        logger.info(f"Adding {len(licenses_data)} license(s) to SPDX main package")

        # Convert backend licenses to SPDX format and get ExtractedLicensingInfo objects
        spdx_license_expression, extracted_licensing_infos = _convert_backend_licenses_to_spdx_expression(licenses_data)

        # Add extracted licensing info for custom licenses to document
        if extracted_licensing_infos:
            # Add to document's extracted_licensing_info list
            document.extracted_licensing_info.extend(extracted_licensing_infos)
            logger.info(
                f"Added {len(extracted_licensing_infos)} custom license(s) to document extracted_licensing_info"
            )

        # Apply to main package only (dependencies have their own licenses)
        if document.packages:
            main_package = document.packages[0]

            # Set license_declared with the SPDX expression
            # Use license_declared as this represents what the package declares in its metadata
            if not main_package.license_declared or override_sbom_metadata:
                # Parse the SPDX expression string into a proper Expression object
                license_parser = LicenseExpressionParser()
                try:
                    parsed_expression = license_parser.parse_license_expression(spdx_license_expression)
                    main_package.license_declared = parsed_expression
                    logger.info(f"Set package license_declared: {spdx_license_expression}")
                except Exception as e:
                    # If parsing fails, add to comment instead
                    logger.warning(f"Failed to parse license expression '{spdx_license_expression}': {e}")
                    if main_package.license_comment:
                        main_package.license_comment += f" | Backend licenses: {spdx_license_expression}"
                    else:
                        main_package.license_comment = f"Backend licenses: {spdx_license_expression}"
            else:
                # If there's already a declared license and we're not overriding, add to comment
                logger.info("Package already has license_declared, adding backend licenses to comment")
                if main_package.license_comment:
                    main_package.license_comment += f" | Backend licenses: {spdx_license_expression}"
                else:
                    main_package.license_comment = f"Backend licenses: {spdx_license_expression}"

    # Apply component name override
    if component_name:
        # SPDX document name is in creation_info
        existing_name = document.creation_info.name
        document.creation_info.name = component_name
        logger.info(f"Overriding SPDX document name: '{existing_name}' -> '{component_name}'")

        # Also update main package if exists
        if document.packages:
            main_package = document.packages[0]  # Typically the first package is the main one
            main_package.name = component_name

    # Apply component version override
    if component_version and document.packages:
        main_package = document.packages[0]
        main_package.version = component_version
        # Also update the PURL version in external references to maintain consistency
        _update_spdx_package_purl_version(main_package, component_version)
        logger.info(f"Set package version from configuration: {component_version}")

    # Add lifecycle phase if present (CISA 2025 Generation Context requirement)
    # See: https://sbomify.com/compliance/cisa-minimum-elements/
    # Crosswalk: https://sbomify.com/compliance/schema-crosswalk/
    # For SPDX, we add this to creator_comment since there's no dedicated field
    if "lifecycle_phase" in augmentation_data and augmentation_data["lifecycle_phase"]:
        phase_value = augmentation_data["lifecycle_phase"]
        lifecycle_comment = f"Lifecycle phase: {phase_value}"
        if document.creation_info.creator_comment:
            document.creation_info.creator_comment += f" | {lifecycle_comment}"
        else:
            document.creation_info.creator_comment = lifecycle_comment
        logger.info(f"Added lifecycle phase to SPDX creator comment: {phase_value}")

    # Add VCS information if present (from CI providers or sbomify.json config)
    _add_vcs_info_to_spdx(document, augmentation_data)

    # Ensure main package has PURL for NTIA compliance
    # This uses VCS info if available to construct a PURL
    _ensure_spdx_main_package_purl(document, augmentation_data)

    # Add security contact (uses native SPDX structures)
    # This satisfies CRA vulnerability contact requirements
    if "security_contact" in augmentation_data and augmentation_data["security_contact"]:
        contact_url = augmentation_data["security_contact"]

        if document.packages:
            main_package = document.packages[0]

            # Check if security contact already exists
            existing = [ref for ref in main_package.external_references if ref.reference_type == "security-contact"]
            if not existing:
                # Add as external reference with SECURITY category
                ext_ref = ExternalPackageRef(
                    category=ExternalPackageRefCategory.SECURITY,
                    reference_type="security-contact",
                    locator=contact_url,
                    comment="Security vulnerability reporting contact",
                )
                main_package.external_references.append(ext_ref)
                logger.info(f"Added security contact to SPDX: {contact_url}")

                # Record to audit trail
                spdx_audit_trail = get_audit_trail()
                spdx_audit_trail.record_augmentation("security_contact", contact_url, source="config")

    # Add support period end date
    # This satisfies CRA support period requirements
    if "support_period_end" in augmentation_data and augmentation_data["support_period_end"]:
        end_date = augmentation_data["support_period_end"]

        if document.packages:
            main_package = document.packages[0]

            # Primary: Use validUntilDate (native SPDX 2.3 field)
            # Note: SPDX requires datetime object, not string
            if hasattr(main_package, "valid_until_date") and not main_package.valid_until_date:
                try:
                    from datetime import datetime

                    # Parse ISO-8601 date string to datetime
                    valid_until = datetime.fromisoformat(end_date)
                    main_package.valid_until_date = valid_until
                    logger.info(f"Set SPDX validUntilDate: {end_date}")
                except ValueError:
                    logger.warning(
                        f"Could not parse support_period_end date '{end_date}'. "
                        "Expected format: YYYY-MM-DD (for example, 2025-12-31)."
                    )

            # Also add as external reference for broader compatibility
            existing = [ref for ref in main_package.external_references if ref.reference_type == "support-end-date"]
            if not existing:
                ext_ref = ExternalPackageRef(
                    category=ExternalPackageRefCategory.OTHER,
                    reference_type="support-end-date",
                    locator=end_date,
                    comment="Date when security support ends",
                )
                main_package.external_references.append(ext_ref)
                logger.info(f"Added support-end-date to SPDX: {end_date}")

                # Record to audit trail
                spdx_audit_trail = get_audit_trail()
                spdx_audit_trail.record_augmentation("support_period_end", end_date, source="config")

    # Add release date
    # Records when the component was released
    if "release_date" in augmentation_data and augmentation_data["release_date"]:
        release_date = augmentation_data["release_date"]

        if document.packages:
            main_package = document.packages[0]

            # Check if release-date already exists
            existing = [ref for ref in main_package.external_references if ref.reference_type == "release-date"]
            if not existing:
                ext_ref = ExternalPackageRef(
                    category=ExternalPackageRefCategory.OTHER,
                    reference_type="release-date",
                    locator=release_date,
                    comment="Release date of the component",
                )
                main_package.external_references.append(ext_ref)
                logger.info(f"Added release-date to SPDX: {release_date}")

                # Record to audit trail
                spdx_audit_trail = get_audit_trail()
                spdx_audit_trail.record_augmentation("release_date", release_date, source="config")

    # Add end of life date
    # Records when all support ends (beyond security-only support)
    if "end_of_life" in augmentation_data and augmentation_data["end_of_life"]:
        eol_date = augmentation_data["end_of_life"]

        if document.packages:
            main_package = document.packages[0]

            # Check if end-of-life-date already exists
            existing = [ref for ref in main_package.external_references if ref.reference_type == "end-of-life-date"]
            if not existing:
                ext_ref = ExternalPackageRef(
                    category=ExternalPackageRefCategory.OTHER,
                    reference_type="end-of-life-date",
                    locator=eol_date,
                    comment="Date when all support ends",
                )
                main_package.external_references.append(ext_ref)
                logger.info(f"Added end-of-life-date to SPDX: {eol_date}")

                # Record to audit trail
                spdx_audit_trail = get_audit_trail()
                spdx_audit_trail.record_augmentation("end_of_life", eol_date, source="config")

    return document


def _add_vcs_info_to_spdx(document: Document, augmentation_data: Dict[str, Any]) -> None:
    """
    Add VCS information to SPDX document.

    SPDX lacks dedicated VCS fields, so we add info to multiple places:
    - downloadLocation: VCS URL with commit pinning (git+https://...@sha)
    - sourceInfo: Human-readable build context
    - externalRefs: VCS external reference (category=OTHER, type="vcs")
    - creationInfo.comment: Build context at document level

    Note on externalRefs: SPDX 2.3 doesn't define a standard "vcs" reference type.
    We use ExternalPackageRefCategory.OTHER with reference_type="vcs" as a convention.
    This is valid per the spec but may not be recognized by all SBOM consumers.
    The primary VCS information should be consumed from downloadLocation.

    Args:
        document: The SPDX Document to augment
        augmentation_data: Metadata containing VCS fields
    """
    vcs_url = augmentation_data.get("vcs_url")
    vcs_commit_sha = augmentation_data.get("vcs_commit_sha")
    vcs_ref = augmentation_data.get("vcs_ref")

    if not vcs_url:
        return

    if not document.packages:
        logger.debug("No packages in SPDX document, cannot add VCS info")
        return

    main_package = document.packages[0]

    # Build VCS URL with commit pinning (git+https://...@sha format)
    vcs_url_with_commit = build_vcs_url_with_commit(vcs_url, vcs_commit_sha)

    # Set downloadLocation if not already set or is NOASSERTION
    if not main_package.download_location or main_package.download_location == "NOASSERTION":
        main_package.download_location = vcs_url_with_commit
        logger.debug(f"Set SPDX downloadLocation to VCS URL: {vcs_url_with_commit}")

    # Add sourceInfo with build context
    source_info_parts = []
    if vcs_commit_sha:
        source_info_parts.append(f"Built from commit {truncate_sha(vcs_commit_sha, 12)}")
    if vcs_ref:
        source_info_parts.append(f"on {vcs_ref}")

    if source_info_parts:
        source_info = " ".join(source_info_parts)
        if main_package.source_info:
            main_package.source_info += f" | {source_info}"
        else:
            main_package.source_info = source_info
        logger.debug(f"Added SPDX sourceInfo: {source_info}")

    # Add VCS external reference (check for duplicates)
    # Note: Using category=OTHER with type="vcs" as SPDX 2.3 convention
    existing_vcs_refs = [ref for ref in main_package.external_references if ref.reference_type == "vcs"]

    if not existing_vcs_refs:
        comment = None
        if vcs_commit_sha:
            comment = f"commit: {truncate_sha(vcs_commit_sha)}"
            if vcs_ref:
                comment += f", ref: {vcs_ref}"

        vcs_ext_ref = ExternalPackageRef(
            category=ExternalPackageRefCategory.OTHER,
            reference_type="vcs",
            locator=vcs_url_with_commit,
            comment=comment,
        )
        main_package.external_references.append(vcs_ext_ref)
        logger.debug(f"Added SPDX VCS external reference: {vcs_url_with_commit}")

    # Add VCS info to document creation comment
    vcs_comment_parts = [f"Source: {vcs_url}"]
    if vcs_commit_sha:
        vcs_comment_parts.append(f"@ {truncate_sha(vcs_commit_sha)}")
    if vcs_ref:
        vcs_comment_parts.append(f"({vcs_ref})")

    vcs_comment = " ".join(vcs_comment_parts)
    if document.creation_info.creator_comment:
        document.creation_info.creator_comment += f" | {vcs_comment}"
    else:
        document.creation_info.creator_comment = vcs_comment

    log_msg = f"Added VCS info to SPDX: {vcs_url}"
    if vcs_commit_sha:
        log_msg += f" @ {truncate_sha(vcs_commit_sha)}"
    if vcs_ref:
        log_msg += f" ({vcs_ref})"
    logger.info(log_msg)


def _construct_purl_from_vcs(vcs_url: str, vcs_commit_sha: str | None) -> str | None:
    """
    Construct a PURL from VCS URL information.

    Maps common VCS hosts to their PURL types:
    - github.com -> pkg:github/owner/repo
    - gitlab.com -> pkg:gitlab/owner/repo (includes self-hosted with "gitlab" in hostname)
    - bitbucket.org -> pkg:bitbucket/owner/repo

    For GitLab nested groups (e.g., gitlab.com/group/subgroup/project),
    the last path component is used as the repo name.

    Args:
        vcs_url: Repository URL (e.g., https://github.com/owner/repo)
        vcs_commit_sha: Optional commit SHA for versioning

    Returns:
        PURL string or None if construction fails
    """
    from urllib.parse import urlparse

    if not vcs_url:
        return None

    # Parse the VCS URL
    parsed = urlparse(vcs_url)
    host = parsed.netloc.lower()
    path = parsed.path.strip("/")

    # Remove .git suffix if present
    if path.endswith(".git"):
        path = path[:-4]

    # Map hosts to PURL types
    purl_type = None
    if "github.com" in host:
        purl_type = "github"
    elif "gitlab.com" in host or "gitlab" in host:
        purl_type = "gitlab"
    elif "bitbucket.org" in host:
        purl_type = "bitbucket"

    if purl_type and path:
        # path should be owner/repo or owner/subgroup/repo (GitLab nested groups)
        parts = path.split("/")
        if len(parts) >= 2:
            # For nested groups, use first part as namespace and last as name
            namespace = parts[0]
            name = parts[-1]  # Last component is always the repo name
            version = truncate_sha(vcs_commit_sha, 7) if vcs_commit_sha else None

            if version:
                return f"pkg:{purl_type}/{namespace}/{name}@{version}"
            else:
                return f"pkg:{purl_type}/{namespace}/{name}"

    return None


def _ensure_spdx_main_package_purl(document: Document, augmentation_data: dict[str, Any]) -> None:
    """
    Ensure the SPDX main package has a PURL for NTIA compliance.

    NTIA Minimum Elements require a unique identifier (PURL) for the main component.
    This function checks if one exists and constructs one from VCS info if possible.

    The PURL is added as an externalRef with:
    - category: OTHER (VCS-based PURLs like github/gitlab/bitbucket)
    - referenceType: purl
    - locator: the PURL string

    Args:
        document: The SPDX Document to check/augment
        augmentation_data: Metadata containing VCS fields and other info
    """
    if not document.packages:
        logger.debug("No packages in SPDX document, cannot add PURL")
        return

    main_package = document.packages[0]

    # Check if PURL already exists
    existing_purl = None
    for ref in main_package.external_references:
        if ref.reference_type == "purl":
            existing_purl = ref.locator
            break

    if existing_purl:
        logger.debug(f"SPDX main package already has PURL: {existing_purl}")
        return

    # Try to construct PURL from VCS info
    vcs_url = augmentation_data.get("vcs_url")
    vcs_commit_sha = augmentation_data.get("vcs_commit_sha")

    purl = _construct_purl_from_vcs(vcs_url, vcs_commit_sha)

    if purl:
        # VCS-based PURLs (github, gitlab, bitbucket) use OTHER category
        # since they're not traditional package managers
        ext_ref = ExternalPackageRef(
            category=ExternalPackageRefCategory.OTHER,
            reference_type="purl",
            locator=purl,
            comment="Package URL for unique identification (NTIA Minimum Elements)",
        )
        main_package.external_references.append(ext_ref)

        # Record to audit trail
        audit_trail = get_audit_trail()
        audit_trail.record_augmentation("purl", purl, source="vcs")
        logger.info(f"Added PURL to SPDX main package: {purl}")


def augment_spdx3_sbom(
    input_file: str,
    output_file: str,
    augmentation_data: Dict[str, Any],
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
) -> None:
    """Augment an SPDX 3 SBOM with organizational metadata.

    Args:
        input_file: Path to the input SPDX 3 JSON-LD file
        output_file: Path to write the augmented output
        augmentation_data: Metadata from backend/config
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override
    """
    from .spdx3 import (
        ExternalReference as Spdx3ExtRef,
    )
    from .spdx3 import (
        ExternalReferenceType as Spdx3ExtRefType,
    )
    from .spdx3 import (
        Organization as Spdx3Org,
    )
    from .spdx3 import (
        Person as Spdx3Person,
    )
    from .spdx3 import (
        Tool as Spdx3Tool,
    )
    from .spdx3 import (
        get_spdx3_document,
        get_spdx3_root_package,
        make_spdx3_creation_info,
        make_spdx3_spdx_id,
        parse_spdx3_file,
        spdx3_licenses_from_list,
        write_spdx3_file,
    )

    payload = parse_spdx3_file(input_file)
    doc = get_spdx3_document(payload)
    root_pkg = get_spdx3_root_package(payload)

    # Add sbomify tool
    tool_id = make_spdx3_spdx_id()
    tool = Spdx3Tool(
        spdx_id=tool_id, name=f"{SBOMIFY_TOOL_NAME}-{SBOMIFY_VERSION}", creation_info=make_spdx3_creation_info()
    )
    payload.add_element(tool)
    if doc:
        doc.element.append(tool_id)
        if doc.creation_info and tool_id not in doc.creation_info.created_using:
            doc.creation_info.created_using.append(tool_id)
    logger.info("Added sbomify as processing tool")

    # Apply supplier information
    if "supplier" in augmentation_data and root_pkg:
        supplier_data = augmentation_data["supplier"]
        supplier_name = supplier_data.get("name")
        if supplier_name and (not root_pkg.supplied_by or override_sbom_metadata):
            org_id = make_spdx3_spdx_id()
            org = Spdx3Org(spdx_id=org_id, name=supplier_name, creation_info=make_spdx3_creation_info())
            payload.add_element(org)
            root_pkg.supplied_by = [org_id]
            if doc:
                doc.element.append(org_id)
            logger.info(f"Set supplier: {supplier_name}")

    # Apply authors
    if "authors" in augmentation_data and augmentation_data["authors"]:
        authors_data = augmentation_data["authors"]
        for author_data in authors_data:
            author_name = author_data.get("name")
            if author_name:
                person_id = make_spdx3_spdx_id()
                person = Spdx3Person(spdx_id=person_id, name=author_name, creation_info=make_spdx3_creation_info())
                payload.add_element(person)
                if doc:
                    doc.element.append(person_id)
                    if doc.creation_info:
                        doc.creation_info.created_by.append(person_id)
        logger.info(f"Added {len(authors_data)} author(s)")

    # Apply licenses
    if "licenses" in augmentation_data and augmentation_data["licenses"] and root_pkg:
        licenses_data = augmentation_data["licenses"]
        license_ids = []
        for lic_data in licenses_data:
            if isinstance(lic_data, dict):
                spdx_id = lic_data.get("spdx_id") or lic_data.get("name", "")
                if spdx_id:
                    license_ids.append(spdx_id)
            elif isinstance(lic_data, str):
                license_ids.append(lic_data)

        if license_ids and (not root_pkg.declared_license or override_sbom_metadata):
            root_pkg.declared_license = spdx3_licenses_from_list(license_ids)
            logger.info(f"Set license(s): {', '.join(license_ids)}")

    # Apply component name override
    if component_name:
        if doc:
            doc.name = component_name
        if root_pkg:
            root_pkg.name = component_name
        logger.info(f"Set component name: {component_name}")

    # Apply component version override
    if component_version and root_pkg:
        root_pkg.package_version = component_version
        # Update PURL version to maintain consistency
        if root_pkg.package_url:
            try:
                old_purl = PackageURL.from_string(root_pkg.package_url)
                root_pkg.package_url = str(
                    PackageURL(
                        type=old_purl.type,
                        namespace=old_purl.namespace,
                        name=old_purl.name,
                        version=component_version,
                        qualifiers=old_purl.qualifiers,
                        subpath=old_purl.subpath,
                    )
                )
                logger.debug(f"Updated SPDX 3 package PURL version: {old_purl} -> {root_pkg.package_url}")
            except Exception as e:
                logger.warning(f"Failed to update SPDX 3 package PURL version: {e}")
        logger.info(f"Set component version: {component_version}")

    # Apply VCS information
    vcs_url = augmentation_data.get("vcs_url")
    vcs_commit_sha = augmentation_data.get("vcs_commit_sha")
    if vcs_url and root_pkg:
        download_url = vcs_url
        if vcs_commit_sha:
            download_url = f"git+{vcs_url}@{vcs_commit_sha}"
        if not root_pkg.download_location or override_sbom_metadata:
            root_pkg.download_location = download_url

        # Add VCS external reference
        existing_locs = []
        for ref in root_pkg.external_reference:
            existing_locs.extend(ref.locator)
        if vcs_url not in existing_locs:
            root_pkg.external_reference.append(
                Spdx3ExtRef(
                    external_reference_type=Spdx3ExtRefType.VCS,
                    locator=[vcs_url],
                )
            )
            logger.info(f"Added VCS reference: {vcs_url}")

    # Apply security contact
    security_contact = augmentation_data.get("security_contact")
    if security_contact and root_pkg:
        existing_locs = []
        for ref in root_pkg.external_reference:
            existing_locs.extend(ref.locator)
        if security_contact not in existing_locs:
            root_pkg.external_reference.append(
                Spdx3ExtRef(
                    external_reference_type=Spdx3ExtRefType.SECURITY_POLICY,
                    locator=[security_contact],
                    comment="Security vulnerability reporting contact",
                )
            )
            logger.info(f"Added security contact: {security_contact}")

    # Apply support period end date
    support_end = augmentation_data.get("support_period_end")
    if support_end and root_pkg:
        try:
            from datetime import datetime

            valid_until = datetime.fromisoformat(support_end)
            if not root_pkg.valid_until_time or override_sbom_metadata:
                root_pkg.valid_until_time = valid_until
                logger.info(f"Set valid_until_time: {support_end}")
        except ValueError:
            logger.warning(f"Could not parse support_period_end date '{support_end}'")

    # Apply lifecycle phase
    lifecycle_phase = augmentation_data.get("lifecycle_phase")
    if lifecycle_phase and doc and doc.creation_info:
        comment = f"Lifecycle phase: {lifecycle_phase}"
        if doc.creation_info.comment:
            doc.creation_info.comment += f" | {comment}"
        else:
            doc.creation_info.comment = comment
        logger.info(f"Added lifecycle phase: {lifecycle_phase}")

    write_spdx3_file(payload, output_file)


def augment_sbom_from_file(
    input_file: str,
    output_file: str,
    api_base_url: Optional[str] = None,
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    validate: bool = True,
    config_path: Optional[str] = None,
) -> Literal["cyclonedx", "spdx"]:
    """
    Augment SBOM file with metadata from multiple providers.

    Uses the plugin architecture to fetch metadata from:
    1. JSON config file (sbomify.json) - higher priority
    2. sbomify API - lower priority (fallback)

    After augmentation, the output SBOM is validated against its JSON schema
    (when validate=True).

    Note: PURL override is handled separately in main.py via _apply_sbom_purl_override()
    to ensure it works regardless of augmentation settings.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save augmented SBOM
        api_base_url: Backend API base URL (optional, for sbomify API provider)
        token: Authentication token (optional, for sbomify API provider)
        component_id: Component ID (optional, for sbomify API provider)
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override
        validate: Whether to validate the output SBOM (default: True)
        config_path: Path to JSON config file (optional, defaults to sbomify.json)

    Returns:
        SBOM format ('cyclonedx' or 'spdx')

    Raises:
        ValueError: If SBOM format is not supported
        SBOMValidationError: If output validation fails
        Exception: For other errors during augmentation
    """
    # Fetch metadata from all providers (merged by priority)
    logger.info("Fetching augmentation metadata from providers")
    augmentation_data = fetch_augmentation_metadata(
        api_base_url=api_base_url,
        token=token,
        component_id=component_id,
        config_path=config_path,
    )

    # Detect format and parse
    input_path = Path(input_file)

    # Try CycloneDX first
    try:
        import json

        try:
            with open(input_path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Input SBOM file not found: {input_file}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in SBOM file: {e}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading SBOM file: {input_file}")
        except OSError as e:
            raise OSError(f"Error reading SBOM file {input_file}: {e}")

        if data.get("bomFormat") == "CycloneDX":
            # Validate required fields before processing
            spec_version = data.get("specVersion")
            if spec_version is None:
                raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")

            # Parse as CycloneDX
            try:
                bom = Bom.from_json(data)
            except Exception as e:
                raise SBOMValidationError(f"Failed to parse CycloneDX SBOM: {e}")
            logger.info("Processing CycloneDX SBOM")

            # Augment
            bom = augment_cyclonedx_sbom(
                bom,
                augmentation_data,
                override_sbom_metadata,
                component_name,
                component_version,
                spec_version,
            )

            # Sanitize dependency graph (add stubs for orphaned references)
            sanitize_dependency_graph(bom)

            # Link top-level components to root if root has no dependencies
            link_root_dependencies(bom)

            # Write output using version-aware serialization
            serialized = serialize_cyclonedx_bom(bom, spec_version)

            output_path = Path(output_file)
            try:
                with open(output_path, "w") as f:
                    f.write(serialized)
            except PermissionError:
                raise PermissionError(f"Permission denied writing output file: {output_file}")
            except OSError as e:
                raise OSError(f"Error writing output file {output_file}: {e}")

            logger.info(f"Augmented CycloneDX SBOM written to: {output_file}")

            # Validate the augmented SBOM
            if validate:
                validation_result = validate_sbom_file_auto(output_file)
                if validation_result.valid is None:
                    logger.warning(
                        f"Augmented SBOM could not be validated ({validation_result.sbom_format} "
                        f"{validation_result.spec_version}): {validation_result.error_message}"
                    )
                elif not validation_result.valid:
                    raise SBOMValidationError(f"Augmented SBOM failed validation: {validation_result.error_message}")
                else:
                    logger.info(
                        f"Augmented SBOM validated: {validation_result.sbom_format} {validation_result.spec_version}"
                    )

            return "cyclonedx"

        elif is_spdx3(data):
            # Parse as SPDX 3
            logger.info("Processing SPDX 3 SBOM")
            augment_spdx3_sbom(
                str(input_path),
                output_file,
                augmentation_data,
                override_sbom_metadata,
                component_name,
                component_version,
            )

            logger.info(f"Augmented SPDX 3 SBOM written to: {output_file}")

            # Validate the augmented SBOM
            if validate:
                validation_result = validate_sbom_file_auto(output_file)
                if validation_result.valid is None:
                    logger.warning(
                        f"Augmented SBOM could not be validated ({validation_result.sbom_format} "
                        f"{validation_result.spec_version}): {validation_result.error_message}"
                    )
                elif not validation_result.valid:
                    raise SBOMValidationError(f"Augmented SBOM failed validation: {validation_result.error_message}")
                else:
                    logger.info(
                        f"Augmented SBOM validated: {validation_result.sbom_format} {validation_result.spec_version}"
                    )

            return "spdx"

        elif data.get("spdxVersion"):
            # Parse as SPDX 2.x
            try:
                document = spdx_parse_file(str(input_path))
            except Exception as e:
                raise SBOMValidationError(f"Failed to parse SPDX SBOM: {e}")
            logger.info("Processing SPDX SBOM")

            # Augment
            document = augment_spdx_sbom(
                document, augmentation_data, override_sbom_metadata, component_name, component_version
            )

            # Write output
            output_path = Path(output_file)
            try:
                spdx_write_file(document, str(output_path), validate=False)
                sanitize_spdx_json_file(str(output_path))
            except PermissionError:
                raise PermissionError(f"Permission denied writing output file: {output_file}")
            except OSError as e:
                raise OSError(f"Error writing output file {output_file}: {e}")

            logger.info(f"Augmented SPDX SBOM written to: {output_file}")

            # Validate the augmented SBOM
            if validate:
                validation_result = validate_sbom_file_auto(output_file)
                if validation_result.valid is None:
                    logger.warning(
                        f"Augmented SBOM could not be validated ({validation_result.sbom_format} "
                        f"{validation_result.spec_version}): {validation_result.error_message}"
                    )
                elif not validation_result.valid:
                    raise SBOMValidationError(f"Augmented SBOM failed validation: {validation_result.error_message}")
                else:
                    logger.info(
                        f"Augmented SBOM validated: {validation_result.sbom_format} {validation_result.spec_version}"
                    )

            return "spdx"

        else:
            raise ValueError("Neither CycloneDX nor SPDX format detected")

    except Exception as e:
        logger.error(f"Failed to augment SBOM: {e}")
        raise
