"""Wizard section functions for collecting sbomify.json configuration."""

from typing import Any

from questionary import Choice

from sbomify_action.cli.wizard.prompts import (
    ask_autocomplete,
    ask_confirm,
    ask_select,
    ask_text,
    print_info,
    print_section_header,
)
from sbomify_action.cli.wizard.validators import (
    LIFECYCLE_PHASES,
    validate_email,
    validate_iso_date,
    validate_license,
    validate_url,
)


def _collect_contact() -> dict[str, str] | None:
    """Collect a single contact entry."""
    contact: dict[str, str] = {}

    name = ask_text("Contact name:")
    if name:
        contact["name"] = name

    email = ask_text(
        "Contact email:",
        validate=lambda x: True if not x else validate_email(x) or "Invalid email format",
    )
    if email:
        contact["email"] = email

    phone = ask_text("Contact phone:")
    if phone:
        contact["phone"] = phone

    return contact if contact else None


def _collect_contacts() -> list[dict[str, str]]:
    """Collect multiple contacts."""
    contacts = []

    while True:
        contact = _collect_contact()
        if contact:
            contacts.append(contact)

        if not ask_confirm("Add another contact?", default=False):
            break

    return contacts


def _collect_organization_entity(entity_type: str, existing: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Collect supplier or manufacturer info.

    Args:
        entity_type: "Supplier" or "Manufacturer"
        existing: Existing entity data

    Returns:
        Entity dict or None if skipped
    """
    entity: dict[str, Any] = {}

    name = ask_text(
        f"{entity_type} name:",
        default=existing.get("name", "") if existing else "",
    )
    if name:
        entity["name"] = name

    urls_str = ask_text(
        f"{entity_type} URL(s) (comma-separated):",
        default=", ".join(existing.get("url", [])) if existing else "",
        validate=lambda x: True
        if not x
        else all(validate_url(u.strip()) for u in x.split(",")) or "One or more URLs are invalid",
    )
    if urls_str:
        urls = [u.strip() for u in urls_str.split(",") if u.strip()]
        if urls:
            entity["url"] = urls

    if ask_confirm(f"Add contacts for {entity_type.lower()}?", default=False):
        contacts = _collect_contacts()
        if contacts:
            entity["contacts"] = contacts

    return entity if entity else None


def collect_organization(existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect organization info (supplier and manufacturer).

    Args:
        existing: Existing configuration

    Returns:
        Dict with supplier and/or manufacturer keys
    """
    print_section_header(
        "Organization Information",
        "Configure supplier and manufacturer details for your SBOM.",
    )

    result: dict[str, Any] = {}

    # Supplier
    print_info("Supplier is the organization that distributes the software.")
    supplier = _collect_organization_entity(
        "Supplier",
        existing.get("supplier") if existing else None,
    )
    if supplier:
        result["supplier"] = supplier

    # Manufacturer (optional)
    if ask_confirm("Do you want to add a manufacturer? (May differ from supplier)", default=False):
        print_info("Manufacturer is the organization that created the software.")
        manufacturer = _collect_organization_entity(
            "Manufacturer",
            existing.get("manufacturer") if existing else None,
        )
        if manufacturer:
            result["manufacturer"] = manufacturer

    return result


def collect_authors(existing: list[dict[str, str]] | None = None) -> list[dict[str, str]] | None:
    """Collect author information.

    Args:
        existing: Existing authors list

    Returns:
        List of author dicts or None if none added
    """
    print_section_header(
        "Authors",
        "Add information about the software authors.",
    )

    authors: list[dict[str, str]] = []

    # Show existing authors if any
    if existing:
        print_info(f"Existing authors: {len(existing)}")
        if ask_confirm("Keep existing authors?", default=True):
            authors.extend(existing)

    while True:
        if authors and not ask_confirm("Add another author?", default=False):
            break

        author: dict[str, str] = {}

        name = ask_text("Author name:")
        if name:
            author["name"] = name

        email = ask_text(
            "Author email:",
            validate=lambda x: True if not x else validate_email(x) or "Invalid email format",
        )
        if email:
            author["email"] = email

        phone = ask_text("Author phone:")
        if phone:
            author["phone"] = phone

        if author:
            authors.append(author)
        elif not authors:
            # First iteration and nothing entered - ask if they want to continue
            if not ask_confirm("No author entered. Try again?", default=False):
                break

    return authors if authors else None


def collect_licenses(existing: list[str] | None = None) -> list[str] | None:
    """Collect license information.

    Args:
        existing: Existing licenses list

    Returns:
        List of SPDX license IDs or None if none selected
    """
    from license_expression import get_spdx_licensing

    print_section_header(
        "Licenses",
        "Add SPDX license identifiers for your software.",
    )

    licenses: list[str] = []

    # Show existing
    if existing:
        print_info(f"Existing licenses: {', '.join(existing)}")
        if ask_confirm("Keep existing licenses?", default=True):
            licenses = list(existing)

    # Get all SPDX license keys for autocomplete
    spdx = get_spdx_licensing()
    all_licenses = sorted(spdx.known_symbols.keys())

    # Search-based license selection
    print_info("Type to search SPDX licenses (e.g., 'MIT', 'Apache', 'GPL').")
    print_info("You can also enter custom/proprietary license identifiers.")
    print_info("Press Enter with empty input when done.\n")

    while True:
        # Show current selections
        if licenses:
            print_info(f"Selected: {', '.join(licenses)}")

        license_id = ask_autocomplete(
            "Add license (or press Enter to finish):",
            choices=all_licenses,
        )

        if not license_id:
            # Empty input = done
            break

        if license_id in licenses:
            print_info(f"'{license_id}' already added.")
        else:
            licenses.append(license_id)
            if validate_license(license_id):
                print_info(f"Added '{license_id}'.")
            else:
                print_info(f"Added '{license_id}' (custom license, not in SPDX list).")

    return licenses if licenses else None


def collect_security_contact(existing: str | None = None) -> str | None:
    """Collect security contact information.

    Args:
        existing: Existing security contact

    Returns:
        Security contact string or None
    """
    print_section_header(
        "Security Contact",
        "Provide contact information for reporting security vulnerabilities (CRA compliance).",
    )

    if existing:
        print_info(f"Existing: {existing}")
        if ask_confirm("Keep existing security contact?", default=True):
            return existing

    contact_type = ask_select(
        "Security contact type:",
        choices=[
            Choice("security.txt URL (recommended)", value="url"),
            Choice("Email address", value="email"),
            Choice("Disclosure page URL", value="page"),
        ],
    )

    if not contact_type:
        return None

    if contact_type == "email":
        email = ask_text(
            "Security email address:",
            validate=lambda x: True if not x else validate_email(x) or "Invalid email format",
        )
        if email:
            return f"mailto:{email}"
    else:
        placeholder = (
            "https://example.com/.well-known/security.txt" if contact_type == "url" else "https://example.com/security"
        )
        url = ask_text(
            "Security contact URL:",
            instruction=f"(e.g., {placeholder})",
            validate=lambda x: True if not x else validate_url(x) or "Invalid URL format",
        )
        if url:
            return url

    return None


def collect_lifecycle_and_dates(existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect lifecycle phase and dates.

    Args:
        existing: Existing configuration

    Returns:
        Dict with lifecycle_phase and date fields
    """
    print_section_header(
        "Lifecycle & Dates",
        "Configure CISA 2025 lifecycle phase and important dates.",
    )

    result: dict[str, Any] = {}

    # Lifecycle phase dropdown
    phase_choices = [
        Choice("build - During compilation/build (most common)", value="build"),
        Choice("design - During design phase", value="design"),
        Choice("pre-build - Before build starts", value="pre-build"),
        Choice("post-build - After build completes", value="post-build"),
        Choice("operations - During deployment/runtime", value="operations"),
        Choice("discovery - During analysis", value="discovery"),
        Choice("decommission - End-of-life", value="decommission"),
        Choice("(skip)", value=""),
    ]

    existing_phase = existing.get("lifecycle_phase") if existing else None
    phase = ask_select(
        "Lifecycle phase:",
        choices=phase_choices,
        default=existing_phase if existing_phase in LIFECYCLE_PHASES else "build",
    )
    if phase:
        result["lifecycle_phase"] = phase

    # Dates
    print_info("Enter dates in YYYY-MM-DD format (or leave empty to skip).")

    release_date = ask_text(
        "Release date:",
        default=existing.get("release_date", "") if existing else "",
        validate=lambda x: True if not x else validate_iso_date(x) or "Invalid date format (use YYYY-MM-DD)",
    )
    if release_date:
        result["release_date"] = release_date

    support_end = ask_text(
        "Support period end date:",
        default=existing.get("support_period_end", "") if existing else "",
        validate=lambda x: True if not x else validate_iso_date(x) or "Invalid date format (use YYYY-MM-DD)",
    )
    if support_end:
        result["support_period_end"] = support_end

    eol = ask_text(
        "End of life date:",
        default=existing.get("end_of_life", "") if existing else "",
        validate=lambda x: True if not x else validate_iso_date(x) or "Invalid date format (use YYYY-MM-DD)",
    )
    if eol:
        result["end_of_life"] = eol

    return result


def collect_vcs_override(existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect VCS override information.

    Args:
        existing: Existing configuration

    Returns:
        Dict with VCS fields
    """
    print_section_header(
        "VCS Override",
        "Override auto-detected VCS information (useful for self-hosted git servers).",
    )

    print_info("Note: VCS information is usually auto-detected from CI environment variables.")
    print_info("Only set these if you need to override auto-detection.")

    result: dict[str, Any] = {}

    vcs_url = ask_text(
        "Repository URL:",
        default=existing.get("vcs_url", "") if existing else "",
        validate=lambda x: True if not x else validate_url(x) or "Invalid URL format",
        instruction="(e.g., https://github.mycompany.com/org/repo)",
    )
    if vcs_url:
        result["vcs_url"] = vcs_url

    return result
