"""Rich console utilities for sbomify-action.

This module provides a shared Rich Console instance and helper functions
for beautiful CLI output.

How output is rendered is the active CI platform's business, not this module's:
structural output (groups, step headers, annotations, banners) is delegated to
``get_platform().log_formatter()``. GitHub Actions gets workflow commands,
everything else gets Rich styling.
"""

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from sbomify_action import format_display_name
from sbomify_action._runtime import LogFormatter, get_platform

# Resolved once: the Console below is built from it and cannot be rebuilt later.
# Everything else calls _formatter(), which re-resolves per call.
_STARTUP_PLATFORM = get_platform()

# Snapshots taken at import, for decisions that are themselves made once (the
# Console's colour handling, the theme). They do NOT track later changes to the
# environment and nothing reads them to choose output format -- reassigning one
# changes nothing. Call get_platform() if you need the current platform.
#
# IS_CI comes from the platform, which is why TeamCity no longer needs a flag of
# its own here: every CI platform reports is_ci, so tracebacks_show_locals stays
# off for all of them rather than only the ones this module remembered to list.
IS_GITHUB_ACTIONS = _STARTUP_PLATFORM.name == "github-actions"
IS_GITLAB_CI = _STARTUP_PLATFORM.name == "gitlab-ci"
IS_TEAMCITY = _STARTUP_PLATFORM.name == "teamcity"
IS_CI = _STARTUP_PLATFORM.is_ci


def _formatter() -> LogFormatter:
    """Return the active platform's log formatter.

    Resolved per call so a platform pinned mid-process (tests, embedders) takes
    effect without re-importing this module.
    """
    return get_platform().log_formatter()


# sbomify brand colors (from logo gradient)
# These hex colors look great in local terminals
BRAND_COLORS_HEX = {
    "blue": "#4059D0",
    "purple_light": "#7C5BC8",
    "purple": "#A85AC0",
    "pink": "#CC58BB",
    "peach": "#E0879D",
    "orange": "#F4B57F",
}

# Theme-adaptive colors for GitHub Actions (works in both light and dark mode)
# Standard ANSI color names automatically adapt to the terminal's theme
BRAND_COLORS_ADAPTIVE = {
    "blue": "blue",
    "purple_light": "bright_blue",
    "purple": "magenta",
    "pink": "bright_magenta",
    "peach": "bright_red",
    "orange": "yellow",
}

# Choose colors based on environment
# In CI, use adaptive colors that work in both light and dark themes
# Locally, use the exact brand hex colors for best appearance
BRAND_COLORS = BRAND_COLORS_ADAPTIVE if IS_CI else BRAND_COLORS_HEX

# Custom theme for sbomify branding
# Uses adaptive colors that work in both light and dark terminal themes
custom_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "step": "bold blue",
        "highlight": "magenta",
        "brand.blue": BRAND_COLORS["blue"],
        "brand.purple": BRAND_COLORS["purple"],
        "brand.pink": BRAND_COLORS["pink"],
        "brand.orange": BRAND_COLORS["orange"],
    }
)

# Shared console instance. Whether to force colors on is the platform's call --
# some runners support ANSI but Rich cannot detect it through their pipe.
console = Console(
    theme=custom_theme,
    force_terminal=_STARTUP_PLATFORM.log_formatter().force_terminal,
    color_system="auto",
)


def print_banner(version: str = "unknown") -> None:
    """Print the sbomify banner with gradient colors."""
    banner = Text()
    banner.append(
        "         __                    _ ____         ___        __  _           \n", style=BRAND_COLORS["blue"]
    )
    banner.append(
        "   _____/ /_  ____  ____ ___  (_) __/_  __   /   | _____/ /_(_)___  ____ \n",
        style=BRAND_COLORS["purple_light"],
    )
    banner.append(
        "  / ___/ __ \\/ __ \\/ __ `__ \\/ / /_/ / / /  / /| |/ ___/ __/ / __ \\/ __ \\\n", style=BRAND_COLORS["purple"]
    )
    banner.append(
        " (__  ) /_/ / /_/ / / / / / / / __/ /_/ /  / ___ / /__/ /_/ / /_/ / / / /\n", style=BRAND_COLORS["pink"]
    )
    banner.append(
        "/____/_.___/\\____/_/ /_/ /_/_/_/  \\__, /  /_/  |_\\___/\\__/_/\\____/_/ /_/ \n", style=BRAND_COLORS["peach"]
    )
    banner.append(
        "                                 /____/                                  \n", style=BRAND_COLORS["orange"]
    )
    # Only prefix with 'v' if version looks like semver (starts with digit)
    version_display = f"v{version}" if version and version[0:1].isdigit() else version
    banner.append(" From zero to SBOM hero\n", style=BRAND_COLORS["purple_light"])
    banner.append(f" {version_display}\n", style=BRAND_COLORS["orange"])

    console.print(banner)


def print_step_header(step_num: int | float, title: str) -> None:
    """
    Print a styled step header.

    Rendering is the platform's choice: a collapsible group on GitHub Actions,
    a Rich rule elsewhere.

    Args:
        step_num: Step number (e.g., 1, 2, or substeps like 1.4, 1.5)
        title: Step title
    """
    _formatter().step_header(f"STEP {step_num}: {title}")


def print_step_end(step_num: int | float, success: bool = True) -> None:
    """
    Print step completion status and close the step's group, if any.

    Args:
        step_num: Step number (e.g., 1, 2, or substeps like 1.4, 1.5)
        success: Whether the step completed successfully
    """
    if success:
        console.print(f"[success]✓ Step {step_num} completed successfully[/success]")
    else:
        console.print(f"[error]✗ Step {step_num} failed[/error]")

    _formatter().step_footer()


@contextmanager
def log_group(title: str) -> Generator[None, None, None]:
    """
    Context manager for a collapsible output group.

    Collapses on platforms that support it; a no-op elsewhere.

    Args:
        title: Group title

    Usage:
        with log_group("Details"):
            print("This is collapsible where the platform supports it")
    """
    formatter = _formatter()
    formatter.group_start(title)
    try:
        yield
    finally:
        formatter.group_end()


def log_warning(message: str, title: Optional[str] = None) -> None:
    """
    Emit a warning annotation.

    Args:
        message: Warning message
        title: Optional title for the warning
    """
    _formatter().warning(message, title)


def log_error(message: str, title: Optional[str] = None) -> None:
    """
    Emit an error annotation.

    Args:
        message: Error message
        title: Optional title for the error
    """
    _formatter().error(message, title)


def log_notice(message: str, title: Optional[str] = None) -> None:
    """
    Emit an informational annotation.

    Args:
        message: Notice message
        title: Optional title for the notice
    """
    _formatter().notice(message, title)


# Deprecated GitHub-flavoured aliases. The annotations are no longer
# GitHub-specific -- each platform renders them its own way.
gha_group = log_group
gha_warning = log_warning
gha_error = log_error
gha_notice = log_notice


def print_summary_table(
    title: str,
    data: List[Tuple[str, Any]],
    show_if_empty: bool = False,
) -> None:
    """
    Print a summary table.

    Args:
        title: Table title
        data: List of (label, value) tuples
        show_if_empty: Whether to show the table if all values are 0/empty
    """
    # Filter out zero/empty values unless show_if_empty is True
    if not show_if_empty:
        data = [(label, value) for label, value in data if value]

    if not data:
        return

    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    for label, value in data:
        table.add_row(label, str(value))

    console.print(table)


def print_enrichment_summary(stats: Dict[str, Any], total_components: int) -> None:
    """
    Print enrichment summary as a Rich table.

    Args:
        stats: Enrichment statistics dictionary (from CycloneDX or SPDX enrichment)
        total_components: Total number of components processed
    """
    data = [
        ("Components enriched", f"{stats.get('components_enriched', 0)}/{total_components}"),
        ("Descriptions added", stats.get("descriptions_added", 0)),
        ("Licenses added", stats.get("licenses_added", 0)),
        ("Publishers added", stats.get("publishers_added", 0)),
        ("Suppliers added", stats.get("suppliers_added", 0)),
        ("Homepage URLs added", stats.get("homepages_added", 0)),
        ("Repository URLs added", stats.get("repositories_added", 0)),
        # CycloneDX-specific fields
        ("Distribution URLs added", stats.get("distributions_added", 0)),
        ("Issue tracker URLs added", stats.get("issue_trackers_added", 0)),
        ("OS components enriched", stats.get("os_components_enriched", 0)),
        # SPDX-specific fields
        ("Originators added", stats.get("originators_added", 0)),
        ("Source info added", stats.get("source_info_added", 0)),
        ("External refs added", stats.get("external_refs_added", 0)),
    ]

    print_summary_table("Enrichment Summary", data)

    # Show sources breakdown if available
    sources = stats.get("sources", {})
    if sources:
        source_data = [(source, count) for source, count in sorted(sources.items())]
        print_summary_table("Enrichment by Source", source_data)


def print_sanitization_summary(
    vcs_normalized: int = 0,
    purls_normalized: int = 0,
    purls_cleared: int = 0,
    urls_rejected: int = 0,
    stubs_added: int = 0,
    details: Optional[List[str]] = None,
) -> None:
    """
    Print sanitization summary as a Rich table.

    Args:
        vcs_normalized: Number of VCS URLs normalized
        purls_normalized: Number of PURLs normalized
        purls_cleared: Number of invalid PURLs cleared
        urls_rejected: Number of URLs rejected
        stubs_added: Number of stub components added
        details: Optional list of detail strings for attestation
    """
    data = [
        ("VCS URLs normalized", vcs_normalized),
        ("PURLs normalized", purls_normalized),
        ("PURLs cleared (invalid)", purls_cleared),
        ("URLs rejected", urls_rejected),
        ("Stub components added", stubs_added),
    ]

    print_summary_table("Sanitization Summary", data)

    # Show details in collapsible group for attestation
    if details and any(d for d in details):
        with gha_group("Sanitization Details (for attestation)"):
            for detail in details:
                console.print(f"  {detail}")


def print_upload_summary(
    destination: str,
    success: bool,
    sbom_format: str,
    sbom_id: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    """
    Print upload result summary.

    Args:
        destination: Upload destination name
        success: Whether upload succeeded
        sbom_format: SBOM format (cyclonedx/spdx)
        sbom_id: Optional SBOM ID from response
        error_message: Optional error message if failed
    """
    if success:
        console.print(f"[success]✓ Uploaded to {destination}[/success]")
        if sbom_id:
            console.print(f"  SBOM ID: {sbom_id}")
    else:
        console.print(f"[error]✗ Upload to {destination} failed[/error]")
        if error_message:
            console.print(f"  Error: {error_message}")


def print_duplicate_sbom_error(
    component_id: str,
    sbom_format: str,
    component_version: Optional[str] = None,
    artifact_kind: str = "SBOM",
) -> None:
    """
    Print a styled error panel for a duplicate artifact upload.

    This provides a clear, user-friendly error message when an artifact
    already exists for the component, with suggested solutions.

    Args:
        component_id: The component ID that has the duplicate
        sbom_format: SBOM format (cyclonedx/spdx)
        component_version: The component version that has the duplicate
        artifact_kind: Display kind of the artifact (SBOM, VEX, CBOM, HBOM);
            non-SBOM kinds upload verbatim, so COMPONENT_VERSION advice does
            not apply to them
    """
    content = Text()
    content.append(f"A duplicate {artifact_kind} already exists for this component.\n\n", style="bold")
    content.append("Details:\n", style="cyan")
    content.append(f"  Component ID: {component_id}\n")
    if component_version:
        content.append(f"  Version: {component_version}\n")
    content.append(f"  Format: {format_display_name(sbom_format)}\n\n")
    content.append("Possible solutions:\n", style="cyan")
    if artifact_kind == "SBOM":
        content.append("  1. Set a unique version via COMPONENT_VERSION or --component-version\n")
    else:
        content.append("  1. Bump the version inside the authored document (COMPONENT_VERSION is ignored)\n")
    content.append(f"  2. Delete the existing {artifact_kind} in the sbomify dashboard\n")
    content.append("  3. Use a different component ID\n")

    panel = Panel(content, title=f"[bold red]Duplicate {artifact_kind}[/bold red]", border_style="red")
    console.print(panel)

    # Also emit GHA error annotation, mirroring the panel guidance
    if artifact_kind == "SBOM":
        gha_error("SBOM already exists for this component version", title="Duplicate SBOM")
    else:
        gha_error(
            f"{artifact_kind} already exists for this component; bump the version inside the authored document",
            title=f"Duplicate {artifact_kind}",
        )


def print_component_not_found_error(component_id: str) -> None:
    """
    Print a styled error panel for component not found error.

    This provides a clear, user-friendly error message when the specified
    component does not exist in sbomify, with suggested solutions.

    Args:
        component_id: The component ID that was not found
    """
    content = Text()
    content.append("The specified component does not exist.\n\n", style="bold")
    content.append("Details:\n", style="cyan")
    content.append(f"  Component ID: {component_id}\n\n")
    content.append("Possible solutions:\n", style="cyan")
    content.append("  1. Verify your COMPONENT_ID matches the one in your sbomify dashboard\n")
    content.append("  2. Check that the component exists in your sbomify account\n")
    content.append("  3. Create the component in the sbomify dashboard if it doesn't exist\n")
    content.append("  4. Ensure your API token has access to this component\n")

    panel = Panel(content, title="[bold red]Component Not Found[/bold red]", border_style="red")
    console.print(panel)

    # Also emit GHA error annotation
    gha_error(
        f"Component '{component_id}' not found. Verify the COMPONENT_ID is correct.",
        title="Component Not Found",
    )


def print_final_success() -> None:
    """Print final success message."""
    console.print()
    _formatter().final_success()
    console.print()


def print_final_failure(message: str) -> None:
    """Print final failure message."""
    console.print()
    formatter = _formatter()
    formatter.error(message, "SBOM Processing Failed")
    formatter.final_failure(message)
    console.print()


@dataclass
class AuditEntry:
    """A single audit trail entry recording an SBOM modification."""

    timestamp: str
    category: str  # AUGMENTATION, ENRICHMENT, SANITIZATION, OVERRIDE
    operation: str  # added, modified, normalized, cleared, rejected
    field: str  # e.g., supplier.name, license, description
    new_value: Optional[str] = None
    old_value: Optional[str] = None
    component: Optional[str] = None  # PURL or component name for component-level changes
    source: Optional[str] = None  # e.g., sbomify-api, pypi, depsdev

    def format_for_file(self) -> str:
        """Format entry for audit_trail.txt file."""
        parts = [f"[{self.timestamp}]", self.category, self.field, self.operation.upper()]

        if self.component:
            parts.insert(2, self.component)

        if self.old_value and self.new_value:
            parts.append(f'"{self.old_value}" -> "{self.new_value}"')
        elif self.new_value:
            # Truncate very long values for readability
            display_value = self.new_value[:200] + "..." if len(self.new_value) > 200 else self.new_value
            parts.append(f'"{display_value}"')

        if self.source:
            parts.append(f"(source: {self.source})")

        return " ".join(parts)

    def format_for_summary(self) -> str:
        """Format entry for stdout summary (shorter)."""
        if self.component:
            return f"{self.field}: {self.component}"
        elif self.new_value:
            display_value = self.new_value[:50] + "..." if len(self.new_value) > 50 else self.new_value
            return f"{self.field}: {display_value}"
        return self.field


@dataclass
class AuditTrail:
    """
    Comprehensive audit trail for all SBOM modifications.

    Tracks every change made to an SBOM during processing for attestation purposes.
    Outputs:
    - Clean summary to stdout (always visible)
    - Detailed audit_trail.txt file
    - Full details in collapsible GitHub Actions group

    Categories of changes tracked:
    - AUGMENTATION: supplier, manufacturer, authors, licenses, VCS info, lifecycle, tool metadata
    - ENRICHMENT: descriptions, licenses, publishers, external refs per component
    - SANITIZATION: VCS URLs, PURLs, URLs normalized/cleared/rejected
    - OVERRIDE: component name, version, PURL overrides from CLI/env
    """

    entries: List[AuditEntry] = field(default_factory=list)
    input_file: Optional[str] = None
    output_file: Optional[str] = None
    start_time: Optional[str] = None

    # Counters for summary
    _augmentation_count: int = 0
    _enrichment_count: int = 0
    _sanitization_count: int = 0
    _override_count: int = 0

    # Legacy compatibility fields (for TransformationTracker interface)
    vcs_normalizations: List[Tuple[str, str]] = field(default_factory=list)
    purl_normalizations: List[Tuple[str, str, str]] = field(default_factory=list)
    purls_cleared: List[Tuple[str, str, str]] = field(default_factory=list)
    urls_rejected: List[Tuple[str, str, str]] = field(default_factory=list)
    stubs_added: List[Tuple[str, str, str]] = field(default_factory=list)
    root_dependencies_linked: List[Tuple[str, int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Initialize start time."""
        from datetime import datetime, timezone

        self.start_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _get_timestamp(self) -> str:
        """Get current UTC timestamp."""
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _add_entry(
        self,
        category: str,
        operation: str,
        field: str,
        new_value: Optional[str] = None,
        old_value: Optional[str] = None,
        component: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        """Add an entry to the audit trail."""
        entry = AuditEntry(
            timestamp=self._get_timestamp(),
            category=category,
            operation=operation,
            field=field,
            new_value=new_value,
            old_value=old_value,
            component=component,
            source=source,
        )
        self.entries.append(entry)

    # ==========================================================================
    # Augmentation Recording
    # ==========================================================================

    def record_augmentation(
        self,
        field: str,
        value: str,
        old_value: Optional[str] = None,
        source: str = "sbomify-api",
    ) -> None:
        """Record an augmentation change (supplier, manufacturer, etc.)."""
        operation = "modified" if old_value else "added"
        self._add_entry("AUGMENTATION", operation, field, value, old_value, source=source)
        self._augmentation_count += 1

    def record_supplier_added(self, name: str, source: str = "sbomify-api") -> None:
        """Record supplier information added."""
        self.record_augmentation("supplier.name", name, source=source)

    def record_manufacturer_added(self, name: str, source: str = "sbomify-api") -> None:
        """Record manufacturer information added."""
        self.record_augmentation("manufacturer.name", name, source=source)

    def record_author_added(self, name: str, email: Optional[str] = None, source: str = "sbomify-api") -> None:
        """Record author added."""
        value = f"{name} ({email})" if email else name
        self.record_augmentation("author", value, source=source)

    def record_license_added(self, license_expr: str, source: str = "sbomify-api") -> None:
        """Record license added to metadata."""
        self.record_augmentation("metadata.license", license_expr, source=source)

    def record_vcs_info_added(self, url: str, commit: Optional[str] = None, source: str = "ci-provider") -> None:
        """Record VCS information added."""
        value = f"{url}@{commit[:7]}" if commit else url
        self.record_augmentation("vcs.url", value, source=source)

    def record_lifecycle_added(self, phase: str, source: str = "sbomify-api") -> None:
        """Record lifecycle phase added."""
        self.record_augmentation("lifecycle.phase", phase, source=source)

    def record_tool_added(self, tool_name: str, version: str) -> None:
        """Record tool added to SBOM metadata."""
        self.record_augmentation("tools", f"{tool_name}@{version}", source="sbomify-action")

    # ==========================================================================
    # Enrichment Recording
    # ==========================================================================

    def record_enrichment(
        self,
        component: str,
        field: str,
        value: str,
        source: str,
    ) -> None:
        """Record a component enrichment."""
        self._add_entry("ENRICHMENT", "added", field, value, component=component, source=source)
        self._enrichment_count += 1

    def record_component_enriched(
        self,
        purl: str,
        fields_added: List[str],
        source: str,
    ) -> None:
        """Record multiple fields enriched on a component."""
        for field_name in fields_added:
            self._add_entry("ENRICHMENT", "added", field_name, component=purl, source=source)
        self._enrichment_count += len(fields_added)

    def record_hash_added(
        self,
        component: str,
        algorithm: str,
        source: str = "lockfile",
    ) -> None:
        """Record a hash added to a component from lockfile."""
        self._add_entry("ENRICHMENT", "added", f"hash.{algorithm}", component=component, source=source)
        self._enrichment_count += 1

    # ==========================================================================
    # Sanitization Recording (Legacy compatibility + new interface)
    # ==========================================================================

    def record_vcs_normalization(self, original: str, normalized: str) -> None:
        """Record a VCS URL normalization."""
        self.vcs_normalizations.append((original, normalized))
        self._add_entry("SANITIZATION", "normalized", "vcs.url", normalized, original)
        self._sanitization_count += 1

    def record_purl_normalization(self, component_name: str, original: str, normalized: str) -> None:
        """Record a PURL normalization."""
        self.purl_normalizations.append((component_name, original, normalized))
        self._add_entry("SANITIZATION", "normalized", "purl", normalized, original, component=component_name)
        self._sanitization_count += 1

    def record_purl_cleared(self, component_name: str, purl: str, reason: str) -> None:
        """Record a PURL that was cleared due to being invalid."""
        self.purls_cleared.append((component_name, purl, reason))
        self._add_entry("SANITIZATION", "cleared", "purl", reason, purl, component=component_name)
        self._sanitization_count += 1

    def record_url_rejected(self, field_name: str, url: str, reason: str) -> None:
        """Record a URL that was rejected during sanitization."""
        self.urls_rejected.append((field_name, url, reason))
        self._add_entry("SANITIZATION", "rejected", field_name, reason, url)
        self._sanitization_count += 1

    def record_stub_added(self, ref_value: str, component_name: str, version: str) -> None:
        """Record a stub component added for orphaned dependency reference."""
        self.stubs_added.append((ref_value, component_name, version))
        self._add_entry("SANITIZATION", "stub_added", "component", f"{component_name}@{version}", component=ref_value)
        self._sanitization_count += 1

    def record_root_dependencies_linked(self, root_name: str, count: int) -> None:
        """Record root dependencies linking (components linked to root component)."""
        self.root_dependencies_linked.append((root_name, count))
        self._add_entry("SANITIZATION", "linked", "dependencies", f"{count} components linked to root '{root_name}'")
        self._sanitization_count += 1

    def record_license_sanitized(self, original: str, sanitized: str, component: Optional[str] = None) -> None:
        """Record a license expression sanitized."""
        self._add_entry("SANITIZATION", "sanitized", "license", sanitized, original, component=component)
        self._sanitization_count += 1

    # ==========================================================================
    # Override Recording
    # ==========================================================================

    def record_override(self, field: str, new_value: str, old_value: Optional[str] = None) -> None:
        """Record a CLI/env override applied."""
        operation = "modified" if old_value else "set"
        self._add_entry("OVERRIDE", operation, field, new_value, old_value, source="cli/env")
        self._override_count += 1

    def record_component_name_override(self, new_name: str, old_name: Optional[str] = None) -> None:
        """Record component name override."""
        self.record_override("component.name", new_name, old_name)

    def record_component_version_override(self, new_version: str, old_version: Optional[str] = None) -> None:
        """Record component version override."""
        self.record_override("component.version", new_version, old_version)

    def record_component_purl_override(self, new_purl: str, old_purl: Optional[str] = None) -> None:
        """Record component PURL override."""
        self.record_override("component.purl", new_purl, old_purl)

    # ==========================================================================
    # Query Methods
    # ==========================================================================

    def has_changes(self) -> bool:
        """Check if any changes were recorded."""
        return len(self.entries) > 0

    # Legacy compatibility
    def has_transformations(self) -> bool:
        """Check if any transformations were recorded (legacy compatibility)."""
        return self.has_changes()

    def get_summary_counts(self) -> Dict[str, int]:
        """Get counts by category."""
        return {
            "augmentation": self._augmentation_count,
            "enrichment": self._enrichment_count,
            "sanitization": self._sanitization_count,
            "override": self._override_count,
            "total": len(self.entries),
        }

    def get_entries_by_category(self, category: str) -> List[AuditEntry]:
        """Get all entries for a specific category."""
        return [e for e in self.entries if e.category == category]

    # ==========================================================================
    # Output Methods
    # ==========================================================================

    def write_audit_file(self, path: str) -> None:
        """
        Write detailed audit trail to file.

        Args:
            path: Path to write audit_trail.txt
        """
        from datetime import datetime, timezone

        lines = [
            "# SBOM Audit Trail",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        ]

        if self.input_file:
            lines.append(f"# Input: {self.input_file}")
        if self.output_file:
            lines.append(f"# Output: {self.output_file}")

        lines.append("")

        # Group entries by category
        categories = ["OVERRIDE", "AUGMENTATION", "ENRICHMENT", "SANITIZATION"]

        for category in categories:
            category_entries = self.get_entries_by_category(category)
            if category_entries:
                lines.append(f"## {category.title()}")
                lines.append("")
                for entry in category_entries:
                    lines.append(entry.format_for_file())
                lines.append("")

        # Write file
        with open(path, "w") as f:
            f.write("\n".join(lines))

    def print_summary(self, title: str = "SBOM Modifications") -> None:
        """
        Print a clean summary to stdout.

        Shows counts by category and key changes.
        """
        if not self.has_changes():
            console.print("[dim]No SBOM modifications recorded.[/dim]")
            return

        console.print()
        console.rule(f"[bold]{title}[/bold]", style="blue")

        counts = self.get_summary_counts()

        # Build summary data
        data = []
        if counts["override"]:
            data.append(("Overrides applied", counts["override"]))
        if counts["augmentation"]:
            data.append(("Augmentation changes", counts["augmentation"]))
        if counts["enrichment"]:
            data.append(("Components enriched", counts["enrichment"]))
        if counts["sanitization"]:
            data.append(("Sanitization fixes", counts["sanitization"]))

        if data:
            print_summary_table("Summary", data)

    def print_to_stdout_for_attestation(self) -> None:
        """
        Print the full audit trail to stdout for attestation.

        Uses GitHub Actions collapsible group to keep output tidy.
        """
        if not self.has_changes():
            return

        with gha_group("Audit Trail (for attestation)"):
            print("# SBOM Audit Trail")
            print(f"# Generated: {self._get_timestamp()}")
            if self.input_file:
                print(f"# Input: {self.input_file}")
            if self.output_file:
                print(f"# Output: {self.output_file}")
            print()

            # Group and print by category
            categories = ["OVERRIDE", "AUGMENTATION", "ENRICHMENT", "SANITIZATION"]

            for category in categories:
                category_entries = self.get_entries_by_category(category)
                if category_entries:
                    print(f"## {category.title()}")
                    for entry in category_entries:
                        print(entry.format_for_file())
                    print()

    # Legacy compatibility method
    def _format_details(self) -> List[str]:
        """Format all transformations as detail strings (legacy compatibility)."""
        details = []

        for original, normalized in self.vcs_normalizations:
            details.append(f"VCS: {original} -> {normalized}")

        for comp_name, original, normalized in self.purl_normalizations:
            details.append(f"PURL normalized ({comp_name}): {original} -> {normalized}")

        for comp_name, purl, reason in self.purls_cleared:
            details.append(f"PURL cleared ({comp_name}): {purl} ({reason})")

        for field_name, url, reason in self.urls_rejected:
            url_display = url[:100] + "..." if len(url) > 100 else url
            details.append(f"URL rejected ({field_name}): {url_display} ({reason})")

        for ref_value, comp_name, version in self.stubs_added:
            details.append(f"Stub added: {comp_name}@{version} (ref: {ref_value})")

        for root_name, count in self.root_dependencies_linked:
            details.append(f"Linked {count} components to root '{root_name}'")

        return details


# Alias for backward compatibility
TransformationTracker = AuditTrail


# Thread-safe audit trail using contextvars
# This ensures each thread/async context has its own tracker instance
_current_tracker: contextvars.ContextVar[Optional[AuditTrail]] = contextvars.ContextVar("audit_trail", default=None)


def get_audit_trail() -> AuditTrail:
    """
    Get the current audit trail, creating one if needed.

    Thread-safe: Each thread/async context gets its own instance.

    Returns:
        The current AuditTrail instance
    """
    tracker = _current_tracker.get()
    if tracker is None:
        tracker = AuditTrail()
        _current_tracker.set(tracker)
    return tracker


# Alias for backward compatibility
def get_transformation_tracker() -> AuditTrail:
    """
    Get the current transformation tracker (alias for get_audit_trail).

    Thread-safe: Each thread/async context gets its own tracker.

    Returns:
        The current AuditTrail instance
    """
    return get_audit_trail()


def reset_audit_trail() -> AuditTrail:
    """
    Reset the audit trail for a new SBOM processing run.

    Thread-safe: Only affects the current thread/async context.

    Returns:
        A fresh AuditTrail instance
    """
    tracker = AuditTrail()
    _current_tracker.set(tracker)
    return tracker


# Alias for backward compatibility
def reset_transformation_tracker() -> AuditTrail:
    """
    Reset the transformation tracker (alias for reset_audit_trail).

    Thread-safe: Only affects the current thread/async context.

    Returns:
        A fresh AuditTrail instance
    """
    return reset_audit_trail()


def print_transformation_summary() -> None:
    """Print the current audit trail summary (legacy compatibility)."""
    tracker = get_audit_trail()
    tracker.print_summary()
