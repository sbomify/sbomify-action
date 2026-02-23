"""Batch orchestrator for Yocto SPDX pipeline."""

import json
import shutil

from rich.table import Table

from sbomify_action._processors.releases_api import create_release, tag_sbom_with_release
from sbomify_action.augmentation import augment_sbom_from_file
from sbomify_action.console import console
from sbomify_action.enrichment import enrich_sbom
from sbomify_action.exceptions import APIError, ConfigurationError, PlanLimitError
from sbomify_action.logging_config import logger
from sbomify_action.spdx3 import is_spdx3
from sbomify_action.upload import upload_sbom

from .api import get_or_create_component, list_components, patch_component_visibility
from .archive import extract_archive
from .models import YoctoConfig, YoctoPipelineResult
from .parser import discover_packages


def _process_single_package(
    pkg_name: str,
    pkg_spdx_file: str,
    component_id: str,
    config: YoctoConfig,
) -> str | None:
    """Process a single package SBOM: augment, enrich, upload.

    Returns:
        sbom_id if uploaded successfully, None otherwise.

    Raises:
        Exception: Propagated from augmentation/enrichment/upload.
    """
    working_file = pkg_spdx_file

    if config.augment:
        augmented_file = pkg_spdx_file + ".augmented.json"
        augment_sbom_from_file(
            input_file=working_file,
            output_file=augmented_file,
            api_base_url=config.api_base_url,
            token=config.token,
            component_id=component_id,
            validate=False,
        )
        working_file = augmented_file

    if config.enrich:
        enriched_file = pkg_spdx_file + ".enriched.json"
        enrich_sbom(
            input_file=working_file,
            output_file=enriched_file,
            validate=False,
        )
        working_file = enriched_file

    result = upload_sbom(
        sbom_file=working_file,
        sbom_format="spdx",
        token=config.token,
        component_id=component_id,
        api_base_url=config.api_base_url,
        validate_before_upload=False,
    )

    if result.success and result.sbom_id:
        return result.sbom_id

    # 409 DUPLICATE_ARTIFACT is a benign skip
    if result.error_code == "DUPLICATE_ARTIFACT":
        logger.info(f"SBOM for '{pkg_name}' already exists, skipping")
        return None

    if not result.success:
        raise APIError(f"Upload failed for '{pkg_name}': {result.error_message}")

    # Upload reported success but no SBOM ID was returned
    raise APIError(
        f"Upload reported success for '{pkg_name}' but no SBOM ID was returned; "
        "this likely indicates a malformed response from the upload destination."
    )


def _print_summary(result: YoctoPipelineResult) -> None:
    """Print a Rich summary table of the pipeline run."""
    table = Table(title="Yocto Pipeline Summary", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Packages found", str(result.packages_found))
    table.add_row("Components created", str(result.components_created))
    table.add_row("SBOMs uploaded", str(result.sboms_uploaded), style="green" if result.sboms_uploaded else "")
    table.add_row("SBOMs skipped", str(result.sboms_skipped), style="yellow" if result.sboms_skipped else "")
    table.add_row("Errors", str(result.errors), style="red" if result.errors else "")
    if result.release_id:
        table.add_row("Release ID", result.release_id)

    console.print(table)


def _detect_spdx3(input_path: str) -> dict | None:
    """If *input_path* is an SPDX 3 JSON-LD file, return parsed data; else None."""
    if not input_path.endswith((".json", ".spdx.json")):
        return None
    try:
        with open(input_path) as f:
            data = json.load(f)
        if isinstance(data, dict) and is_spdx3(data):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _run_spdx3_pipeline(config: YoctoConfig, data: dict) -> YoctoPipelineResult:
    """Single-file SPDX 3 pipeline: augment, enrich, upload, release-tag."""
    if not config.component_id:
        raise ConfigurationError(
            "SPDX 3 single-file mode requires --component-id. Specify the sbomify component ID to upload this SBOM to."
        )

    graph = data.get("@graph", [])
    pkg_count = sum(
        1
        for el in graph
        if isinstance(el, dict) and (el.get("type") or el.get("@type")) in ("software_Package", "Package")
    )
    console.print(f"\n[bold]SPDX 3 single file:[/bold] {config.input_path}")
    console.print(f"  {len(graph)} elements, {pkg_count} packages")

    result = YoctoPipelineResult(packages_found=pkg_count)

    if config.dry_run:
        console.print("\n[bold yellow]DRY RUN[/bold yellow] - no API calls will be made")
        console.print(f"  Would upload to component {config.component_id}")
        result.sboms_skipped = 1
        _print_summary(result)
        return result

    try:
        sbom_id = _process_single_package(
            pkg_name="spdx3-image",
            pkg_spdx_file=config.input_path,
            component_id=config.component_id,
            config=config,
        )

        if sbom_id:
            result.sboms_uploaded = 1

            console.print(f"\n[bold]Creating release:[/bold] {config.product_id}:{config.release_version}")
            release_id = create_release(config.api_base_url, config.token, config.product_id, config.release_version)
            if release_id:
                result.release_id = release_id
                tag_sbom_with_release(config.api_base_url, config.token, sbom_id, release_id)
                console.print(f"  Tagged SBOM with release {release_id}")
        else:
            result.sboms_skipped = 1

    except Exception as e:
        result.errors += 1
        result.error_messages.append(str(e))
        logger.error(f"SPDX 3 pipeline error: {e}")

    _print_summary(result)
    return result


def run_yocto_pipeline(config: YoctoConfig) -> YoctoPipelineResult:
    """Run the full Yocto batch pipeline.

    For SPDX 3 single JSON-LD files (Yocto 5.0+), uploads as one SBOM
    to the component specified by --component-id.

    For SPDX 2.2 archives (.spdx.tar.zst/.tar.gz), extracts and processes
    each package SBOM individually.

    Args:
        config: Pipeline configuration

    Returns:
        YoctoPipelineResult with summary statistics
    """
    # Detect SPDX 3 single-file input
    spdx3_data = _detect_spdx3(config.input_path)
    if spdx3_data is not None:
        return _run_spdx3_pipeline(config, spdx3_data)

    result = YoctoPipelineResult()
    extract_dir = None

    try:
        # Step 1: Extract
        console.print(f"\n[bold]Extracting archive:[/bold] {config.input_path}")
        extract_dir = extract_archive(config.input_path)

        # Step 2: Discover packages
        console.print("[bold]Discovering packages...[/bold]")
        packages = discover_packages(extract_dir)
        if config.max_packages and len(packages) > config.max_packages:
            console.print(f"  Found {len(packages)} package SBOMs, limiting to {config.max_packages}")
            packages = packages[: config.max_packages]
        result.packages_found = len(packages)
        console.print(f"  Processing {len(packages)} package SBOMs")

        if config.dry_run:
            console.print("\n[bold yellow]DRY RUN[/bold yellow] - no API calls will be made")
            for pkg in packages:
                console.print(f"  Would process: {pkg.name} {pkg.version}")
            result.sboms_skipped = len(packages)
            _print_summary(result)
            return result

        # Step 3: Cache existing components
        console.print("[bold]Fetching existing components...[/bold]")
        component_cache = list_components(config.api_base_url, config.token)

        # Step 4: Process each package
        collected_sbom_ids: list[str] = []

        for i, pkg in enumerate(packages, 1):
            console.print(f"  [{i}/{len(packages)}] Processing {pkg.name} {pkg.version}...")

            try:
                comp_id, was_created = get_or_create_component(
                    config.api_base_url, config.token, pkg.name, component_cache
                )
                if was_created:
                    result.components_created += 1
                    if config.visibility:
                        patch_component_visibility(
                            config.api_base_url, config.token, comp_id, config.visibility
                        )

                sbom_id = _process_single_package(pkg.name, pkg.spdx_file, comp_id, config)

                if sbom_id:
                    collected_sbom_ids.append(sbom_id)
                    result.sboms_uploaded += 1
                else:
                    result.sboms_skipped += 1

            except PlanLimitError as e:
                remaining = len(packages) - i
                result.errors += 1
                result.error_messages.append(str(e))
                logger.error(str(e))
                console.print(
                    f"\n[bold red]Plan limit reached.[/bold red] Stopping pipeline ({remaining} packages remaining).\n"
                    "Upgrade your plan or reduce the number of components to continue."
                )
                break

            except Exception as e:
                result.errors += 1
                result.error_messages.append(f"{pkg.name}: {e}")
                logger.error(f"Error processing {pkg.name}: {e}")

        # Step 5: Release tagging
        if collected_sbom_ids:
            console.print(f"\n[bold]Creating release:[/bold] {config.product_id}:{config.release_version}")
            try:
                release_id = create_release(
                    config.api_base_url, config.token, config.product_id, config.release_version
                )
                if release_id:
                    result.release_id = release_id
                    for sbom_id in collected_sbom_ids:
                        tag_sbom_with_release(config.api_base_url, config.token, sbom_id, release_id)
                    console.print(f"  Tagged {len(collected_sbom_ids)} SBOMs with release {release_id}")
            except APIError as e:
                result.errors += 1
                result.error_messages.append(f"Release tagging: {e}")
                logger.error(f"Failed to create/tag release: {e}")

        _print_summary(result)

    finally:
        # Clean up temp directory
        if extract_dir:
            try:
                shutil.rmtree(extract_dir, ignore_errors=True)
            except Exception:
                pass

    return result
