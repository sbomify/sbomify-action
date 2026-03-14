"""SPDX 2.2 parsing and package discovery for Yocto builds."""

import hashlib
import json
from pathlib import Path
from typing import Any

from sbomify_action.exceptions import FileProcessingError
from sbomify_action.logging_config import logger

from .models import YoctoPackage


def _compute_sha256(data: dict[str, Any]) -> str:
    """Compute SHA256 of parsed JSON data with normalized content (sorted keys)."""
    normalized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode()).hexdigest()


def _is_spdx_22(data: dict[str, Any]) -> bool:
    """Check if a parsed SPDX document is version 2.2."""
    return data.get("spdxVersion") == "SPDX-2.2"


def _is_rootfs_manifest(file_path: Path, data: dict[str, Any]) -> bool:
    """Check if an SPDX document is the rootfs manifest.

    The rootfs manifest is the image-level index that references all packages.
    It is identified by having ".rootfs" in its document name or in the SPDX
    filename. While rootfs manifests typically have many externalDocumentRefs,
    this function only uses the ".rootfs" pattern for detection.
    """
    name = data.get("name", "")
    # Yocto rootfs names contain ".rootfs" (e.g. "core-image-base-qemux86-64.rootfs-20260214054917")
    if ".rootfs" in name:
        return True
    # Also check filename pattern
    if ".rootfs" in file_path.name:
        return True
    return False


def _categorize_document(file_path: Path, data: dict[str, Any]) -> str:
    """Categorize an SPDX document as rootfs, recipe, runtime, or package.

    Returns one of: "rootfs", "recipe", "runtime", "package"
    """
    name = data.get("name", "")
    if name.startswith("recipe-"):
        return "recipe"
    if name.startswith("runtime-"):
        return "runtime"
    if _is_rootfs_manifest(file_path, data):
        return "rootfs"

    return "package"


def _extract_package_info(file_path: str, data: dict[str, Any]) -> YoctoPackage:
    """Extract package info from an SPDX 2.2 document."""
    name = data.get("name", Path(file_path).stem)
    namespace = data.get("documentNamespace", "")

    # Extract version from the first package in the document
    version = ""
    packages = data.get("packages", [])
    if packages:
        version = packages[0].get("versionInfo", "")

    sha256 = _compute_sha256(data)

    return YoctoPackage(
        name=name,
        version=version,
        spdx_file=file_path,
        document_namespace=namespace,
        sha256=sha256,
    )


def discover_packages(extract_dir: str) -> list[YoctoPackage]:
    """Discover package SBOMs from extracted Yocto SPDX output.

    Scans for *.spdx.json files, identifies the rootfs manifest,
    skips recipe-* and runtime-* documents, and returns package SBOMs.

    Args:
        extract_dir: Directory containing extracted SPDX files

    Returns:
        List of YoctoPackage objects for package SBOMs

    Raises:
        FileProcessingError: If no valid SPDX 2.2 content is found
    """
    extract_path = Path(extract_dir)
    spdx_files = sorted(extract_path.rglob("*.spdx.json"))

    if not spdx_files:
        raise FileProcessingError(f"No .spdx.json files found in {extract_dir}")

    packages: list[YoctoPackage] = []
    rootfs_found = False
    skipped_recipe = 0
    skipped_runtime = 0
    skipped_non_spdx22 = 0

    for spdx_file in spdx_files:
        try:
            with open(spdx_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Skipping {spdx_file.name}: {e}")
            continue

        if not _is_spdx_22(data):
            skipped_non_spdx22 += 1
            logger.debug(f"Skipping non-SPDX-2.2 file: {spdx_file.name}")
            continue

        category = _categorize_document(spdx_file, data)

        if category == "rootfs":
            rootfs_found = True
            logger.info(f"Found rootfs manifest: {spdx_file.name}")
        elif category == "recipe":
            skipped_recipe += 1
        elif category == "runtime":
            skipped_runtime += 1
        elif category == "package":
            pkg = _extract_package_info(str(spdx_file), data)
            packages.append(pkg)

    logger.info(
        f"Discovery: {len(packages)} packages, "
        f"rootfs={'yes' if rootfs_found else 'no'}, "
        f"skipped {skipped_recipe} recipes, {skipped_runtime} runtime, "
        f"{skipped_non_spdx22} non-SPDX-2.2"
    )

    if not packages:
        raise FileProcessingError("No package SBOMs found in extracted archive")

    return packages
