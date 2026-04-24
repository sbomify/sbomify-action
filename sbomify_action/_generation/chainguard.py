"""Chainguard base image detection and SBOM reuse.

Detects Chainguard images (direct or as base images in user-built images),
downloads their SPDX SBOMs from cosign attestations, and converts to CycloneDX.
"""

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.tool import Tool
from packageurl import PackageURL

from sbomify_action.logging_config import logger
from sbomify_action.serialization import serialize_cyclonedx_bom

from . import buildkit_provenance as bkp

# Re-export internals referenced by tests. Keep these as thin aliases so test
# imports (``from sbomify_action._generation.chainguard import _extract_repo``)
# continue to resolve after the shared-helper extraction.
_extract_repo = bkp.extract_repo
_parse_purl_docker_uri = bkp.parse_purl_docker_uri


@dataclass
class ChainguardBaseImage:
    """Information about a detected Chainguard base image."""

    image_ref: str  # e.g., "cgr.dev/chainguard/python"
    digest: str  # per-architecture digest, e.g., "sha256:242e08c..."


def _is_chainguard_config(image_ref: str) -> bool:
    """Check if an image config indicates a Chainguard image."""
    try:
        config_json = bkp.run_crane(["config", image_ref])
        config = json.loads(config_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch config for {image_ref}: {e}")
        return False

    if config.get("author") == "github.com/chainguard-dev/apko":
        return True

    labels = config.get("config", {}).get("Labels", {})
    if "dev.chainguard.image.title" in labels:
        return True

    return False


def _detect_direct_chainguard(docker_image: str) -> ChainguardBaseImage | None:
    """Detect if the image is directly from cgr.dev/chainguard/."""
    if not docker_image.startswith("cgr.dev/chainguard/"):
        return None

    logger.debug(f"Image ref starts with cgr.dev/chainguard/, verifying: {docker_image}")

    if not _is_chainguard_config(docker_image):
        logger.debug(f"Image config does not match Chainguard pattern: {docker_image}")
        return None

    digest = bkp.resolve_platform_digest(docker_image)
    if not digest:
        logger.warning(f"Could not resolve platform digest for {docker_image}")
        return None

    return ChainguardBaseImage(image_ref=bkp.extract_repo(docker_image), digest=digest)


def _detect_chainguard_from_provenance(docker_image: str) -> ChainguardBaseImage | None:
    """Detect Chainguard base image by parsing BuildKit SLSA provenance."""
    statement = bkp.fetch_build_provenance(docker_image)
    if statement is None:
        return None

    for dep in bkp.iter_resolved_dependencies(statement):
        uri = dep.get("uri", "")
        if "cgr.dev/chainguard/" not in uri:
            continue

        parsed = bkp.parse_purl_docker_uri(uri)
        if not parsed:
            continue

        image_ref, digest = parsed
        logger.info(f"Found Chainguard base image in provenance: {image_ref}@{digest}")

        platform_digest = bkp.resolve_platform_digest(f"{image_ref}@{digest}") or digest
        return ChainguardBaseImage(image_ref=image_ref, digest=platform_digest)

    logger.debug(f"No Chainguard base image found in provenance for {docker_image}")
    return None


def detect_chainguard_image(docker_image: str) -> ChainguardBaseImage | None:
    """Detect if a Docker image is or is built FROM a Chainguard image.

    Tries two detection paths:
    1. Direct: image ref starts with cgr.dev/chainguard/
    2. Provenance: parse BuildKit SLSA provenance for Chainguard base images

    Returns ChainguardBaseImage with the per-architecture digest, or None if not detected.
    Requires crane to be available on PATH.
    """
    if not bkp.crane_available():
        logger.debug("crane not found on PATH, skipping Chainguard detection")
        return None

    result = _detect_direct_chainguard(docker_image)
    if result:
        return result

    return _detect_chainguard_from_provenance(docker_image)


def fetch_chainguard_sbom(info: ChainguardBaseImage) -> dict[str, Any]:
    """Download the SPDX SBOM from a Chainguard image's cosign attestation."""
    if not bkp.cosign_available():
        raise RuntimeError("cosign not found on PATH, cannot fetch Chainguard SBOM")

    image_with_digest = f"{info.image_ref}@{info.digest}"
    logger.info(f"Fetching Chainguard SBOM for {image_with_digest}")

    predicate = bkp.fetch_cosign_spdx_predicate(image_with_digest)
    if predicate is None:
        raise RuntimeError(f"No SPDX SBOM found in attestations for {image_with_digest}")

    pkg_count = len(predicate.get("packages", []))
    logger.info(f"Found Chainguard SPDX SBOM with {pkg_count} packages")
    return predicate


# CycloneDX hash algorithm mapping from SPDX algorithm names
_SPDX_TO_CDX_HASH_ALG: dict[str, HashAlgorithm] = {
    "SHA256": HashAlgorithm.SHA_256,
    "SHA384": HashAlgorithm.SHA_384,
    "SHA512": HashAlgorithm.SHA_512,
    "SHA1": HashAlgorithm.SHA_1,
    "MD5": HashAlgorithm.MD5,
}


def convert_spdx_to_cyclonedx(spdx_doc: dict[str, Any], spec_version: str = "1.6") -> str:
    """Convert an SPDX 2.x SBOM dict to CycloneDX JSON.

    Handles the simple package shape (PURLs, checksums, supplier, description).
    Generic enough to use on any SPDX 2.x doc (Chainguard, Docker Hub, etc.).

    Args:
        spdx_doc: SPDX document dict
        spec_version: Target CycloneDX spec version (default "1.6")

    Returns:
        CycloneDX JSON string
    """
    bom = Bom()

    creation_info = spdx_doc.get("creationInfo", {})
    created = creation_info.get("created")
    if created:
        try:
            bom.metadata.timestamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            pass

    for creator in creation_info.get("creators", []):
        if creator.startswith("Tool:"):
            tool_name = creator[len("Tool:") :].strip()
            bom.metadata.tools.tools.add(Tool(name=tool_name))

    described_ids = set(spdx_doc.get("documentDescribes", []))

    components: list[Component] = []
    main_component: Component | None = None

    for pkg in spdx_doc.get("packages", []):
        spdx_id = pkg.get("SPDXID", "")
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")

        purl_str = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl_str = ref.get("referenceLocator", "")
                break

        purpose = pkg.get("primaryPackagePurpose", "")
        if purpose == "CONTAINER":
            comp_type = ComponentType.CONTAINER
        elif purpose == "OPERATING_SYSTEM":
            comp_type = ComponentType.OPERATING_SYSTEM
        else:
            comp_type = ComponentType.LIBRARY

        comp = Component(
            type=comp_type,
            name=name,
            version=version if version else None,
            bom_ref=spdx_id,
        )

        if purl_str:
            try:
                comp.purl = PackageURL.from_string(purl_str)
            except ValueError:
                pass

        supplier_str = pkg.get("supplier", "")
        if supplier_str and supplier_str != "NOASSERTION":
            if supplier_str.startswith("Organization:"):
                org_name = supplier_str[len("Organization:") :].strip()
                comp.supplier = OrganizationalEntity(name=org_name)

        for checksum in pkg.get("checksums", []):
            alg = checksum.get("algorithm", "")
            value = checksum.get("checksumValue", "")
            cdx_alg = _SPDX_TO_CDX_HASH_ALG.get(alg)
            if cdx_alg and value:
                comp.hashes.add(HashType(alg=cdx_alg, content=value))

        description = pkg.get("description", "")
        if description:
            comp.description = description

        if spdx_id in described_ids and main_component is None:
            main_component = comp
        else:
            components.append(comp)

    if main_component:
        bom.metadata.component = main_component

    for comp in components:
        bom.components.add(comp)

    return serialize_cyclonedx_bom(bom, spec_version)
