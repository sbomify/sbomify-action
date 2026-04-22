"""Chainguard base image detection and SBOM reuse.

Detects Chainguard images (direct or as base images in user-built images),
downloads their SPDX SBOMs from cosign attestations, and converts to CycloneDX.
"""

import base64
import json
import platform
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote

from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.tool import Tool
from packageurl import PackageURL

from sbomify_action.logging_config import logger
from sbomify_action.serialization import serialize_cyclonedx_bom


@dataclass
class ChainguardBaseImage:
    """Information about a detected Chainguard base image."""

    image_ref: str  # e.g., "cgr.dev/chainguard/python"
    digest: str  # per-architecture digest, e.g., "sha256:242e08c..."


def _get_current_platform() -> str:
    """Get the current platform in OCI format (e.g., 'linux/amd64')."""
    import os

    # Check environment variable first (CI environments may set this)
    target_arch = os.environ.get("TARGETARCH")
    if target_arch:
        return f"linux/{target_arch}"

    machine = platform.machine()
    arch_map = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(machine, machine)
    return f"linux/{arch}"


def _run_crane(args: list[str]) -> str:
    """Run a crane command and return stdout."""
    cmd = ["crane"] + args
    logger.debug(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
    return result.stdout


def _run_cosign(args: list[str]) -> str:
    """Run a cosign command and return stdout."""
    cmd = ["cosign"] + args
    logger.debug(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
    return result.stdout


def _resolve_platform_digest(image_ref: str) -> str | None:
    """Resolve an image reference to a platform-specific manifest digest.

    If the image is a manifest list (multi-arch), resolves to the current platform.
    If it's already a single manifest, returns its digest.
    """
    current_platform = _get_current_platform()
    os_name, arch = current_platform.split("/")

    try:
        manifest_json = _run_crane(["manifest", image_ref])
        manifest = json.loads(manifest_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch manifest for {image_ref}: {e}")
        return None

    # Check if this is a manifest list / OCI image index
    media_type = manifest.get("mediaType", "")
    if "manifest.list" in media_type or "image.index" in media_type:
        for entry in manifest.get("manifests", []):
            p = entry.get("platform", {})
            if p.get("os") == os_name and p.get("architecture") == arch:
                return entry["digest"]
        logger.debug(f"No matching platform {current_platform} in manifest list for {image_ref}")
        return None

    # Single manifest — get its digest
    try:
        digest = _run_crane(["digest", image_ref]).strip()
        return digest
    except subprocess.CalledProcessError:
        return None


def _is_chainguard_config(image_ref: str) -> bool:
    """Check if an image config indicates a Chainguard image."""
    try:
        config_json = _run_crane(["config", image_ref])
        config = json.loads(config_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch config for {image_ref}: {e}")
        return False

    # Check author field (set by apko)
    if config.get("author") == "github.com/chainguard-dev/apko":
        return True

    # Check labels
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

    digest = _resolve_platform_digest(docker_image)
    if not digest:
        logger.warning(f"Could not resolve platform digest for {docker_image}")
        return None

    # Extract the image ref without tag/digest for the ChainguardBaseImage
    image_ref = docker_image.split("@")[0].split(":")[0]
    return ChainguardBaseImage(image_ref=image_ref, digest=digest)


def _parse_purl_docker_uri(uri: str) -> tuple[str, str] | None:
    """Parse a pkg:docker URI into (image_ref, digest).

    Example: pkg:docker/cgr.dev/chainguard/python?digest=sha256:abc...&platform=linux%2Famd64
    Returns: ("cgr.dev/chainguard/python", "sha256:abc...")
    """
    if not uri.startswith("pkg:docker/"):
        return None

    # Remove pkg:docker/ prefix
    rest = uri[len("pkg:docker/") :]

    # Split on ? to separate path from query
    if "?" in rest:
        path, query = rest.split("?", 1)
    else:
        return None

    # Decode the path
    image_ref = unquote(path)
    # Remove @tag if present (e.g., pkg:docker/alpine@3.21)
    if "@" in image_ref:
        image_ref = image_ref.split("@")[0]

    # Parse query parameters for digest
    digest = None
    for param in query.split("&"):
        if param.startswith("digest="):
            digest = unquote(param[len("digest=") :])
            break

    if not digest:
        return None

    return image_ref, digest


def _detect_chainguard_from_provenance(docker_image: str) -> ChainguardBaseImage | None:
    """Detect Chainguard base image by parsing BuildKit provenance attestation."""
    try:
        index_json = _run_crane(["manifest", docker_image])
        index = json.loads(index_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch manifest for {docker_image}: {e}")
        return None

    # Find attestation manifest in the image index
    att_digest = None
    for entry in index.get("manifests", []):
        annotations = entry.get("annotations", {})
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            att_digest = entry["digest"]
            break

    if not att_digest:
        logger.debug(f"No attestation manifest found for {docker_image}")
        return None

    # Fetch the attestation manifest to find the provenance layer
    try:
        att_manifest_json = _run_crane(["manifest", f"{docker_image.split(':')[0]}@{att_digest}"])
        # Handle case where docker_image has @ instead of :
        if "@" in docker_image:
            registry_repo = docker_image.split("@")[0]
            att_manifest_json = _run_crane(["manifest", f"{registry_repo}@{att_digest}"])
        att_manifest = json.loads(att_manifest_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch attestation manifest: {e}")
        return None

    # Find SLSA provenance layer
    provenance_digest = None
    for layer in att_manifest.get("layers", []):
        annotations = layer.get("annotations", {})
        if annotations.get("in-toto.io/predicate-type") == "https://slsa.dev/provenance/v1":
            provenance_digest = layer["digest"]
            break

    if not provenance_digest:
        logger.debug(f"No SLSA provenance layer found in attestation for {docker_image}")
        return None

    # Fetch and parse the provenance blob
    try:
        # Need to resolve the registry/repo for blob fetching
        if "@" in docker_image:
            registry_repo = docker_image.split("@")[0]
        else:
            registry_repo = docker_image.split(":")[0]
        provenance_json = _run_crane(["blob", f"{registry_repo}@{provenance_digest}"])
        provenance = json.loads(provenance_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch provenance blob: {e}")
        return None

    # Search resolvedDependencies for Chainguard images
    resolved_deps = provenance.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])

    for dep in resolved_deps:
        uri = dep.get("uri", "")
        if "cgr.dev/chainguard/" not in uri:
            continue

        parsed = _parse_purl_docker_uri(uri)
        if not parsed:
            continue

        image_ref, digest = parsed
        logger.info(f"Found Chainguard base image in provenance: {image_ref}@{digest}")

        # Resolve to per-architecture digest if this is an index digest
        platform_digest = _resolve_platform_digest(f"{image_ref}@{digest}")
        if not platform_digest:
            platform_digest = digest

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
    if not shutil.which("crane"):
        logger.debug("crane not found on PATH, skipping Chainguard detection")
        return None

    # Path A: Direct Chainguard image
    result = _detect_direct_chainguard(docker_image)
    if result:
        return result

    # Path B: User-built image FROM Chainguard
    return _detect_chainguard_from_provenance(docker_image)


def fetch_chainguard_sbom(info: ChainguardBaseImage) -> dict:
    """Download the SPDX SBOM from a Chainguard image's cosign attestation.

    Args:
        info: Detected Chainguard image info with per-architecture digest

    Returns:
        SPDX document as a dict

    Raises:
        RuntimeError: If SBOM cannot be fetched or parsed
    """
    if not shutil.which("cosign"):
        raise RuntimeError("cosign not found on PATH, cannot fetch Chainguard SBOM")

    image_with_digest = f"{info.image_ref}@{info.digest}"
    logger.info(f"Fetching Chainguard SBOM for {image_with_digest}")

    try:
        output = _run_cosign(["download", "attestation", image_with_digest])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to download attestation for {image_with_digest}: {e.stderr or e}") from e

    # Parse each line as a JSON attestation envelope
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            envelope = json.loads(line)
        except json.JSONDecodeError:
            continue

        payload_b64 = envelope.get("payload", "")
        if not payload_b64:
            continue

        try:
            payload = json.loads(base64.b64decode(payload_b64))
        except (json.JSONDecodeError, Exception):
            continue

        if payload.get("predicateType") == "https://spdx.dev/Document":
            predicate = payload.get("predicate", {})
            if predicate.get("spdxVersion"):
                pkg_count = len(predicate.get("packages", []))
                logger.info(f"Found Chainguard SPDX SBOM with {pkg_count} packages")
                return predicate

    raise RuntimeError(f"No SPDX SBOM found in attestations for {image_with_digest}")


# CycloneDX hash algorithm mapping from SPDX algorithm names
_SPDX_TO_CDX_HASH_ALG: dict[str, HashAlgorithm] = {
    "SHA256": HashAlgorithm.SHA_256,
    "SHA384": HashAlgorithm.SHA_384,
    "SHA512": HashAlgorithm.SHA_512,
    "SHA1": HashAlgorithm.SHA_1,
    "MD5": HashAlgorithm.MD5,
}


def convert_spdx_to_cyclonedx(spdx_doc: dict, spec_version: str = "1.6") -> str:
    """Convert a Chainguard SPDX SBOM to CycloneDX JSON.

    Handles the simple structure of Chainguard SBOMs: packages with PURLs,
    checksums, and supplier info.

    Args:
        spdx_doc: SPDX document dict (from fetch_chainguard_sbom)
        spec_version: Target CycloneDX spec version (default "1.6")

    Returns:
        CycloneDX JSON string
    """
    bom = Bom()

    # Set metadata
    creation_info = spdx_doc.get("creationInfo", {})
    created = creation_info.get("created")
    if created:
        try:
            bom.metadata.timestamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            pass

    # Add tool info from SPDX creators
    for creator in creation_info.get("creators", []):
        if creator.startswith("Tool:"):
            tool_name = creator[len("Tool:") :].strip()
            bom.metadata.tools.tools.add(Tool(name=tool_name))

    # Track which SPDX IDs are "described" (top-level components)
    described_ids = set(spdx_doc.get("documentDescribes", []))

    # Build components from SPDX packages
    components: list[Component] = []
    main_component: Component | None = None

    for pkg in spdx_doc.get("packages", []):
        spdx_id = pkg.get("SPDXID", "")
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")

        # Extract PURL from external refs
        purl_str = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl_str = ref.get("referenceLocator", "")
                break

        # Determine component type
        purpose = pkg.get("primaryPackagePurpose", "")
        if purpose == "CONTAINER":
            comp_type = ComponentType.CONTAINER
        elif purpose == "OPERATING_SYSTEM":
            comp_type = ComponentType.OPERATING_SYSTEM
        else:
            comp_type = ComponentType.LIBRARY

        # Build component
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

        # Add supplier
        supplier_str = pkg.get("supplier", "")
        if supplier_str and supplier_str != "NOASSERTION":
            # Parse "Organization: Chainguard, Inc." format
            if supplier_str.startswith("Organization:"):
                org_name = supplier_str[len("Organization:") :].strip()
                comp.supplier = OrganizationalEntity(name=org_name)

        # Add hashes
        for checksum in pkg.get("checksums", []):
            alg = checksum.get("algorithm", "")
            value = checksum.get("checksumValue", "")
            cdx_alg = _SPDX_TO_CDX_HASH_ALG.get(alg)
            if cdx_alg and value:
                comp.hashes.add(HashType(alg=cdx_alg, content=value))

        # Add description
        description = pkg.get("description", "")
        if description:
            comp.description = description

        # Set as main component if it's the described package
        if spdx_id in described_ids and main_component is None:
            main_component = comp
        else:
            components.append(comp)

    # Set main component in metadata
    if main_component:
        bom.metadata.component = main_component

    # Add all other components
    for comp in components:
        bom.components.add(comp)

    # Serialize
    return serialize_cyclonedx_bom(bom, spec_version)
