"""Docker Hub base image detection and upstream SBOM fetch.

Two detection paths mirror :mod:`chainguard`:

1. **Direct** — ``docker_image`` itself is a Docker Official Image
   (``docker.io/library/*`` or the implicit-library shorthand) or a Docker
   Hardened Image (``dhi.io/*``).
2. **Provenance** — ``docker_image`` was built with BuildKit and its SLSA v1
   provenance lists a Docker Hub base image under ``resolvedDependencies``.

Unlike Chainguard, Docker Hub images are commonly *extended* by users
(``FROM python:3.11 && RUN apt-get install ...``). The CLI integration pairs
this upstream SBOM with a local Syft scan and merges them via
:mod:`sbom_merge`.

SBOM delivery differs by tier:

* **Docker Official Images** attach an unsigned SPDX in-toto attestation
  alongside the image manifest (``vnd.docker.reference.type=attestation-manifest``
  sibling in the OCI index). Fetched with crane.
* **Docker Hardened Images (DHI)** ship cosign-signed attestations keyed
  against Docker's scout keyring, with Rekor transparency logging skipped.
  Fetched with ``cosign download attestation --key ... --insecure-ignore-tlog=true``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sbomify_action.logging_config import logger

from . import buildkit_provenance as bkp

DHI_COSIGN_KEY_URL = "https://registry.scout.docker.com/keyring/dhi/latest.pub"
_DOCKER_HUB_HOSTS = {"docker.io", "index.docker.io", "registry-1.docker.io"}
_DHI_HOST = "dhi.io"

# User-facing warning shown when Docker Hub SBOMs are consumed. Kept short
# enough for the GitHub Actions job-summary warning box.
DOCKERHUB_MERGE_WARNING = (
    "Using Docker Hub's upstream SBOM merged with a local Syft scan. Docker's "
    "published attestation is authoritative for base-layer packages; Syft "
    "overlays packages your Dockerfile added on top (apt, pip, COPY/ADD, etc). "
    "Some gaps can remain — for the fullest coverage, build your image with "
    "`docker buildx --sbom=true --provenance=true` so BuildKit attaches a "
    "complete SBOM directly. See: "
    "https://github.com/sbomify/sbomify-action#docker-hub-images"
)


@dataclass
class DockerHubBaseImage:
    """Information about a detected Docker Hub base image.

    ``index_ref`` is the ref that resolves to the *image index* (typically a
    tag like ``docker.io/library/python:3.11`` or ``<repo>@<index-digest>``),
    which is where BuildKit parks the attestation-manifest siblings.
    ``digest`` is the per-platform manifest digest, used both to match the
    correct attestation sibling in multi-arch indexes and to key cosign
    lookups for DHI.
    """

    image_ref: str  # canonical repo, e.g., "docker.io/library/python"
    index_ref: str  # ref that resolves to an image index
    digest: str  # per-platform manifest digest
    tier: str  # "official" or "dhi"


def _classify_ref(image_ref: str) -> str | None:
    """Return ``"official"``, ``"dhi"``, or ``None`` for an image reference.

    Handles both full refs (``docker.io/library/python``) and the shorthand
    forms Docker CLI accepts (``library/nginx``, bare ``python``).
    """
    base = bkp.extract_repo(image_ref)
    if not base:
        return None

    if base == _DHI_HOST or base.startswith(f"{_DHI_HOST}/"):
        return "dhi"

    parts = base.split("/")
    first = parts[0]
    # Docker's own heuristic: a segment is a registry host iff it has a dot,
    # a colon (port), or is "localhost".
    has_registry = "." in first or ":" in first or first == "localhost"

    if has_registry:
        if first in _DOCKER_HUB_HOSTS:
            if len(parts) == 3 and parts[1] == "library":
                return "official"
            return None
        return None

    # Implicit docker.io registry.
    if len(parts) == 1:
        # Bare name: docker.io/library/<name>
        return "official"
    if len(parts) == 2 and parts[0] == "library":
        return "official"
    # docker.io/<user>/<repo> — not an Official Image.
    return None


def _canonicalize(image_ref: str, tier: str) -> str:
    """Return the canonical ``registry/namespace/name`` form for display/logs."""
    base = bkp.extract_repo(image_ref)
    if tier == "dhi":
        if not base.startswith(f"{_DHI_HOST}/") and base != _DHI_HOST:
            return f"{_DHI_HOST}/{base}"
        return base
    # Official: ensure docker.io/library/<name>
    parts = base.split("/")
    first = parts[0]
    has_registry = "." in first or ":" in first or first == "localhost"
    if has_registry:
        if first in _DOCKER_HUB_HOSTS:
            return "docker.io/" + "/".join(parts[1:])
        return base
    if len(parts) == 1:
        return f"docker.io/library/{parts[0]}"
    if parts[0] == "library":
        return f"docker.io/{base}"
    return base


def _detect_direct(docker_image: str) -> DockerHubBaseImage | None:
    tier = _classify_ref(docker_image)
    if tier is None:
        return None

    logger.debug(f"Image ref matches Docker Hub {tier} pattern, verifying: {docker_image}")

    digest = bkp.resolve_platform_digest(docker_image)
    if not digest:
        logger.debug(f"Could not resolve platform digest for {docker_image}")
        return None

    # The user-provided ref typically resolves to the image INDEX (tags do),
    # which is where BuildKit stores attestation-manifest siblings.
    return DockerHubBaseImage(
        image_ref=_canonicalize(docker_image, tier),
        index_ref=docker_image,
        digest=digest,
        tier=tier,
    )


def _detect_from_provenance(docker_image: str) -> DockerHubBaseImage | None:
    statement = bkp.fetch_build_provenance(docker_image)
    if statement is None:
        return None

    for dep in bkp.iter_resolved_dependencies(statement):
        parsed = bkp.parse_docker_resolved_dependency(dep)
        if not parsed:
            continue

        base_ref, base_digest = parsed
        tier = _classify_ref(base_ref)
        if tier is None:
            continue

        logger.info(f"Found Docker Hub base image in provenance: {base_ref}@{base_digest}")
        # BuildKit's resolvedDependencies digest is typically the image-INDEX
        # digest (what `FROM python:3.11` saw), so `base_ref@base_digest` is a
        # valid index ref. Resolve down to the per-platform manifest for
        # attestation sibling matching.
        index_ref = f"{base_ref}@{base_digest}"
        platform_digest = bkp.resolve_platform_digest(index_ref) or base_digest
        return DockerHubBaseImage(
            image_ref=_canonicalize(base_ref, tier),
            index_ref=index_ref,
            digest=platform_digest,
            tier=tier,
        )

    logger.debug(f"No Docker Hub base image found in provenance for {docker_image}")
    return None


def detect_dockerhub_image(docker_image: str) -> DockerHubBaseImage | None:
    """Detect whether ``docker_image`` is or is built FROM a Docker Hub image.

    Returns ``None`` if not detected or if crane is unavailable.
    """
    if not bkp.crane_available():
        logger.debug("crane not found on PATH, skipping Docker Hub detection")
        return None

    direct = _detect_direct(docker_image)
    if direct:
        return direct

    return _detect_from_provenance(docker_image)


def fetch_dockerhub_sbom(info: DockerHubBaseImage) -> dict[str, Any] | None:
    """Fetch the upstream SPDX SBOM for a detected Docker Hub image.

    Returns the SPDX document (the ``predicate`` body) or ``None`` if no
    SBOM attestation is attached. Some older Official Images don't ship
    attestations — callers should fall through to a plain Syft scan.
    """
    logger.info(f"Fetching Docker Hub upstream SBOM for {info.image_ref}@{info.digest} (tier={info.tier})")

    if info.tier == "dhi":
        if not bkp.cosign_available():
            logger.warning("cosign not found on PATH, cannot fetch DHI SBOM")
            return None
        # DHI attestations are keyed on the platform manifest digest.
        predicate = bkp.fetch_cosign_spdx_predicate(
            f"{info.image_ref}@{info.digest}",
            extra_cosign_args=["--key", DHI_COSIGN_KEY_URL, "--insecure-ignore-tlog=true"],
        )
    else:
        # Official Images attach SBOM attestations as siblings in the image
        # INDEX. Pull the index via index_ref and match the sibling whose
        # vnd.docker.reference.digest equals our platform digest.
        predicate = bkp.fetch_buildkit_spdx_attestation(info.index_ref, platform_digest=info.digest)

    if predicate is None:
        logger.info(f"No upstream SBOM attestation found for {info.image_ref}@{info.digest}")
        return None

    pkg_count = len(predicate.get("packages", []))
    logger.info(f"Fetched upstream SBOM with {pkg_count} packages for {info.image_ref}")
    return predicate
