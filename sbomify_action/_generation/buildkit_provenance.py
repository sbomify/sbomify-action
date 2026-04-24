"""BuildKit / in-toto attestation helpers shared across base-image detectors.

BuildKit attaches in-toto attestations (SLSA provenance, SPDX SBOMs, etc.) to
images as sibling manifests in the image index, annotated with
``vnd.docker.reference.type=attestation-manifest``. Each layer of that
manifest is one in-toto statement, annotated with ``in-toto.io/predicate-type``.

Two delivery mechanisms are supported:

* **Crane** walks the OCI image index directly — used for Docker Official
  Images and BuildKit-built user images where attestations are attached as
  siblings (unsigned).
* **Cosign** reads DSSE envelopes produced by ``cosign attest`` — used for
  Chainguard and Docker Hardened Images where attestations are cosign-signed.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import platform
import shutil
import subprocess
from typing import Any, Iterator
from urllib.parse import unquote

from sbomify_action.logging_config import logger

# Well-known in-toto predicate types.
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
SPDX_DOCUMENT = "https://spdx.dev/Document"


def extract_repo(image_ref: str) -> str:
    """Strip ``:tag`` and ``@digest`` from an image reference.

    Handles registries with ports (``localhost:5000/repo/image:tag``) by only
    treating the last colon as a tag separator when it falls after the last
    slash.
    """
    if "@" in image_ref:
        image_ref = image_ref.split("@")[0]

    last_slash = image_ref.rfind("/")
    last_colon = image_ref.rfind(":")
    if last_colon > last_slash:
        image_ref = image_ref[:last_colon]

    return image_ref


def get_current_platform() -> str:
    """Return the current platform as an OCI ``os/arch`` string."""
    target_arch = os.environ.get("TARGETARCH")
    if target_arch:
        return f"linux/{target_arch}"

    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
    }
    arch = arch_map.get(machine, machine)
    return f"linux/{arch}"


def crane_available() -> bool:
    return shutil.which("crane") is not None


def cosign_available() -> bool:
    return shutil.which("cosign") is not None


def _classify_registry_error(stderr: str) -> str | None:
    """Return a human-friendly hint for common registry error shapes.

    Returns ``None`` when the stderr doesn't match a known pattern — callers
    can then log the raw message.
    """
    if not stderr:
        return None
    low = stderr.lower()
    if "toomanyrequests" in low or "rate limit" in low or "429" in low:
        return (
            "Docker Hub anonymous pull rate limit exceeded (100 pulls / 6h). "
            "Run `docker login` to raise the limit to 200/6h (free account) or "
            "unlimited (paid)."
        )
    if "401" in low and "unauthorized" in low:
        return "Registry returned 401 Unauthorized — run `docker login` to authenticate."
    if "not found" in low or "404" in low:
        return "Registry manifest not found (image may not exist or tag has moved)."
    return None


def run_crane(args: list[str]) -> str:
    """Run a ``crane`` command and return stdout."""
    cmd = ["crane"] + args
    logger.debug(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
    if result.returncode != 0:
        hint = _classify_registry_error(result.stderr)
        if hint:
            logger.warning(f"crane {' '.join(args)} failed: {hint}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
    return result.stdout


def run_cosign(args: list[str]) -> str:
    """Run a ``cosign`` command and return stdout."""
    cmd = ["cosign"] + args
    logger.debug(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
    if result.returncode != 0:
        hint = _classify_registry_error(result.stderr)
        if hint:
            logger.warning(f"cosign {' '.join(args)} failed: {hint}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
    return result.stdout


def resolve_platform_digest(image_ref: str) -> str | None:
    """Resolve a reference to the current platform's manifest digest.

    If the reference is a manifest list / OCI image index, pick the entry
    matching the current platform. Otherwise return the single manifest's
    digest.
    """
    current_platform = get_current_platform()
    os_name, arch = current_platform.split("/")

    try:
        manifest_json = run_crane(["manifest", image_ref])
        manifest = json.loads(manifest_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch manifest for {image_ref}: {e}")
        return None

    media_type = manifest.get("mediaType", "")
    if "manifest.list" in media_type or "image.index" in media_type:
        for entry in manifest.get("manifests", []):
            p = entry.get("platform", {})
            if p.get("os") == os_name and p.get("architecture") == arch:
                return str(entry["digest"])
        logger.debug(f"No matching platform {current_platform} in manifest list for {image_ref}")
        return None

    try:
        return run_crane(["digest", image_ref]).strip()
    except subprocess.CalledProcessError:
        return None


def parse_purl_docker_uri(uri: str) -> tuple[str, str] | None:
    """Parse a ``pkg:docker`` PURL into ``(image_ref, digest)``.

    Example: ``pkg:docker/cgr.dev/chainguard/python?digest=sha256:abc...&platform=linux%2Famd64``
    returns ``("cgr.dev/chainguard/python", "sha256:abc...")``.
    """
    if not uri.startswith("pkg:docker/"):
        return None

    rest = uri[len("pkg:docker/") :]
    if "?" not in rest:
        return None

    path, query = rest.split("?", 1)
    image_ref = unquote(path)
    if "@" in image_ref:
        image_ref = image_ref.split("@")[0]

    digest = None
    for param in query.split("&"):
        if param.startswith("digest="):
            digest = unquote(param[len("digest=") :])
            break

    if not digest:
        return None

    return image_ref, digest


def parse_docker_resolved_dependency(dep: dict[str, Any]) -> tuple[str, str] | None:
    """Parse a ``resolvedDependencies[]`` entry into ``(image_ref, digest)``.

    SLSA v1 provenance may put the digest in the PURL's ``digest=`` qualifier
    *or* in the sibling ``digest`` field on the dependency object. Docker
    Hub's BuildKit provenance commonly uses the sibling-field form. This
    helper handles both.
    """
    uri = dep.get("uri", "")
    if not isinstance(uri, str) or not uri.startswith("pkg:docker/"):
        return None

    rest = uri[len("pkg:docker/") :]
    path = rest.split("?", 1)[0] if "?" in rest else rest
    image_ref = unquote(path)
    if "@" in image_ref:
        image_ref = image_ref.split("@")[0]
    if not image_ref:
        return None

    if "?" in rest:
        query = rest.split("?", 1)[1]
        for param in query.split("&"):
            if param.startswith("digest="):
                return image_ref, unquote(param[len("digest=") :])

    digest_field = dep.get("digest")
    if isinstance(digest_field, dict):
        for alg, value in digest_field.items():
            if isinstance(alg, str) and isinstance(value, str) and alg and value:
                return image_ref, f"{alg}:{value}"

    return None


def _find_attestation_manifest_digest(
    index: dict[str, Any],
    platform_digest: str | None = None,
) -> str | None:
    """Return the digest of the attestation-manifest sibling in an image index.

    If ``platform_digest`` is given, only a sibling whose
    ``vnd.docker.reference.digest`` matches is returned (the right choice for
    multi-arch indexes where each platform has its own attestation sibling).
    Otherwise the first attestation-manifest is returned — fine for callers
    that just want to confirm provenance exists.
    """
    for entry in index.get("manifests", []):
        annotations = entry.get("annotations", {})
        if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        if platform_digest is None or annotations.get("vnd.docker.reference.digest") == platform_digest:
            return str(entry["digest"])
    return None


def fetch_buildkit_attestation_statement(
    image_ref: str,
    predicate_type: str,
    platform_digest: str | None = None,
) -> dict[str, Any] | None:
    """Fetch an in-toto statement attached to an image by BuildKit.

    Walks the image index → attestation-manifest sibling → layer annotated with
    the given ``predicate_type`` → parses the blob as JSON.

    ``image_ref`` must resolve to an image INDEX (typically a tag like
    ``library/python:3.11`` or an index digest like ``library/python@sha256:…``),
    not a per-platform manifest digest. BuildKit stores attestations as siblings
    in the index.

    ``platform_digest`` is the per-platform manifest digest to match against
    attestation siblings' ``vnd.docker.reference.digest`` annotation. Required
    for correctness on multi-arch indexes (every platform has its own
    attestation sibling). If omitted, the first attestation-manifest is used
    (fine for single-arch images or when the caller just needs one provenance
    document).

    Returns the full in-toto statement (``_type``, ``predicateType``,
    ``predicate``), or ``None`` if the image has no attestations or no layer
    with that predicate type.
    """
    try:
        index_json = run_crane(["manifest", image_ref])
        index = json.loads(index_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch manifest for {image_ref}: {e}")
        return None

    att_digest = _find_attestation_manifest_digest(index, platform_digest=platform_digest)
    if not att_digest:
        if platform_digest:
            logger.debug(f"No attestation manifest found for {image_ref} (platform digest {platform_digest})")
        else:
            logger.debug(f"No attestation manifest found for {image_ref}")
        return None

    registry_repo = extract_repo(image_ref)

    try:
        att_manifest_json = run_crane(["manifest", f"{registry_repo}@{att_digest}"])
        att_manifest = json.loads(att_manifest_json)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch attestation manifest: {e}")
        return None

    layer_digest = None
    for layer in att_manifest.get("layers", []):
        annotations = layer.get("annotations", {})
        if annotations.get("in-toto.io/predicate-type") == predicate_type:
            layer_digest = layer["digest"]
            break

    if not layer_digest:
        logger.debug(f"No {predicate_type} layer found in attestation for {image_ref}")
        return None

    try:
        blob = run_crane(["blob", f"{registry_repo}@{layer_digest}"])
        return dict(json.loads(blob))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to fetch attestation blob: {e}")
        return None


def fetch_build_provenance(image_ref: str) -> dict[str, Any] | None:
    """Fetch the SLSA v1 provenance statement attached by BuildKit.

    Does not filter by platform — provenance is usually identical across
    platforms in a BuildKit-built image, and Chainguard's provenance parser
    just needs to see the resolved base refs.
    """
    return fetch_buildkit_attestation_statement(image_ref, SLSA_PROVENANCE_V1)


def fetch_buildkit_spdx_attestation(
    image_ref: str,
    platform_digest: str | None = None,
) -> dict[str, Any] | None:
    """Fetch the SPDX SBOM statement attached by BuildKit (OCI layer path).

    Returns the SPDX document (the ``predicate`` field), not the wrapping
    in-toto statement. Matches the shape of :func:`fetch_cosign_spdx_predicate`.

    Pass ``platform_digest`` when the image is multi-arch so the
    attestation-manifest sibling for the *current* platform is picked.
    """
    statement = fetch_buildkit_attestation_statement(image_ref, SPDX_DOCUMENT, platform_digest=platform_digest)
    if statement is None:
        return None
    predicate = statement.get("predicate")
    if isinstance(predicate, dict) and predicate.get("spdxVersion"):
        return predicate
    return None


def iter_resolved_dependencies(statement: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield ``resolvedDependencies`` entries from a SLSA v1 provenance statement."""
    resolved = statement.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])
    yield from resolved


def fetch_cosign_spdx_predicate(
    image_with_digest: str,
    extra_cosign_args: list[str] | None = None,
) -> dict[str, Any] | None:
    """Run ``cosign download attestation`` and extract the SPDX predicate.

    ``cosign`` emits one JSON DSSE envelope per line. Each envelope has a
    base64-encoded ``payload`` that is the in-toto statement. We scan for a
    statement whose ``predicateType`` is ``https://spdx.dev/Document`` and
    return its ``predicate`` (the SPDX document itself).

    ``extra_cosign_args`` are inserted before the image reference; use this
    to pass keys / tlog flags for signed-but-not-Rekor-logged attestations
    (e.g., Docker Hardened Images).
    """
    args = ["download", "attestation"]
    if extra_cosign_args:
        args.extend(extra_cosign_args)
    args.append(image_with_digest)

    try:
        output = run_cosign(args)
    except subprocess.CalledProcessError as e:
        logger.debug(f"cosign download attestation failed for {image_with_digest}: {e.stderr or e}")
        return None

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
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError, binascii.Error):
            continue

        if payload.get("predicateType") != SPDX_DOCUMENT:
            continue

        predicate = payload.get("predicate")
        if isinstance(predicate, dict) and predicate.get("spdxVersion"):
            return dict(predicate)

    return None
