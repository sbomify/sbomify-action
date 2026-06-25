"""Generate a CBOM (Cryptography Bill of Materials) and cross-link it with the SBOM.

cdxgen's ``--include-crypto`` discovers ``cryptographic-asset`` components
(algorithms, certificates, protocols, keys) from the source tree. Coverage is
realistically Java keystores/certificates plus JS/TS source call sites; it does not
see binary-embedded, dynamically dispatched, or framework/stdlib crypto, so the
generated CBOM is marked ``compositions: aggregate=incomplete``.

The SBOM and CBOM reference each other through CycloneDX ``externalReferences`` of
type ``bom`` carrying a BOM-Link URN (``urn:cdx:<serialNumber>/<version>``), so a
consumer that has one can discover the other.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Optional

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger

from ._generation.utils import DEFAULT_TIMEOUT, run_command

CBOM_DEFAULT_SPEC_VERSION = "1.7"


def generate_cbom(
    output_file: str, spec_version: str = CBOM_DEFAULT_SPEC_VERSION, cwd: Optional[str] = None
) -> Optional[str]:
    """Generate a CBOM with ``cdxgen --include-crypto``.

    Returns the absolute output path, or ``None`` if generation failed or produced
    nothing. CBOM generation is best-effort and never fails the overall run.
    """
    output_abs = str(Path(output_file).resolve())
    cmd = ["cdxgen", "-o", output_abs, "--spec-version", spec_version, "--include-crypto", "."]
    logger.info(f"Generating CBOM with cdxgen --include-crypto (CycloneDX {spec_version})")
    try:
        run_command(cmd, "cdxgen (CBOM)", timeout=DEFAULT_TIMEOUT, cwd=cwd, log_errors=False)
    except SBOMGenerationError as e:
        logger.warning(f"CBOM generation failed, skipping CBOM: {e}")
        return None
    if not Path(output_abs).exists():
        logger.warning("CBOM generation produced no output, skipping CBOM")
        return None
    return output_abs


def _serial_and_version(bom: dict[str, Any]) -> tuple[str, int]:
    """Return ``(bare-uuid, version)`` for a BOM, assigning a serialNumber if absent."""
    serial = bom.get("serialNumber")
    if not serial:
        serial = f"urn:uuid:{uuid.uuid4()}"
        bom["serialNumber"] = serial
    version = int(bom.get("version") or 1)
    bom["version"] = version
    bare_uuid = serial.rsplit(":", 1)[-1]
    return bare_uuid, version


def _bom_link(bare_uuid: str, version: int) -> str:
    return f"urn:cdx:{bare_uuid}/{version}"


def _add_external_bom_ref(bom: dict[str, Any], url: str, comment: str) -> None:
    """Idempotently add a top-level ``externalReferences`` entry of type ``bom``."""
    refs = bom.setdefault("externalReferences", [])
    if any(isinstance(r, dict) and r.get("type") == "bom" and r.get("url") == url for r in refs):
        return
    refs.append({"type": "bom", "url": url, "comment": comment})


def _mark_incomplete(cbom: dict[str, Any]) -> None:
    """Record ``aggregate: incomplete`` when the CBOM declares no ``compositions`` of
    its own, so consumers do not read a scanner-derived CBOM as a complete
    cryptographic inventory. A composition the generator already set is left as-is."""
    if not cbom.get("compositions"):
        cbom["compositions"] = [{"aggregate": "incomplete"}]


def crosslink_sbom_and_cbom(sbom_path: str, cbom_path: str) -> None:
    """Cross-reference the SBOM and CBOM and write both files back.

    Each BOM gains an ``externalReferences`` entry of type ``bom`` with a BOM-Link
    URN to the other; the CBOM is also marked ``aggregate: incomplete``. Idempotent.
    """
    sbom = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
    cbom = json.loads(Path(cbom_path).read_text(encoding="utf-8"))

    sbom_uuid, sbom_ver = _serial_and_version(sbom)
    cbom_uuid, cbom_ver = _serial_and_version(cbom)

    _add_external_bom_ref(
        sbom, _bom_link(cbom_uuid, cbom_ver), "Cryptography Bill of Materials (CBOM) for this component"
    )
    _add_external_bom_ref(
        cbom, _bom_link(sbom_uuid, sbom_ver), "Software Bill of Materials (SBOM) this CBOM was derived from"
    )
    _mark_incomplete(cbom)

    Path(sbom_path).write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    Path(cbom_path).write_text(json.dumps(cbom, indent=2), encoding="utf-8")
