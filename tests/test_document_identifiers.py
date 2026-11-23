"""Every SBOM the pipeline writes carries a document identifier.

A signature or attestation names the document it covers, and CISA's 2026
minimum elements and BSI TR-03183-2 both expect one: a CycloneDX
``serialNumber``, an SPDX 2 ``documentNamespace``. These run the real pipeline
(UPLOAD=false) and read OUTPUT_FILE, which is what gets signed and uploaded.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from sbomify_action.cli.main import build_config, run_pipeline

SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"


def _run(tmp_path, monkeypatch, **kwargs) -> dict:
    monkeypatch.chdir(tmp_path)
    run_pipeline(build_config(upload=False, output_file="out.json", **kwargs))
    return json.loads((tmp_path / "out.json").read_text())


def _cyclonedx_file(tmp_path, **extra) -> str:
    src = tmp_path / "in.cdx.json"
    src.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, **extra}))
    return str(src)


def _assert_urn_uuid(serial: str) -> None:
    assert serial.startswith("urn:uuid:")
    uuid.UUID(serial.removeprefix("urn:uuid:"))


def test_sbom_file_without_serial_number_gets_one(tmp_path, monkeypatch):
    out = _run(tmp_path, monkeypatch, sbom_file=_cyclonedx_file(tmp_path))
    _assert_urn_uuid(out["serialNumber"])


def test_sbom_file_serial_number_is_kept(tmp_path, monkeypatch):
    out = _run(tmp_path, monkeypatch, sbom_file=_cyclonedx_file(tmp_path, serialNumber=SERIAL))
    assert out["serialNumber"] == SERIAL


def test_gradle_lockfile_sbom_gets_a_serial_number(tmp_path, monkeypatch):
    # The native gradle.lockfile reader builds its document by hand. Lockfile
    # hash enrichment happens to re-serialize it through cyclonedx-python-lib,
    # which mints a serial, but that step is non-fatal: when it fails, the
    # hand-built document is what ships.
    def fail(**_kwargs):
        raise RuntimeError("simulated hash enrichment failure")

    monkeypatch.setattr("sbomify_action._hash_enrichment.enrich_sbom_with_hashes", fail)
    lockfile = tmp_path / "gradle.lockfile"
    lockfile.write_text("org.slf4j:slf4j-api:2.0.13=runtimeClasspath\n")
    out = _run(tmp_path, monkeypatch, lock_file=str(lockfile))
    _assert_urn_uuid(out["serialNumber"])


def test_serial_number_helper_leaves_unparseable_content_alone():
    from sbomify_action.serialization import _add_serial_number_if_missing

    assert _add_serial_number_if_missing("not json") == "not json"
    assert _add_serial_number_if_missing("[]") == "[]"


def _spdx_file(tmp_path, **extra) -> str:
    src = tmp_path / "in.spdx.json"
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "app",
        "dataLicense": "CC0-1.0",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: test"]},
        **extra,
    }
    src.write_text(json.dumps(document))
    return str(src)


def test_spdx_sbom_file_without_namespace_gets_a_unique_one(tmp_path, monkeypatch):
    first = _run(tmp_path, monkeypatch, sbom_file=_spdx_file(tmp_path))["documentNamespace"]
    second = _run(tmp_path, monkeypatch, sbom_file=_spdx_file(tmp_path))["documentNamespace"]
    assert first.startswith("https://")
    assert first != second


def test_spdx_sbom_file_namespace_is_kept(tmp_path, monkeypatch):
    namespace = "https://example.com/spdxdocs/app-1.0"
    out = _run(tmp_path, monkeypatch, sbom_file=_spdx_file(tmp_path, documentNamespace=namespace))
    assert out["documentNamespace"] == namespace


def test_spdx_sbom_file_without_namespace_survives_augmentation(tmp_path, monkeypatch):
    # spdx-tools refuses to parse a document with no namespace, so augmentation
    # and enrichment could not read one before it was given a namespace.
    (tmp_path / "sbomify.json").write_text(json.dumps({"supplier": {"name": "Example Ltd"}}))
    out = _run(tmp_path, monkeypatch, sbom_file=_spdx_file(tmp_path), augment=True)
    assert out["documentNamespace"].startswith("https://")
    assert "Example Ltd" in json.dumps(out)


def test_spdx_sbom_file_given_a_namespace_stays_pretty_printed(tmp_path, monkeypatch):
    # Rewritten with indent=2, as the CycloneDX fixups write theirs, so the output stays diffable.
    src = Path(_spdx_file(tmp_path))
    src.write_text(json.dumps(json.loads(src.read_text()), indent=2))
    _run(tmp_path, monkeypatch, sbom_file=str(src))
    text = (tmp_path / "out.json").read_text()
    assert text == json.dumps(json.loads(text), indent=2, ensure_ascii=False)
