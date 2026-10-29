"""PURL clean-up reaches the output whatever ENRICH is set to."""

from __future__ import annotations

import json
import logging
import sys

from sbomify_action.cli.main import build_config, run_pipeline

FORMULATION = [{"bom-ref": "build", "components": [{"type": "application", "name": "builder"}]}]

LOCAL_PURL = "pkg:npm/local@file:../local"


def _write_input(tmp_path, encoding="utf-8"):
    src = tmp_path / "input.cdx.json"
    src.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                "version": 1,
                "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app"}},
                "components": [
                    {"type": "library", "name": "local", "bom-ref": "local", "purl": LOCAL_PURL},
                    {"type": "library", "name": "request", "bom-ref": "req", "purl": "pkg:npm/%40root/request@1.9.2"},
                ],
                "formulation": FORMULATION,
            }
        ),
        encoding=encoding,
    )
    return src


def test_file_purl_is_cleared_with_enrich_off(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = _write_input(tmp_path)

    run_pipeline(build_config(sbom_file=str(src), upload=False, enrich=False, output_file="out.json"))

    out = json.loads((tmp_path / "out.json").read_text())
    assert {c["name"]: c.get("purl") for c in out["components"]} == {
        "local": None,
        "request": "pkg:npm/%40root/request@1.9.2",
    }
    # The rest of the document is left as it was, including fields the
    # CycloneDX library does not model and would drop on a round trip.
    assert out["formulation"] == FORMULATION


def test_a_bom_prefixed_input_with_enrich_off_finishes_and_is_cleaned(tmp_path, monkeypatch):
    """Step 1 accepts a UTF-8 BOM (Windows PowerShell 5 writes one) and copies
    the file verbatim, so the clean-up has to read it the same way."""
    monkeypatch.chdir(tmp_path)
    src = _write_input(tmp_path, encoding="utf-8-sig")

    run_pipeline(build_config(sbom_file=str(src), upload=False, enrich=False, output_file="out.json"))

    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8-sig"))
    assert {c["name"]: c.get("purl") for c in out["components"]}["local"] is None


def test_a_clean_up_failure_does_not_stop_the_run(tmp_path, monkeypatch, caplog):
    """The clean-up is best effort: a bad PURL left in place beats a run that
    dies before writing or uploading anything."""
    monkeypatch.chdir(tmp_path)
    src = _write_input(tmp_path)

    def broken(_path):
        raise ValueError("unexpected document")

    # sbomify_action.cli exports a main() that shadows the module of the same
    # name, so patch the module object itself.
    monkeypatch.setattr(sys.modules["sbomify_action.cli.main"], "sanitize_cyclonedx_json_file_purls", broken)
    with caplog.at_level(logging.WARNING, logger="sbomify_action"):
        run_pipeline(build_config(sbom_file=str(src), upload=False, enrich=False, output_file="out.json"))

    out = json.loads((tmp_path / "out.json").read_text())
    assert {c["name"]: c.get("purl") for c in out["components"]}["local"] == LOCAL_PURL
    assert any("PURL clean-up" in r.getMessage() for r in caplog.records)
