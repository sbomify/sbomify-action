"""Tests for CBOM generation and SBOM<->CBOM cross-linking."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sbomify_action.cbom import crosslink_sbom_and_cbom, generate_cbom
from sbomify_action.exceptions import SBOMGenerationError

# --- generate_cbom -----------------------------------------------------------


def test_generate_cbom_builds_include_crypto_command(tmp_path: Path) -> None:
    out = str(tmp_path / "cbom.json")
    with patch("sbomify_action.cbom.run_command") as run, patch("pathlib.Path.exists", return_value=True):
        result = generate_cbom(out, spec_version="1.7", cwd="/repo")
    cmd = run.call_args.args[0]
    assert cmd[0] == "cdxgen"
    assert "--include-crypto" in cmd
    assert cmd[cmd.index("--spec-version") + 1] == "1.7"
    assert cmd[-1] == "."
    assert run.call_args.kwargs["cwd"] == "/repo"
    assert result == str(Path(out).resolve())


def test_generate_cbom_returns_none_on_failure(tmp_path: Path) -> None:
    with patch("sbomify_action.cbom.run_command", side_effect=SBOMGenerationError("boom")):
        assert generate_cbom(str(tmp_path / "cbom.json")) is None


def test_generate_cbom_returns_none_when_no_output(tmp_path: Path) -> None:
    with patch("sbomify_action.cbom.run_command"), patch("pathlib.Path.exists", return_value=False):
        assert generate_cbom(str(tmp_path / "cbom.json")) is None


# --- crosslink_sbom_and_cbom -------------------------------------------------


def _write(p: Path, doc: dict) -> str:
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def _bom(serial: str | None = None) -> dict:
    d: dict = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1}
    if serial:
        d["serialNumber"] = serial
    return d


def _bom_refs(path: str) -> list[dict]:
    return [r for r in json.loads(Path(path).read_text())["externalReferences"] if r["type"] == "bom"]


def test_crosslink_adds_bidirectional_bom_refs(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "sbom.json", _bom("urn:uuid:11111111-1111-1111-1111-111111111111"))
    cbom = _write(tmp_path / "cbom.json", _bom("urn:uuid:22222222-2222-2222-2222-222222222222"))

    crosslink_sbom_and_cbom(sbom, cbom)

    sbom_ref = _bom_refs(sbom)[0]
    cbom_ref = _bom_refs(cbom)[0]
    assert sbom_ref["url"] == "urn:cdx:22222222-2222-2222-2222-222222222222/1"  # SBOM -> CBOM
    assert cbom_ref["url"] == "urn:cdx:11111111-1111-1111-1111-111111111111/1"  # CBOM -> SBOM


def test_crosslink_marks_cbom_incomplete(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "sbom.json", _bom("urn:uuid:11111111-1111-1111-1111-111111111111"))
    cbom = _write(tmp_path / "cbom.json", _bom("urn:uuid:22222222-2222-2222-2222-222222222222"))

    crosslink_sbom_and_cbom(sbom, cbom)

    assert json.loads(Path(cbom).read_text())["compositions"] == [{"aggregate": "incomplete"}]


def test_crosslink_assigns_serial_when_missing(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "sbom.json", _bom())  # no serialNumber
    cbom = _write(tmp_path / "cbom.json", _bom())

    crosslink_sbom_and_cbom(sbom, cbom)

    sbom_doc = json.loads(Path(sbom).read_text())
    assert sbom_doc["serialNumber"].startswith("urn:uuid:")
    # the CBOM's back-reference points at the SBOM's freshly assigned serial
    bare = sbom_doc["serialNumber"].rsplit(":", 1)[-1]
    assert _bom_refs(cbom)[0]["url"] == f"urn:cdx:{bare}/1"


def test_crosslink_marks_incomplete_when_generator_set_other_compositions(tmp_path: Path) -> None:
    # cdxgen could emit its own compositions without an incomplete marker; the
    # safety marker must still be added, and the generator's entry preserved.
    sbom = _write(tmp_path / "sbom.json", _bom("urn:uuid:11111111-1111-1111-1111-111111111111"))
    cbom_doc = _bom("urn:uuid:22222222-2222-2222-2222-222222222222")
    cbom_doc["compositions"] = [{"aggregate": "complete", "assemblies": ["ref-a"]}]
    cbom = _write(tmp_path / "cbom.json", cbom_doc)

    crosslink_sbom_and_cbom(sbom, cbom)

    compositions = json.loads(Path(cbom).read_text())["compositions"]
    assert {"aggregate": "complete", "assemblies": ["ref-a"]} in compositions
    assert any(c.get("aggregate") == "incomplete" for c in compositions)
    # idempotent: a second pass adds no duplicate incomplete entry
    crosslink_sbom_and_cbom(sbom, cbom)
    incomplete = [c for c in json.loads(Path(cbom).read_text())["compositions"] if c.get("aggregate") == "incomplete"]
    assert len(incomplete) == 1


def test_crosslink_is_idempotent(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "sbom.json", _bom("urn:uuid:11111111-1111-1111-1111-111111111111"))
    cbom = _write(tmp_path / "cbom.json", _bom("urn:uuid:22222222-2222-2222-2222-222222222222"))

    crosslink_sbom_and_cbom(sbom, cbom)
    crosslink_sbom_and_cbom(sbom, cbom)

    assert len(_bom_refs(sbom)) == 1
    assert len(_bom_refs(cbom)) == 1
    assert len(json.loads(Path(cbom).read_text())["compositions"]) == 1
