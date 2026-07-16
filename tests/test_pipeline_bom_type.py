"""End-to-end pipeline behavior for non-SBOM artifacts (BOM_TYPE=vex/cbom/hbom).

These run the real pipeline (UPLOAD=false) in a temp working directory and pin
the verbatim contract at the level users experience it: the bytes written to
OUTPUT_FILE are exactly the authored bytes.
"""

from __future__ import annotations

import pytest

from sbomify_action.cli.main import build_config, run_pipeline

AUTHORED_VEX = (
    b'{"bomFormat": "CycloneDX",\r\n'
    b'  "specVersion": "1.6",\n'
    b'  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",\n'
    b'  "version": 7,\n'
    b'  "vulnerabilities": [{"id": "CVE-2026-0001"}]}\n'
)


def _vex_config(tmp_path, monkeypatch, **overrides):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "authored.vex.cdx.json"
    src.write_bytes(AUTHORED_VEX)
    kwargs = dict(
        sbom_file=str(src),
        upload=False,
        bom_type="vex",
        output_file="out.vex.json",
    )
    kwargs.update(overrides)
    return build_config(**kwargs), src


def test_pipeline_vex_verbatim_end_to_end(tmp_path, monkeypatch):
    """The full pipeline must not alter a single byte of an authored VEX —
    CRLF, key order, indentation and the document's own version survive,
    even with additional-package injection configured."""
    monkeypatch.setenv("ADDITIONAL_PACKAGES", "extra-package==1.0.0")
    config, _ = _vex_config(tmp_path, monkeypatch)
    run_pipeline(config)
    assert (tmp_path / "out.vex.json").read_bytes() == AUTHORED_VEX


def test_pipeline_non_sbom_rejects_spdx_content(tmp_path, monkeypatch):
    """An SPDX-content file with a non-SBOM BOM_TYPE must fail loud in step 1:
    the declared-format guard in Config.validate() cannot see file content, and
    the SPDX license sanitization would rewrite the authored bytes."""
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "doc.json"
    src.write_bytes(b'{"spdxVersion": "SPDX-2.3", "name": "x", "packages": []}')
    config = build_config(
        sbom_file=str(src),
        upload=False,
        bom_type="vex",
        output_file="out.json",
    )
    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1


def test_pipeline_output_file_colliding_with_step_file_survives_cleanup(tmp_path, monkeypatch):
    """OUTPUT_FILE resolving to the internal step file must not be deleted by
    the temp-file cleanup: the write is a copy-to-self no-op and the cleanup
    loop must never unlink the final output."""
    config, _ = _vex_config(tmp_path, monkeypatch, output_file="step_1.json")
    run_pipeline(config)
    assert (tmp_path / "step_1.json").read_bytes() == AUTHORED_VEX


AUTHORED_OPENVEX = (
    b'{"@context": "https://openvex.dev/ns/v0.2.0",\r\n'
    b'  "@id": "https://example.com/vex-1",\n'
    b'  "author": "Author",\n'
    b'  "timestamp": "2026-07-15T00:00:00Z",\n'
    b'  "version": 1,\n'
    b'  "statements": [{"vulnerability": {"name": "CVE-2026-0001"},\n'
    b'    "products": [{"@id": "pkg:npm/a@1.0.0"}], "status": "not_affected",\n'
    b'    "justification": "component_not_present"}]}\n'
)

AUTHORED_CSAF = (
    b'{"document": {"category": "csaf_vex", "csaf_version": "2.0",\n'
    b'  "publisher": {"category": "vendor", "name": "Ex", "namespace": "https://example.com"},\n'
    b'  "title": "Example", "tracking": {"id": "EX-1", "status": "final", "version": "1",\n'
    b'    "initial_release_date": "2026-07-15T00:00:00.000Z",\n'
    b'    "current_release_date": "2026-07-15T00:00:00.000Z",\n'
    b'    "revision_history": [{"date": "2026-07-15T00:00:00.000Z", "number": "1", "summary": "i"}]}},\n'
    b'  "product_tree": {"full_product_names": [{"product_id": "P-1", "name": "Example 1.0"}]},\n'
    b'  "vulnerabilities": [{"cve": "CVE-2026-0001",\n'
    b'    "product_status": {"known_not_affected": ["P-1"]}}]}\n'
)


@pytest.mark.parametrize(
    "authored,name",
    [(AUTHORED_OPENVEX, "authored.openvex.json"), (AUTHORED_CSAF, "authored.csaf.json")],
    ids=["openvex", "csaf"],
)
def test_pipeline_external_vex_verbatim(tmp_path, monkeypatch, authored, name):
    """OpenVEX and CSAF VEX documents pass the pipeline byte-for-byte, exactly
    like CycloneDX VEX: CRLF, key order, and indentation survive."""
    monkeypatch.chdir(tmp_path)
    src = tmp_path / name
    src.write_bytes(authored)
    config = build_config(
        sbom_file=str(src),
        upload=False,
        bom_type="vex",
        output_file="out.vex.json",
    )
    run_pipeline(config)
    assert (tmp_path / "out.vex.json").read_bytes() == authored


def test_detect_external_vex_format_non_utf8_falls_back(tmp_path):
    """A file with undecodable (non-UTF-8) bytes must return None so validate_sbom
    reports it normally, not raise UnicodeDecodeError and crash the pipeline."""
    from sbomify_action.cli.main import _detect_external_vex_format

    bad = tmp_path / "bad.json"
    bad.write_bytes(b'\xff\xfe{"@context": "https://openvex.dev/ns"}')
    assert _detect_external_vex_format(str(bad)) is None


def test_validate_sbom_non_utf8_raises_validation_error(tmp_path):
    """A non-UTF-8 SBOM fails as SBOMValidationError (handled by step 1), not an
    uncaught UnicodeDecodeError that crashes the pipeline."""
    from sbomify_action.cli.main import validate_sbom
    from sbomify_action.exceptions import SBOMValidationError

    bad = tmp_path / "bad.json"
    bad.write_bytes(b'\xff\xfe{"bomFormat": "CycloneDX"}')
    with pytest.raises(SBOMValidationError):
        validate_sbom(str(bad))


def test_validate_sbom_accepts_utf8_bom(tmp_path):
    """A UTF-8 BOM (common on Windows) must not be mistaken for invalid JSON."""
    from sbomify_action.cli.main import validate_sbom

    good = tmp_path / "bom.json"
    good.write_bytes(b'\xef\xbb\xbf{"bomFormat": "CycloneDX"}')
    assert validate_sbom(str(good)) == "cyclonedx"


def test_detect_external_vex_format_accepts_utf8_bom(tmp_path):
    """A BOM-prefixed OpenVEX document is still detected, not rejected."""
    from sbomify_action.cli.main import _detect_external_vex_format

    doc = tmp_path / "ov.json"
    doc.write_bytes(b'\xef\xbb\xbf{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}')
    assert _detect_external_vex_format(str(doc)) == "openvex"


def test_detect_external_vex_format_list_context(tmp_path):
    """OpenVEX @context may be a JSON-LD list; any entry under the openvex
    namespace counts (SPDX3-style list-form contexts occur in the wild)."""
    from sbomify_action.cli.main import _detect_external_vex_format

    doc = tmp_path / "ov.json"
    doc.write_text('{"@context": ["https://example.com/other", "https://openvex.dev/ns/v0.2.0"], "statements": []}')
    assert _detect_external_vex_format(str(doc)) == "openvex"


def test_pipeline_openvex_rejected_without_vex_bom_type(tmp_path, monkeypatch):
    """Without BOM_TYPE=vex an OpenVEX document is not an SBOM and must fail
    loud in step 1 rather than upload mislabeled."""
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "doc.json"
    src.write_bytes(AUTHORED_OPENVEX)
    config = build_config(sbom_file=str(src), upload=False, output_file="out.json")
    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1
