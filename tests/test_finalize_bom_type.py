"""Output finalization must leave non-SBOM artifacts (e.g. VEX) untouched."""

from __future__ import annotations

from sbomify_action.cli.main import _finalize_output_content

CYCLONEDX = '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}'


def test_sbom_gets_compositions_injected() -> None:
    out = _finalize_output_content(CYCLONEDX, None)
    assert '"compositions"' in out


def test_explicit_sbom_bom_type_still_finalized() -> None:
    out = _finalize_output_content(CYCLONEDX, "sbom")
    assert '"compositions"' in out


def test_vex_is_uploaded_verbatim() -> None:
    # A VEX is an immutable security artifact: no composition injection, no
    # PURL rewriting, byte-for-byte what was authored.
    out = _finalize_output_content(CYCLONEDX, "vex")
    assert out == CYCLONEDX


def test_cbom_is_uploaded_verbatim() -> None:
    out = _finalize_output_content(CYCLONEDX, "cbom")
    assert out == CYCLONEDX


def test_non_cyclonedx_passthrough() -> None:
    spdx = '{"spdxVersion": "SPDX-2.3", "name": "x"}'
    assert _finalize_output_content(spdx, None) == spdx


def test_write_final_output_copies_non_sbom_bytes_exactly(tmp_path):
    """VEX/CBOM write is a byte copy: CRLF newlines and exact bytes survive."""
    from sbomify_action.cli.main import _write_final_output

    src = tmp_path / "authored.vex.cdx.json"
    raw = b'{"bomFormat": "CycloneDX",\r\n "specVersion": "1.6"}\r\n'
    src.write_bytes(raw)
    dst = tmp_path / "out.json"
    _write_final_output(str(src), str(dst), "vex")
    assert dst.read_bytes() == raw


def test_write_final_output_sbom_still_applies_fixups(tmp_path):
    """The plain-SBOM path still goes through the text fixups (compositions added)."""
    from sbomify_action.cli.main import _write_final_output

    src = tmp_path / "sbom.cdx.json"
    src.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
    dst = tmp_path / "out.json"
    _write_final_output(str(src), str(dst), None)
    assert "compositions" in dst.read_text()
