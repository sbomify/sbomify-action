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
