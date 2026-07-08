"""Output finalization skips its fixes for non-SBOM artifacts (e.g. VEX, CBOM)."""

from __future__ import annotations

from sbomify_action.cli.main import _finalize_output_content

CYCLONEDX = '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}'


def test_sbom_gets_compositions_injected() -> None:
    out = _finalize_output_content(CYCLONEDX, None)
    assert '"compositions"' in out


def test_explicit_sbom_bom_type_still_finalized() -> None:
    out = _finalize_output_content(CYCLONEDX, "sbom")
    assert '"compositions"' in out


def test_vex_skips_finalization_fixes() -> None:
    # Finalization adds no composition and does no PURL rewriting for a VEX, so
    # this step returns the content unchanged (earlier pipeline steps are separate).
    out = _finalize_output_content(CYCLONEDX, "vex")
    assert out == CYCLONEDX


def test_cbom_skips_finalization_fixes() -> None:
    out = _finalize_output_content(CYCLONEDX, "cbom")
    assert out == CYCLONEDX


def test_non_cyclonedx_passthrough() -> None:
    spdx = '{"spdxVersion": "SPDX-2.3", "name": "x"}'
    assert _finalize_output_content(spdx, None) == spdx
