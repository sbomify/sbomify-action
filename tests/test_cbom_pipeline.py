"""Tests for the CBOM pipeline glue in cli/main.py (generate+crosslink, upload)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from sbomify_action.cli.main import _generate_cbom_and_crosslink, _upload_cbom

# String-target patches below resolve the module via importlib; we cannot bind the
# module directly because cli/__init__.py re-exports the `main` function, shadowing
# the `sbomify_action.cli.main` submodule attribute.
MOD = "sbomify_action.cli.main"


def _cfg(**kw):
    base = dict(
        lock_file=None,
        spec_version=None,
        component_version=None,
        token="t",
        component_id="c",
        api_base_url="https://api.test",
        component_name=None,
        upload_destinations=["sbomify"],
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_generate_cbom_and_crosslink_wires_generate_and_link() -> None:
    with (
        patch(f"{MOD}.get_last_sbom_from_last_step", return_value="step_3.json"),
        patch("sbomify_action.cbom.generate_cbom", return_value="/abs/cbom.json") as gen,
        patch("sbomify_action.cbom.crosslink_sbom_and_cbom") as link,
    ):
        out = _generate_cbom_and_crosslink(_cfg())

    assert out == "/abs/cbom.json"
    gen.assert_called_once()
    link.assert_called_once_with("step_3.json", "/abs/cbom.json")


def test_generate_cbom_and_crosslink_none_when_generation_fails() -> None:
    with (
        patch(f"{MOD}.get_last_sbom_from_last_step", return_value="step_3.json"),
        patch("sbomify_action.cbom.generate_cbom", return_value=None),
        patch("sbomify_action.cbom.crosslink_sbom_and_cbom") as link,
    ):
        assert _generate_cbom_and_crosslink(_cfg()) is None
        link.assert_not_called()


def test_generate_cbom_and_crosslink_none_without_sbom() -> None:
    with patch(f"{MOD}.get_last_sbom_from_last_step", return_value=None):
        assert _generate_cbom_and_crosslink(_cfg()) is None


def test_upload_cbom_uses_bom_type_cbom() -> None:
    result = Mock(success=True, sbom_id="cbom-1")
    with patch(f"{MOD}.upload_sbom", return_value=result) as up:
        _upload_cbom(_cfg(), "/abs/cbom.json")

    kwargs = up.call_args.kwargs
    assert kwargs["bom_type"] == "cbom"
    assert kwargs["sbom_file"] == "/abs/cbom.json"
    assert kwargs["sbom_format"] == "cyclonedx"


def test_upload_cbom_skips_non_sbomify_destinations() -> None:
    # CBOM classification is sbomify-specific; DT would ingest it as a plain SBOM.
    result = Mock(success=True, sbom_id="cbom-1")
    with patch(f"{MOD}.upload_sbom", return_value=result) as up:
        _upload_cbom(_cfg(upload_destinations=["sbomify", "dependency-track"]), "/abs/cbom.json")
    destinations = [c.kwargs["destination"] for c in up.call_args_list]
    assert destinations == ["sbomify"]


def test_upload_cbom_swallows_failure() -> None:
    # A CBOM upload failure must not raise (never fails the SBOM run).
    with patch(f"{MOD}.upload_sbom", side_effect=RuntimeError("boom")):
        _upload_cbom(_cfg(), "/abs/cbom.json")  # no exception


def test_upload_cbom_reports_step_failure_on_partial_failure() -> None:
    # A failed destination is non-fatal but the step is reported as failed, not hidden.
    failed = Mock(success=False, error_message="nope")
    with patch(f"{MOD}.upload_sbom", return_value=failed), patch(f"{MOD}._log_step_end") as step_end:
        _upload_cbom(_cfg(upload_destinations=["sbomify"]), "/abs/cbom.json")  # no raise
    step_end.assert_called_with(5.5, success=False)
