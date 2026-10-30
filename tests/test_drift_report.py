"""The drift report: what changed in the SBOM since the previous release.

A run that produced an empty SBOM, where the same input had produced 246
components the time before (sbomify/sbomify-action#384), looked like any other
green run. These pin the comparison the job summary now carries, where the
previous SBOM comes from, and that a missing or unreachable one costs nothing
but the section.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from sbomify_action._runtime import use_platform
from sbomify_action._runtime.platforms import GitHubPlatform
from sbomify_action._upload.result import UploadResult
from sbomify_action.cli.main import build_config, cli, run_pipeline
from sbomify_action.console import reset_audit_trail
from sbomify_action.drift import Drift, compare_with_previous
from sbomify_action.exceptions import APIError, ForbiddenError
from sbomify_action.logging_config import warning_annotations
from tests.test_job_summary import _read_outputs

HEADING = "Changes since the previous SBOM"


def _cdx(*components: dict[str, Any]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "app", "version": "1.0.0"}},
        "components": list(components),
    }


def _lib(name: str, version: str, *, purl: bool = True, **fields: Any) -> dict[str, Any]:
    component = {"type": "library", "name": name, "version": version, **fields}
    if purl:
        component["purl"] = f"pkg:pypi/{name}@{version}"
    return component


def _licensed(license_id: str) -> list[dict[str, Any]]:
    return [{"license": {"id": license_id}}]


PREVIOUS = _cdx(
    _lib("requests", "2.31.0", licenses=_licensed("Apache-2.0"), supplier={"name": "Python Software Foundation"}),
    _lib("idna", "3.6"),
    _lib("urllib3", "2.0.0"),
    _lib("certifi", "2024.2.2", licenses=_licensed("MPL-2.0")),
    _lib("vendored-lib", "1.0", purl=False),
)
CURRENT = _cdx(
    _lib("requests", "2.31.0", licenses=_licensed("Apache-2.0")),  # supplier gone
    _lib("idna", "3.7"),  # version changed
    _lib("certifi", "2024.2.2", licenses=_licensed("MIT")),  # license changed
    _lib("charset-normalizer", "3.3.2"),  # added; urllib3 removed
    _lib("vendored-lib", "1.0", purl=False),  # unchanged, matched by name
)


@pytest.fixture
def summary(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_audit_trail()
    warning_annotations.reset()
    return path


def _write(path: Path, doc: dict[str, Any]) -> str:
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _run(tmp_path: Path, current: dict[str, Any] = CURRENT, **overrides: Any) -> None:
    kwargs: dict[str, Any] = dict(
        sbom_file=_write(tmp_path / "input.cdx.json", current), upload=False, output_file="sbom.cdx.json"
    )
    kwargs.update(overrides)
    with use_platform(GitHubPlatform()):
        run_pipeline(build_config(**kwargs))


def _drift_section(summary: Path) -> str:
    text = summary.read_text(encoding="utf-8")
    assert HEADING in text
    return text[text.index(HEADING) :]


def test_summary_reports_what_changed_since_the_previous_sbom(tmp_path, summary):
    _run(tmp_path, previous_sbom=_write(tmp_path / "previous.cdx.json", PREVIOUS))

    section = _drift_section(summary)
    assert "previous.cdx.json`" in section  # where the comparison came from
    assert "**Components:** 5 → 5" in section
    assert "**Added:** 1" in section
    assert "**Removed:** 1" in section
    assert "**Version changed:** 1" in section
    assert "**Supplier changed:** 1" in section
    assert "**License changed:** 1" in section
    assert "`charset-normalizer@3.3.2`" in section
    assert "`urllib3@2.0.0`" in section
    assert "`idna 3.6 → 3.7`" in section
    assert "vendored-lib" not in section  # same name, same version: no change


def test_no_previous_sbom_means_no_section_and_no_warning(tmp_path, summary, caplog):
    with caplog.at_level(logging.WARNING):
        _run(tmp_path)

    assert HEADING not in summary.read_text(encoding="utf-8")
    assert "previous SBOM" not in caplog.text


def test_a_previous_sbom_that_is_not_there_yet_is_skipped_quietly(tmp_path, summary, caplog):
    """First release: the step that downloads the last release's SBOM found none."""
    with caplog.at_level(logging.WARNING):
        _run(tmp_path, previous_sbom=str(tmp_path / "not-downloaded.json"))

    assert HEADING not in summary.read_text(encoding="utf-8")
    assert "PREVIOUS_SBOM" not in caplog.text


def test_a_missing_previous_sbom_says_where_it_looked(tmp_path, summary, caplog):
    """The path is relative to WORKING_DIR, not the checkout root: show where that led."""
    with caplog.at_level(logging.INFO):
        _run(tmp_path, previous_sbom="prev/sbom.json")

    assert str(Path.cwd() / "prev" / "sbom.json") in caplog.text


def test_a_previous_sbom_that_cannot_be_read_warns_and_is_skipped(tmp_path, summary, caplog):
    broken = tmp_path / "previous.json"
    broken.write_text("{not json", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        _run(tmp_path, previous_sbom=str(broken))

    assert HEADING not in summary.read_text(encoding="utf-8")
    assert "PREVIOUS_SBOM" in caplog.text
    assert (tmp_path / "sbom.cdx.json").exists()


def test_a_malformed_previous_sbom_warns_and_is_skipped(tmp_path, summary, caplog):
    """Valid JSON, wrong shape: whatever was downloaded must not crash the run."""
    malformed = _cdx("not a component")  # type: ignore[arg-type]
    with caplog.at_level(logging.WARNING):
        _run(tmp_path, previous_sbom=_write(tmp_path / "previous.cdx.json", malformed))

    assert HEADING not in summary.read_text(encoding="utf-8")
    assert "No drift report" in caplog.text
    assert "### sbomify" in summary.read_text(encoding="utf-8")


SPDX_PREVIOUS = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "app",
    "documentNamespace": "https://example.com/app",
    "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: test"]},
    "packages": [
        {
            "SPDXID": f"SPDXRef-{name}",
            "name": name,
            "versionInfo": version,
            "supplier": supplier,
            "licenseDeclared": license_id,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{name}@{version}",
                }
            ],
        }
        for name, version, supplier, license_id in [
            ("requests", "2.31.0", "Organization: Python Software Foundation", "Apache-2.0"),
            ("idna", "3.6", "NOASSERTION", "NOASSERTION"),
            ("urllib3", "2.0.0", "NOASSERTION", "NOASSERTION"),
            ("certifi", "2024.2.2", "NOASSERTION", "MPL-2.0"),
        ]
    ],
}


def test_formats_can_differ_between_the_two_sboms(tmp_path, summary):
    """An SPDX 2 previous SBOM against a CycloneDX run: matched by PURL, fields read per format."""
    _run(tmp_path, previous_sbom=_write(tmp_path / "previous.spdx.json", SPDX_PREVIOUS))

    section = _drift_section(summary)
    assert "**Components:** 4 → 5" in section
    assert "`idna 3.6 → 3.7`" in section
    assert "`urllib3@2.0.0`" in section
    # "Organization: Python Software Foundation" is the same supplier as CycloneDX's
    # bare name, so only its removal counts; NOASSERTION is no supplier at all.
    assert "**Supplier changed:** 1" in section
    assert "**License changed:** 1" in section  # certifi MPL-2.0 -> MIT


def _uploaded() -> Any:
    return patch(
        "sbomify_action.cli.main.upload_sbom",
        return_value=UploadResult.success_result(destination_name="sbomify", sbom_id="new-sbom"),
    )


def test_an_upload_to_sbomify_compares_against_the_last_one_there(tmp_path, summary):
    latest = {"id": "old-sbom", "version": "1.0.0", "format": "cyclonedx"}
    with (
        _uploaded(),
        patch("sbomify_action.drift.SbomifyApiClient.latest_component_sbom", return_value=latest) as listed,
        patch("sbomify_action.drift.SbomifyApiClient.download_sbom", return_value=PREVIOUS) as downloaded,
    ):
        _run(tmp_path, upload=True, token="tok", component_id="comp-1")

    listed.assert_called_once_with("comp-1", "cyclonedx")
    downloaded.assert_called_once_with("old-sbom")
    section = _drift_section(summary)
    assert "version `1.0.0`" in section
    assert "**Removed:** 1" in section


def test_previous_sbom_wins_over_sbomify(tmp_path, summary):
    """An explicit file is what the user asked to compare against; no API call."""
    with _uploaded(), patch("sbomify_action.drift.SbomifyApiClient.latest_component_sbom") as listed:
        _run(
            tmp_path,
            upload=True,
            token="tok",
            component_id="comp-1",
            previous_sbom=_write(tmp_path / "previous.cdx.json", PREVIOUS),
        )

    listed.assert_not_called()
    assert "previous.cdx.json`" in _drift_section(summary)


def test_the_first_upload_to_a_component_has_nothing_to_compare(tmp_path, summary, caplog):
    with (
        _uploaded(),
        patch("sbomify_action.drift.SbomifyApiClient.latest_component_sbom", return_value=None),
        caplog.at_level(logging.WARNING),
    ):
        _run(tmp_path, upload=True, token="tok", component_id="comp-1")

    assert HEADING not in summary.read_text(encoding="utf-8")
    assert "previous SBOM" not in caplog.text


def test_an_api_error_warns_and_drops_only_the_section(tmp_path, summary, caplog):
    """sbomify being down is no reason to fail a release."""
    error = APIError("Failed to list component SBOMs. [500] - boom")
    with (
        _uploaded() as upload,
        patch("sbomify_action.drift.SbomifyApiClient.latest_component_sbom", side_effect=error),
        caplog.at_level(logging.WARNING),
    ):
        _run(tmp_path, upload=True, token="tok", component_id="comp-1")

    upload.assert_called_once()
    text = summary.read_text(encoding="utf-8")
    assert "### sbomify" in text
    assert HEADING not in text
    assert "[500] - boom" in caplog.text


def test_a_token_that_cannot_read_the_component_back_is_not_a_warning(tmp_path, summary, caplog):
    """OIDC trusted publishing on a private component: expected, and the fix is PREVIOUS_SBOM."""
    error = ForbiddenError("Failed to list component SBOMs. [403] - Access denied")
    with (
        _uploaded(),
        patch("sbomify_action.drift.SbomifyApiClient.latest_component_sbom", side_effect=error),
        caplog.at_level(logging.INFO),
    ):
        _run(tmp_path, upload=True, token="tok", component_id="comp-1")

    assert HEADING not in summary.read_text(encoding="utf-8")
    hint = [r for r in caplog.records if "PREVIOUS_SBOM" in r.getMessage()]
    assert hint and all(r.levelno == logging.INFO for r in hint)


def _deps(count: int) -> dict[str, Any]:
    return _cdx(*(_lib(f"dep{i:02}", "1.0") for i in range(count)))


def test_a_collapse_fails_the_run_before_anything_is_uploaded(tmp_path, summary, caplog):
    """A broken generator, not 60% of the dependencies deleted: the SBOM must not be published."""
    with _uploaded() as upload, pytest.raises(SystemExit) as exit_info:
        _run(
            tmp_path,
            _deps(4),
            upload=True,
            token="tok",
            component_id="comp-1",
            previous_sbom=_write(tmp_path / "previous.cdx.json", _deps(10)),
        )

    assert exit_info.value.code == 1
    upload.assert_not_called()
    assert (tmp_path / "sbom.cdx.json").exists()  # still there to inspect
    errors = " ".join(r.getMessage() for r in caplog.records if r.levelno == logging.ERROR)
    assert "lists 4 components, down from 10" in errors
    assert "false" in errors.lower() and "FAIL_ON_SBOM_COLLAPSE" in errors
    section = _drift_section(summary)
    assert "**Components:** 10 → 4" in section
    assert "FAIL_ON_SBOM_COLLAPSE" in section


def test_a_collapse_still_names_the_sbom_in_the_step_outputs(tmp_path, summary, monkeypatch):
    """So an `if: failure()` step can keep the collapsed SBOM for inspection."""
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    with pytest.raises(SystemExit):
        _run(tmp_path, _deps(4), previous_sbom=_write(tmp_path / "previous.cdx.json", _deps(10)))

    assert _read_outputs(outputs) == {"sbom-file": "sbom.cdx.json", "sbom-format": "cyclonedx", "component-count": "4"}


def test_the_gate_can_be_turned_off_for_a_drop_that_is_real(tmp_path, summary, caplog):
    with _uploaded() as upload, caplog.at_level(logging.WARNING):
        _run(
            tmp_path,
            _deps(4),
            upload=True,
            token="tok",
            component_id="comp-1",
            previous_sbom=_write(tmp_path / "previous.cdx.json", _deps(10)),
            fail_on_sbom_collapse=False,
        )

    upload.assert_called_once()
    assert "FAIL_ON_SBOM_COLLAPSE" in caplog.text
    assert "FAIL_ON_SBOM_COLLAPSE=false" in _drift_section(summary)


@pytest.mark.parametrize(("before", "after"), [(3, 1), (9, 0)])
def test_a_small_project_can_shed_most_of_its_dependencies(tmp_path, summary, before, after):
    """3 -> 1 is a refactor, not a broken generator. An empty SBOM from a real
    lock file is caught where it is generated, not here."""
    with _uploaded() as upload:
        _run(
            tmp_path,
            _deps(after),
            upload=True,
            token="tok",
            component_id="comp-1",
            previous_sbom=_write(tmp_path / "previous.cdx.json", _deps(before)),
        )

    upload.assert_called_once()
    section = _drift_section(summary)  # still reported
    assert f"**Components:** {before} → {after}" in section
    assert "FAIL_ON_SBOM_COLLAPSE" not in section


def test_no_previous_sbom_means_no_gate(tmp_path, summary):
    _run(tmp_path, _cdx())  # empty, and nothing to say it used to be bigger

    assert (tmp_path / "sbom.cdx.json").exists()


@pytest.mark.parametrize(
    ("before", "after", "collapsed"),
    [(10, 4, True), (10, 5, False), (246, 0, True), (3, 1, False), (9, 0, False), (0, 0, False)],
)
def test_collapse_means_more_than_half_gone_from_at_least_ten(before, after, collapsed):
    assert Drift(source="`previous`", before=before, after=after).collapsed is collapsed


@pytest.mark.parametrize(
    ("env", "args", "expected"),
    [
        ({}, [], True),
        ({"FAIL_ON_SBOM_COLLAPSE": "false"}, [], False),
        ({"FAIL_ON_SBOM_COLLAPSE": "true"}, ["--no-fail-on-sbom-collapse"], False),
    ],
)
def test_the_settings_reach_the_config_like_the_other_booleans(tmp_path, env, args, expected):
    lock_file = tmp_path / "requirements.txt"
    lock_file.write_text("requests==2.28.0", encoding="utf-8")
    with (
        patch("sbomify_action.cli.main.run_pipeline") as run,
        patch("sbomify_action.cli.main.setup_dependencies"),
        patch("sbomify_action.cli.main.initialize_sentry"),
    ):
        result = CliRunner().invoke(
            cli,
            ["--lock-file", str(lock_file), "--no-upload", *args],
            env={"PREVIOUS_SBOM": "previous.cdx.json", **env},
        )

    assert result.exit_code == 0, result.output
    config = run.call_args.args[0]
    assert config.fail_on_sbom_collapse is expected
    assert config.previous_sbom == "previous.cdx.json"


def test_a_typo_in_the_gate_setting_fails_loudly(tmp_path):
    """An unreadable value must not quietly turn the gate off."""
    lock_file = tmp_path / "requirements.txt"
    lock_file.write_text("requests==2.28.0", encoding="utf-8")
    with patch("sbomify_action.cli.main.run_pipeline") as run, patch("sbomify_action.cli.main.setup_dependencies"):
        result = CliRunner().invoke(
            cli, ["--lock-file", str(lock_file), "--no-upload"], env={"FAIL_ON_SBOM_COLLAPSE": "flase"}
        )

    assert result.exit_code == 2
    assert "FAIL_ON_SBOM_COLLAPSE" in result.output
    run.assert_not_called()


class TestCompare:
    """The diff itself, without a pipeline around it."""

    def _compare(self, tmp_path: Path, previous: dict[str, Any], current: dict[str, Any]):
        return compare_with_previous((previous, "`previous`"), _write(tmp_path / "current.json", current))

    def test_several_versions_of_one_package_are_one_entry(self, tmp_path):
        """npm trees hold lodash twice; dropping one copy is a version change, not a removal."""
        previous = _cdx(_lib("lodash", "4.17.20"), _lib("lodash", "4.17.21"))
        drift = self._compare(tmp_path, previous, _cdx(_lib("lodash", "4.17.21")))

        assert drift is not None
        assert (drift.added, drift.removed) == ([], [])
        assert drift.changed == ["lodash 4.17.20, 4.17.21 → 4.17.21"]

    def test_purl_qualifiers_do_not_split_a_package(self, tmp_path):
        """A distro point release rewrites every deb PURL's qualifiers, not its identity."""

        def deb(version: str, distro: str) -> dict[str, Any]:
            purl = f"pkg:deb/debian/libc6@{version}?arch=amd64&distro={distro}"
            return {"type": "library", "name": "libc6", "version": version, "purl": purl}

        drift = self._compare(tmp_path, _cdx(deb("2.36-9", "debian-12.5")), _cdx(deb("2.36-9+deb12u7", "debian-12.6")))

        assert drift is not None
        assert drift.changed == ["libc6 2.36-9 → 2.36-9+deb12u7"]

    def test_a_component_that_loses_or_gains_its_purl_is_one_change(self, tmp_path):
        """A generator that stops emitting PURLs must read as that, not as each package removed and re-added."""
        previous = _cdx(_lib("a", "1"), _lib("b", "1", purl=False), _lib("gone", "1"))
        current = _cdx(_lib("a", "2", purl=False), _lib("b", "1"), _lib("new", "1"))

        drift = self._compare(tmp_path, previous, current)

        assert drift is not None
        assert (drift.added, drift.removed) == (["new@1"], ["gone@1"])
        assert drift.purls == ["a@2: pkg:pypi/a → (none)", "b@1: (none) → pkg:pypi/b"]
        assert drift.changed == ["a 1 → 2"]  # the same package, so its version change still counts
        markdown = drift.markdown()
        assert "**PURL changed:** 2" in markdown
        assert "<summary>PURL changed (2)</summary>" in markdown
        assert "`a@2: pkg:pypi/a → (none)`" in markdown

    def test_a_missing_version_reads_as_none(self, tmp_path):
        """Not `a  → 1`: an empty version vanishes beside the arrow."""
        unversioned, versioned = _cdx(_lib("a", "", purl=False)), _cdx(_lib("a", "1", purl=False))

        gained = self._compare(tmp_path, unversioned, versioned)
        lost = self._compare(tmp_path, versioned, unversioned)

        assert gained is not None and gained.changed == ["a (none) → 1"]
        assert lost is not None and lost.changed == ["a 1 → (none)"]

    def test_lists_are_capped_and_say_how_many_are_left(self, tmp_path):
        previous = _cdx()
        current = _cdx(*(_lib(f"pkg{i:03}", "1.0") for i in range(60)))
        drift = self._compare(tmp_path, previous, current)

        assert drift is not None
        markdown = drift.markdown()
        assert "**Added:** 60" in markdown
        assert "`pkg024@1.0`" in markdown
        assert "`pkg025@1.0`" not in markdown
        assert "and 35 more" in markdown

    def test_a_backtick_in_a_name_cannot_break_out_of_its_code_span(self, tmp_path):
        drift = self._compare(tmp_path, _cdx(), _cdx(_lib("evil`](https://x.test)", "1.0", purl=False)))

        assert drift is not None
        assert "`evil'](https://x.test)@1.0`" in drift.markdown()

    def test_no_drift_against_a_document_it_cannot_read(self, tmp_path):
        """SPDX 3 and VEX get no counts in the summary either."""
        spdx3 = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}
        assert self._compare(tmp_path, spdx3, CURRENT) is None
        assert self._compare(tmp_path, PREVIOUS, spdx3) is None
