"""What a finished run tells the CI system: job summary, step outputs, annotations.

A green run used to look the same whether it produced 400 enriched components
or none. These pin what GitHub Actions now shows, and that every other
platform is left alone.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.text import Text

from sbomify_action._runtime import use_platform
from sbomify_action._runtime.platforms import BitbucketPlatform, GitHubPlatform, GitLabPlatform, LocalPlatform
from sbomify_action._upload.result import UploadResult
from sbomify_action.cli.main import build_config, run_pipeline
from sbomify_action.console import AuditTrail, console, reset_audit_trail
from sbomify_action.logging_config import warning_annotations

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {"component": {"type": "application", "name": "app", "version": "1.0.0"}},
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {"type": "library", "name": "idna", "version": "3.7", "purl": "pkg:pypi/idna@3.7"},
    ],
}


def _read_outputs(path: Path) -> dict[str, str]:
    """Parse GITHUB_OUTPUT the way the runner does: ``name=value`` or a heredoc."""
    outputs: dict[str, str] = {}
    lines = iter(path.read_text(encoding="utf-8").splitlines())
    for line in lines:
        equals, heredoc = line.find("="), line.find("<<")
        if equals >= 0 and (heredoc < 0 or equals < heredoc):
            outputs[line[:equals]] = line[equals + 1 :]
            continue
        name, delimiter = line[:heredoc], line[heredoc + 2 :]
        value: list[str] = []
        for body in lines:
            if body == delimiter:
                break
            value.append(body)
        outputs[name] = "\n".join(value)
    return outputs


@pytest.fixture
def github_files(tmp_path, monkeypatch):
    """Point the runner's summary and output files at temp files."""
    summary, outputs = tmp_path / "summary.md", tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    return summary, outputs


def _run(tmp_path, monkeypatch, **overrides):
    monkeypatch.chdir(tmp_path)
    reset_audit_trail()
    warning_annotations.reset()
    source = tmp_path / "input.cdx.json"
    source.write_text(json.dumps(SBOM), encoding="utf-8")
    kwargs = dict(sbom_file=str(source), upload=False, output_file="sbom.cdx.json")
    kwargs.update(overrides)
    run_pipeline(build_config(**kwargs))


def test_github_run_writes_a_job_summary(tmp_path, monkeypatch, github_files):
    """Format, file, component count, enrichment, upload state, warnings and coverage."""
    summary, _ = github_files
    with use_platform(GitHubPlatform()):
        _run(tmp_path, monkeypatch)

    text = summary.read_text(encoding="utf-8")
    assert "CycloneDX 1.6" in text
    assert "`sbom.cdx.json`" in text
    assert "**Components:** 2" in text
    assert "0 of 2 components" in text
    assert "`ENRICH=true`" in text  # says why nothing was enriched
    assert "`UPLOAD=false`" in text
    assert "**Warnings:**" in text
    assert "| License | 1 of 2 (50%) | 1 of 2 (50%) |" in text
    assert "| Supplier | 0 of 2 (0%) | 0 of 2 (0%) |" in text
    assert len(text.encode()) < 4096  # aggregates only, nowhere near GitHub's 1 MiB


def test_github_run_writes_step_outputs(tmp_path, monkeypatch, github_files):
    """File, format and component count, for later steps to use."""
    _, outputs = github_files
    with use_platform(GitHubPlatform()):
        _run(tmp_path, monkeypatch)

    assert _read_outputs(outputs) == {
        "sbom-file": "sbom.cdx.json",
        "sbom-format": "cyclonedx",
        "component-count": "2",
    }


def test_an_upload_adds_the_sbom_id_and_a_link_into_the_app(tmp_path, monkeypatch, github_files):
    """After an upload the summary links to the component, and the outputs carry it."""
    summary, outputs = github_files
    uploaded = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-123")
    with use_platform(GitHubPlatform()), patch("sbomify_action.cli.main.upload_sbom", return_value=uploaded):
        _run(tmp_path, monkeypatch, upload=True, token="tok", component_id="comp-1")

    url = "https://app.sbomify.com/component/comp-1/"
    assert f"({url})" in summary.read_text(encoding="utf-8")
    written = _read_outputs(outputs)
    assert written["sbom-id"] == "sbom-123"
    assert written["component-url"] == url


@pytest.mark.parametrize("platform", [GitLabPlatform(), BitbucketPlatform(), LocalPlatform()], ids=lambda p: p.name)
def test_other_platforms_write_nothing(tmp_path, monkeypatch, github_files, platform):
    """Only GitHub Actions has these files; nobody else's run touches them."""
    summary, outputs = github_files
    with use_platform(platform), patch("builtins.print") as printed:
        _run(tmp_path, monkeypatch)

    assert not summary.exists()
    assert not outputs.exists()
    assert not [c for c in printed.call_args_list if c.args and str(c.args[0]).startswith("::")]


def test_a_summary_that_cannot_be_written_does_not_fail_the_run(tmp_path, monkeypatch, github_files):
    """The SBOM is already on disk; a missing summary file is not worth a red build."""
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "missing-dir" / "summary.md"))
    with use_platform(GitHubPlatform()):
        _run(tmp_path, monkeypatch)

    assert (tmp_path / "sbom.cdx.json").exists()


def _warning_from(lineno: int) -> logging.LogRecord:
    return logging.LogRecord("sbomify_action", logging.WARNING, "/src/x.py", lineno, f"warning {lineno}", None, None)


class TestWarningAnnotations:
    """Run-level warnings reach the run page, a few at a time."""

    def setup_method(self):
        warning_annotations.reset()

    def _annotations(self, printed) -> list[str]:
        return [str(c.args[0]) for c in printed.call_args_list if c.args and str(c.args[0]).startswith("::warning")]

    def test_a_logged_warning_becomes_an_annotation_on_github(self):
        with use_platform(GitHubPlatform()), patch("builtins.print") as printed:
            logging.getLogger("sbomify_action").warning("lock file substituted")

        assert self._annotations(printed) == ["::warning::lock file substituted"]
        assert warning_annotations.count == 1

    def test_a_warning_repeated_per_component_is_annotated_once(self):
        """One call site, logged for every component: one annotation, every one counted."""
        with use_platform(GitHubPlatform()), patch("builtins.print") as printed:
            for _ in range(50):
                warning_annotations.handle(_warning_from(7))

        assert len(self._annotations(printed)) == 1
        assert warning_annotations.count == 50

    def test_annotations_stop_at_ten_and_the_summary_has_the_rest(self, tmp_path, monkeypatch, github_files):
        summary, _ = github_files
        with use_platform(GitHubPlatform()), patch("builtins.print") as printed:
            for lineno in range(15):
                warning_annotations.handle(_warning_from(lineno))
            assert len(self._annotations(printed)) == 10

            monkeypatch.chdir(tmp_path)
            source = tmp_path / "input.cdx.json"
            source.write_text(json.dumps(SBOM), encoding="utf-8")
            run_pipeline(build_config(sbom_file=str(source), upload=False, output_file="sbom.cdx.json"))

        # The run may log warnings of its own; whatever the total, ten were annotated.
        assert len(self._annotations(printed)) == 10
        assert f"+{warning_annotations.count - 10} more" in summary.read_text(encoding="utf-8")

    def test_annotation_text_cannot_inject_a_workflow_command(self):
        """A newline would end the annotation and start a line the runner obeys."""
        with use_platform(GitHubPlatform()), patch("builtins.print") as printed:
            logging.getLogger("sbomify_action").warning("bad name\n::add-mask::x 100%")

        (annotation,) = self._annotations(printed)
        assert "\n" not in annotation
        assert annotation.startswith("::warning::bad name%0A")
        assert annotation.endswith("x 100%25")

    def test_other_platforms_count_but_do_not_annotate(self):
        """The log line is already all a plain CI log can show."""
        with use_platform(GitLabPlatform()), patch("builtins.print") as printed:
            warning_annotations.handle(_warning_from(1))

        assert self._annotations(printed) == []
        assert warning_annotations.count == 1


class TestEnrichedComponents:
    """The "Components enriched" row counts components, not the fields they gained."""

    def _trail(self) -> AuditTrail:
        trail = AuditTrail()
        trail.record_component_enriched("pkg:pypi/requests@2.31.0", [f"field{i}" for i in range(16)], "pypi")
        trail.record_component_enriched("pkg:pypi/idna@3.7", [f"field{i}" for i in range(14)], "pypi")
        trail.record_hash_added("pkg:pypi/idna@3.7", "sha256")
        trail.record_enrichment("pkg:pypi/urllib3@2.2.0", "transitive_dependency", "via requests", "pipdeptree")
        return trail

    def test_two_components_are_two_however_many_fields_they_gained(self):
        assert self._trail().enrichment_counts() == (2, 31)

    def test_the_summary_table_labels_fields_as_fields(self):
        with console.capture() as captured:
            self._trail().print_summary()

        rows = {}
        # from_ansi: under GitHub Actions the shared console forces colour on.
        for line in Text.from_ansi(captured.get()).plain.splitlines():
            cells = [cell.strip() for cell in line.split("│")]
            if len(cells) == 4:
                rows[cells[1]] = cells[2]
        assert rows["Components enriched"] == "2"
        assert rows["Enrichment fields added"] == "31"
