"""Syft's file catalogers describe files, not software.

Measured across the container images in the survey, they are the
overwhelming majority of what lands in the document:

    eclipse-temurin:21-jre   7,003 components,  6,847 of them `type: file`
    mcr.../dotnet/aspnet:8.0 3,568 components,  3,473 of them files
    nginx:latest             3,379 components,  3,226 of them files

Those entries carry a path and nothing else -- no purl, no version, no
licence, because a file is not a package. They cannot be enriched or matched
to an advisory, and they bury the ~150 packages that can.
"""

import pytest

from sbomify_action._generation.generators.syft import SyftFsGenerator, SyftImageGenerator
from sbomify_action._generation.protocol import GenerationInput


def _captured(monkeypatch):
    seen: dict[str, list[str]] = {}

    def fake_run(cmd, _name, **_kwargs):
        seen["cmd"] = list(cmd)

    monkeypatch.setattr("sbomify_action._generation.generators.syft.run_command", fake_run)
    monkeypatch.setattr("sbomify_action._generation.generators.syft.ensure_runtime", lambda _t: None)
    return seen


def test_an_image_scan_drops_the_file_catalogers(tmp_path, monkeypatch):
    seen = _captured(monkeypatch)
    out = tmp_path / "out.json"
    out.write_text("{}")

    SyftImageGenerator().generate(
        GenerationInput(docker_image="alpine:3", output_file=str(out), output_format="cyclonedx")
    )

    cmd = seen["cmd"]
    assert "--select-catalogers" in cmd
    assert cmd[cmd.index("--select-catalogers") + 1] == "-file"


def test_a_lockfile_scan_drops_them_too(tmp_path, monkeypatch):
    """A lock file scan emits file entries as well -- fewer, but the same kind."""
    seen = _captured(monkeypatch)
    lock = tmp_path / "Gemfile.lock"
    lock.write_text("")
    out = tmp_path / "out.json"
    out.write_text("{}")

    SyftFsGenerator().generate(GenerationInput(lock_file=str(lock), output_file=str(out), output_format="cyclonedx"))

    cmd = seen["cmd"]
    assert "--select-catalogers" in cmd
    assert cmd[cmd.index("--select-catalogers") + 1] == "-file"


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_the_flag_is_passed_for_either_format(tmp_path, monkeypatch, fmt):
    """SPDX output is unchanged by it, but the flag must not be format-conditional.

    Syft's SPDX writer lists files from package ownership rather than from
    these catalogers, so the same scan reports 17 packages and 79 files
    either way. Passing the flag regardless keeps one code path.
    """
    seen = _captured(monkeypatch)
    out = tmp_path / "out.json"
    out.write_text("{}")

    SyftImageGenerator().generate(GenerationInput(docker_image="alpine:3", output_file=str(out), output_format=fmt))

    assert "--select-catalogers" in seen["cmd"]
