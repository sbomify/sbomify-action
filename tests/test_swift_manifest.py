"""Package.swift alone can only ever produce an empty SBOM.

Syft is the only generator that claims it -- cdxgen deliberately excludes
SwiftPM, and no Swift toolchain ships in the image -- and syft cannot
resolve a manifest. Measured across nine Swift projects, every one produced
zero components: swift-nio, swift-collections, swift-package-manager,
swift-log, swift-argument-parser, SwiftyJSON among them. Pointed at the
Package.resolved beside it, the same tool works.
"""

import pytest

from sbomify_action._generation.generators.syft import (
    SyftFsGenerator,
    _swift_manifest_without_resolved,
)
from sbomify_action._generation.protocol import GenerationInput


def _input(tmp_path, name="Package.swift"):
    return GenerationInput(
        lock_file=str(tmp_path / name),
        output_file=str(tmp_path / "out.json"),
        output_format="cyclonedx",
    )


def test_package_swift_alone_is_declined(tmp_path):
    (tmp_path / "Package.swift").write_text("// swift-tools-version:5.9")

    declined = _swift_manifest_without_resolved(_input(tmp_path))

    assert declined is not None
    assert declined.declined, "a decline hands on; a failure would abort the run"
    assert "Package.resolved" in declined.error_message
    assert "swift package resolve" in declined.error_message, "the message has to say how to produce the missing file"


def test_package_swift_beside_resolved_is_not_declined(tmp_path):
    """promote_to_lockfile redirects in this case, so syft must stay out of the way."""
    (tmp_path / "Package.swift").write_text("// swift-tools-version:5.9")
    (tmp_path / "Package.resolved").write_text("{}")

    assert _swift_manifest_without_resolved(_input(tmp_path)) is None


def test_package_resolved_itself_is_not_declined(tmp_path):
    (tmp_path / "Package.resolved").write_text("{}")

    assert _swift_manifest_without_resolved(_input(tmp_path, "Package.resolved")) is None


@pytest.mark.parametrize("name", ["Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock"])
def test_other_lockfiles_are_untouched(tmp_path, name):
    """The check must not become a general veto on manifests."""
    (tmp_path / name).write_text("")

    assert _swift_manifest_without_resolved(_input(tmp_path, name)) is None


def test_a_directory_scan_is_untouched(tmp_path):
    """A source-dir scan is syft's own subject and has no lock file to judge."""
    scanned = GenerationInput(
        source_dir=str(tmp_path),
        output_file=str(tmp_path / "out.json"),
        output_format="cyclonedx",
    )

    assert _swift_manifest_without_resolved(scanned) is None


def test_the_generator_declines_rather_than_running_syft(tmp_path, monkeypatch):
    """End to end: nothing is executed and the caller is told why."""
    (tmp_path / "Package.swift").write_text("// swift-tools-version:5.9")

    def fail(*_args, **_kwargs):
        raise AssertionError("syft must not run for a manifest it cannot resolve")

    monkeypatch.setattr("sbomify_action._generation.generators.syft.ensure_runtime", fail)
    monkeypatch.setattr("sbomify_action._generation.generators.syft.run_command", fail)

    result = SyftFsGenerator().generate(_input(tmp_path))

    assert result.declined
    assert not result.success
