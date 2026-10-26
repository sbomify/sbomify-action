"""The sbom-tools release a build fetches from: pinned, overridable, recorded.

A release of this action has to fetch the bundles it was tested against, so
tools.toml pins a cut sbom-tools release; images built from master opt into
tools-rolling through SBOMIFY_TOOLS_RELEASE. These tests hold both halves,
and the bump.
"""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

import pytest

from sbomify_action import tool_manifest
from sbomify_action.tool_manifest import TOOLS_RELEASE, TOOLS_RELEASE_ENV, ManifestError

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "sbomify_action" / "tools.toml"


def _load_check_tool_versions():
    spec = importlib.util.spec_from_file_location("check_tool_versions", REPO_ROOT / "bin" / "check_tool_versions.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _fresh_bundles(monkeypatch):
    """load_bundles is cached; every test here changes what it should return."""
    monkeypatch.delenv(TOOLS_RELEASE_ENV, raising=False)
    tool_manifest.load_bundles.cache_clear()
    tool_manifest._provider_index.cache_clear()
    yield
    tool_manifest.load_bundles.cache_clear()
    tool_manifest._provider_index.cache_clear()


def _use_manifest(monkeypatch, tmp_path: Path, tools_release: str) -> None:
    text = MANIFEST.read_text().replace(
        f'tools_release = "{tool_manifest.pinned_tools_release()}"', f'tools_release = "{tools_release}"'
    )
    path = tmp_path / "tools.toml"
    path.write_text(text)
    monkeypatch.setattr(tool_manifest, "_MANIFEST", path)


class TestThePin:
    def test_the_committed_pin_is_a_cut_release(self):
        pinned = tomllib.loads(MANIFEST.read_text())["tools_release"]
        assert pinned != TOOLS_RELEASE, "master must pin a cut sbom-tools release, not the rolling one"
        assert pinned.startswith("tools-")

    def test_bundles_fetch_from_the_pin_by_default(self):
        pinned = tool_manifest.pinned_tools_release()
        go = tool_manifest.bundle_for("go")
        assert go is not None
        assert go.release == pinned
        assert f"/releases/download/{pinned}/go-linux-amd64.tar.gz" in go.archive_url("amd64")
        assert go.package_url == f"pkg:github/sbomify/sbom-tools@{pinned}#go"

    def test_a_rolling_pin_is_refused(self, monkeypatch, tmp_path):
        _use_manifest(monkeypatch, tmp_path, TOOLS_RELEASE)
        with pytest.raises(ManifestError, match="cut sbom-tools release"):
            tool_manifest.load_bundles()

    @pytest.mark.parametrize("bad", ["", "v1.0.0", "tools-../../evil"])
    def test_a_malformed_pin_is_refused(self, monkeypatch, tmp_path, bad):
        _use_manifest(monkeypatch, tmp_path, bad)
        with pytest.raises(ManifestError):
            tool_manifest.pinned_tools_release()


class TestTheOverride:
    def test_master_images_track_rolling(self, monkeypatch):
        monkeypatch.setenv(TOOLS_RELEASE_ENV, TOOLS_RELEASE)
        go = tool_manifest.bundle_for("go")
        assert go is not None
        assert go.release == TOOLS_RELEASE
        assert go.package_url == f"pkg:github/sbomify/sbom-tools@{TOOLS_RELEASE}#go"

    def test_an_empty_override_means_the_pin(self, monkeypatch):
        monkeypatch.setenv(TOOLS_RELEASE_ENV, "  ")
        go = tool_manifest.bundle_for("go")
        assert go is not None
        assert go.release == tool_manifest.pinned_tools_release()

    @pytest.mark.parametrize("bad", ["latest", "tools-x/../../other", "tools-"])
    def test_an_override_that_is_not_a_release_tag_is_refused(self, monkeypatch, bad):
        """It lands in a download URL path, so it may not steer it elsewhere."""
        monkeypatch.setenv(TOOLS_RELEASE_ENV, bad)
        with pytest.raises(ManifestError, match=TOOLS_RELEASE_ENV):
            tool_manifest.load_bundles()


class TestTheBump:
    def test_the_pin_is_audited(self):
        ctv = _load_check_tool_versions()
        entry = next(t for t in ctv.TOOLS if t.name == ctv.SBOM_TOOLS)
        assert entry.github_repo == "sbomify/sbom-tools"
        assert entry.current_version == tool_manifest.pinned_tools_release().removeprefix("tools-")

    def test_update_rewrites_only_the_pin(self, monkeypatch, tmp_path):
        ctv = _load_check_tool_versions()
        manifest = tmp_path / "sbomify_action" / "tools.toml"
        manifest.parent.mkdir()
        original = MANIFEST.read_text()
        manifest.write_text(original)
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM scratch\n")
        monkeypatch.setattr(ctv.tool_manifest, "__file__", str(manifest.parent / "tool_manifest.py"))

        current = tool_manifest.pinned_tools_release().removeprefix("tools-")
        info = ctv.ToolInfo(
            name=ctv.SBOM_TOOLS,
            env_var="",
            github_repo="sbomify/sbom-tools",
            stage="release",
            current_version=current,
            latest_version="99.1.0",
        )
        assert ctv.update_pins(dockerfile, [info]) == 1

        updated = manifest.read_text()
        assert tomllib.loads(updated)["tools_release"] == "tools-99.1.0"
        assert updated == original.replace(f'"tools-{current}"', '"tools-99.1.0"')
        assert dockerfile.read_text() == "FROM scratch\n"
