"""The tool manifest must stay the single source of truth.

Versions, download locations and digests used to be restated in four places.
They drifted: moving cosign and crane to on-demand fetching dropped them out
of version monitoring entirely, and bomctl stayed declared in our own SBOM
after it had been removed from the image. These tests make each of those
failure modes fail loudly instead of silently.
"""

import re
from pathlib import Path

import pytest

from sbomify_action import runtimes
from sbomify_action.tool_manifest import (
    STAGE_BUILD,
    STAGE_IMAGE,
    STAGE_RUNTIME,
    ManifestError,
    image_package_urls,
    load_tools,
    runtime_package_urls,
    tools_for_stage,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"


def test_versions_come_from_native_lockfiles_on_master():
    """Tool versions must not be restated in tools.toml.

    A second copy is a second thing to bump, and Dependabot cannot see a
    bespoke file -- which is the whole reason these live in tools/go.mod and
    tools/Cargo.lock. The image build freezes them in (see
    scripts/freeze_tool_versions.py), so this only holds on a source tree.
    """
    manifest = (Path(__file__).resolve().parent.parent / "sbomify_action" / "tools.toml").read_text()
    if "frozen from the lockfile" in manifest:
        pytest.skip("manifest is frozen; this is a built artifact, not a source tree")

    for name in ("syft", "cargo-cyclonedx", "cosign", "crane", "maven"):
        assert f"[tool.{name}]" in manifest
    # Every tool with a native manifest must declare where its version lives:
    # syft, cosign, crane (go.mod), cargo-cyclonedx (Cargo.lock), maven (pom.xml).
    assert manifest.count("version_from") == 5


def test_lockfiles_are_the_ones_dependabot_watches():
    """The manifest must point at files a Dependabot ecosystem covers."""
    root = Path(__file__).resolve().parent.parent
    for rel in ("tools/go.mod", "tools/go.sum", "tools/Cargo.toml", "tools/Cargo.lock", "tools/pom.xml"):
        assert (root / rel).exists(), f"{rel} is missing"

    config = (root / ".github" / "dependabot.yml").read_text()
    for ecosystem in ("gomod", "cargo", "maven"):
        assert f'package-ecosystem: "{ecosystem}"' in config, f"{ecosystem} is not configured"


def test_manifest_loads_and_validates():
    tools = load_tools()
    assert tools, "manifest defines no tools"
    for name, tool in tools.items():
        assert tool.version, f"{name} has no version"
        assert tool.stage in (STAGE_IMAGE, STAGE_RUNTIME, STAGE_BUILD)
        assert "{version}" in tool.purl or tool.version in tool.purl


def test_dockerfile_versions_match_the_manifest():
    """A pin bumped in one place and not the other is a silent mismatch.

    The Dockerfile still has to carry literal ARGs -- it cannot read TOML --
    so this is what keeps the two honest.
    """
    content = DOCKERFILE.read_text()
    args = dict(re.findall(r"ARG\s+(\w+_VERSION)=(\S+)", content))

    for name, tool in load_tools().items():
        if not tool.dockerfile_arg:
            continue
        assert tool.dockerfile_arg in args, (
            f"{name}: manifest names ARG {tool.dockerfile_arg}, which the Dockerfile does not define"
        )
        assert args[tool.dockerfile_arg] == tool.version, (
            f"{name}: Dockerfile has {tool.dockerfile_arg}={args[tool.dockerfile_arg]} "
            f"but the manifest pins {tool.version}"
        )


def test_every_dockerfile_version_arg_is_declared():
    """A tool added to the image without a manifest entry is invisible.

    It would be absent from the SBOM and from version monitoring -- which is
    how bun ended up shipping in the image but missing from its own SBOM.
    """
    content = DOCKERFILE.read_text()
    args = {a for a, _ in re.findall(r"ARG\s+(\w+_VERSION)=(\S+)", content)}
    declared = {t.dockerfile_arg for t in load_tools().values() if t.dockerfile_arg}

    assert args - declared == set(), f"Dockerfile pins versions not in tools.toml: {sorted(args - declared)}"


def test_runtimes_are_built_from_the_manifest():
    """runtimes.py must not carry its own copy of the pins."""
    manifest_runtime = tools_for_stage(STAGE_RUNTIME)
    assert set(runtimes.RUNTIMES) == set(manifest_runtime)
    for name, spec in runtimes.RUNTIMES.items():
        tool = manifest_runtime[name]
        assert spec.version == tool.version
        assert tool.assets is not None
        for arch, asset in tool.assets.items():
            assert spec.assets[arch].digest == asset.digest
            assert spec.assets[arch].algorithm == asset.algorithm
            assert spec.assets[arch].url == asset.url


def test_runtime_tools_are_absent_from_the_image_sbom():
    """The image does not contain them, so it must not claim them.

    This is the whole reason the build and runtime SBOMs diverge.
    """
    image = set(image_package_urls())
    runtime = set(runtime_package_urls())
    assert image and runtime
    assert image.isdisjoint(runtime)
    for tool in tools_for_stage(STAGE_RUNTIME).values():
        assert tool.package_url not in image


def test_build_only_tools_are_not_claimed_as_shipped():
    """uv builds the image but is not in it."""
    for tool in tools_for_stage(STAGE_BUILD).values():
        assert not tool.ships_in_image
        assert tool.package_url not in image_package_urls()


def test_every_runtime_tool_can_actually_be_fetched():
    """Missing assets would only surface on the first machine that needed them."""
    for name, tool in tools_for_stage(STAGE_RUNTIME).items():
        assert tool.assets, f"{name} has no assets"
        assert set(tool.assets) == {"amd64", "arm64"}, f"{name} is missing an architecture"
        for arch, asset in tool.assets.items():
            expected = {"sha256": 64, "sha512": 128}[asset.algorithm]
            assert re.fullmatch(rf"[0-9a-f]{{{expected}}}", asset.digest), (
                f"{name}/{arch} {asset.algorithm} digest is malformed"
            )
            assert asset.url.startswith("https://"), f"{name}/{arch} must be fetched over https"
            # Vendors spell the same version differently in a URL: Adoptium
            # uses both 21.0.12%2B8 and 21.0.12_8 for 21.0.12+8. Accept any
            # encoding of the separator, but insist the version is in there --
            # a bump that left the URL behind would fetch the old binary and
            # still pass its checksum, which is the worst possible outcome.
            candidates = {
                tool.version,
                tool.version.replace("+", "%2B"),
                tool.version.replace("+", "_"),
                tool.version.replace("+", "-"),
                tool.version.replace("+", "."),
            }
            assert any(c in asset.url for c in candidates), (
                f"{name}/{arch}: url does not mention {tool.version} in any encoding"
            )


def test_monitorable_tools_declare_an_upstream():
    """Without github_repo a tool silently stops being version-checked."""
    unmonitored = [n for n, t in load_tools().items() if not t.github_repo]
    assert unmonitored == [], f"tools with no upstream to check: {unmonitored}"


def test_unknown_stage_is_rejected():
    with pytest.raises(ManifestError):
        tools_for_stage("nonsense")
