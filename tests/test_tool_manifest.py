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
import tomllib

from sbomify_action import runtimes, tool_manifest
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

    body = tomllib.loads(manifest)["tool"]
    restated = sorted(name for name, entry in body.items() if "version" in entry)

    # The JDK is the sole exception, and only because there is nowhere to put
    # it: Temurin is not published to Maven Central or any other registry a
    # lockfile reaches. Asserting the exception list rather than a count means
    # adding a tool with a literal version fails here, instead of quietly
    # nudging a magic number.
    assert restated == ["java"], (
        f"these restate a version instead of reading a native lockfile: {restated}. "
        "A second copy is a second thing to bump, and Dependabot cannot see it."
    )


def test_lockfiles_are_the_ones_dependabot_watches():
    """The manifest must point at files a Dependabot ecosystem covers."""
    root = Path(__file__).resolve().parent.parent
    for rel in (
        "tools/go.mod",
        "tools/go.sum",
        "tools/Cargo.toml",
        "tools/Cargo.lock",
        "tools/pom.xml",
        "tools/rust-toolchain.toml",
        "bun.lock",
        "uv.lock",
    ):
        assert (root / rel).exists(), f"{rel} is missing"

    config = (root / ".github" / "dependabot.yml").read_text()
    # rust-toolchain.toml has no Dependabot ecosystem -- it pins the compiler,
    # not a crate -- so bin/check_tool_versions.py covers it instead.
    for ecosystem in ("gomod", "cargo", "maven", "bun", "uv"):
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
        for arch, arch_assets in tool.assets.items():
            for i, asset in enumerate(arch_assets):
                assert spec.assets[arch][i].digest == asset.digest
                assert spec.assets[arch][i].algorithm == asset.algorithm
                assert spec.assets[arch][i].url == asset.url


def test_runtime_tools_are_absent_from_the_image_sbom():
    """The image does not contain them, so it must not claim them.

    This is the whole reason the build and runtime SBOMs diverge.
    """
    image = set(image_package_urls())
    runtime = set(runtime_package_urls())
    assert runtime, "nothing is fetched at run time, which cannot be right"
    assert image.isdisjoint(runtime)
    for tool in tools_for_stage(STAGE_RUNTIME).values():
        assert tool.package_url not in image


def test_the_image_bakes_in_no_external_tools():
    """Only what is Python-native ships; everything else is fetched.

    syft (83MB) and cargo-cyclonedx (6.9MB) were the last two baked in, and
    neither was ecosystem-agnostic. cargo-cyclonedx was the clearer case: it
    is a cargo *subcommand*, and cargo is fetched on demand, so the image
    carried a binary that could not run without a 92MB download it did not
    have. Both are runtime-stage now, which is what keeps the image at one
    Python runtime plus our package.
    """
    baked = sorted(tools_for_stage(STAGE_IMAGE))
    assert baked == [], (
        f"these are baked into the image: {baked}. Anything not useful to every "
        "ecosystem belongs at runtime stage, fetched by the users who need it."
    )


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
        for arch, arch_assets in tool.assets.items():
            for asset in arch_assets:
                if tool.built:
                    assert asset.attestation, f"{name}/{arch} is ours but has no attestation to verify it"
                    continue
                expected = {"sha256": 64, "sha512": 128}[asset.algorithm]
                assert re.fullmatch(rf"[0-9a-f]{{{expected}}}", asset.digest), (
                    f"{name}/{arch} {asset.algorithm} digest is malformed"
                )
            assert asset.url.startswith("https://"), f"{name}/{arch} must be fetched over https"
            if tool.built:
                # Our own URLs carry the release, not the version --
                # .../tools-rolling/syft-linux-amd64 -- because the release is
                # what says which build these bytes came from. The check below
                # is about vendor URLs drifting from the pinned version.
                continue
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


class TestNativeLockfileReaders:
    """Each reader must pin an exact version, and refuse anything that moves.

    cdxgen is why this class exists. package.json tracked
    ``github:cyclonedx/cdxgen#cc0c694`` -- a branch, resolved to whatever it
    pointed at that day -- while tools.toml advertised
    ``pkg:npm/%40cyclonedx/cdxgen@12.8.2``. Both looked pinned. Neither
    described what shipped.
    """

    def test_bun_lock_yields_the_published_version(self, tmp_path):
        lock = tmp_path / "bun.lock"
        lock.write_text('{ "packages": { "@cyclonedx/cdxgen": ["@cyclonedx/cdxgen@12.8.2", "", {}, "sha512-x"], } }')
        assert tool_manifest._version_from_bun_lock(lock, "@cyclonedx/cdxgen") == "12.8.2"

    def test_bun_lock_refuses_a_git_specifier(self, tmp_path):
        """The exact defect: a branch reference where a release should be."""
        lock = tmp_path / "bun.lock"
        lock.write_text(
            '{ "packages": { "@cyclonedx/cdxgen": ["@cyclonedx/cdxgen@github:cyclonedx/cdxgen#cc0c694", ""], } }'
        )
        with pytest.raises(tool_manifest.ManifestError, match="not a released version"):
            tool_manifest._version_from_bun_lock(lock, "@cyclonedx/cdxgen")

    def test_go_toolchain_directive_wins_over_the_go_minimum(self, tmp_path):
        """``go`` is the oldest toolchain that works, not the one we build with.

        Reading it would have pinned us to 1.26.3 while 1.26.5 was current.
        """
        mod = tmp_path / "go.mod"
        mod.write_text("module x\n\ngo 1.26.3\n\ntoolchain go1.26.5\n")
        assert tool_manifest._version_from_go_toolchain(mod) == "1.26.5"

    def test_go_falls_back_to_the_go_directive(self, tmp_path):
        mod = tmp_path / "go.mod"
        mod.write_text("module x\n\ngo 1.26.3\n")
        assert tool_manifest._version_from_go_toolchain(mod) == "1.26.3"

    def test_rust_toolchain_refuses_a_channel_alias(self, tmp_path):
        """ "stable" is a different compiler every six weeks."""
        toolchain = tmp_path / "rust-toolchain.toml"
        toolchain.write_text('[toolchain]\nchannel = "stable"\n')
        with pytest.raises(tool_manifest.ManifestError, match="exact version"):
            tool_manifest._version_from_rust_toolchain(toolchain)

    def test_rust_toolchain_accepts_an_exact_version(self, tmp_path):
        toolchain = tmp_path / "rust-toolchain.toml"
        toolchain.write_text('[toolchain]\nchannel = "1.97.1"\n')
        assert tool_manifest._version_from_rust_toolchain(toolchain) == "1.97.1"

    def test_uv_lock_and_cargo_lock_share_a_reader(self, tmp_path):
        lock = tmp_path / "uv.lock"
        lock.write_text('[[package]]\nname = "uv"\nversion = "0.12.1"\n')
        assert tool_manifest._version_from_toml_lock(lock, "uv") == "0.12.1"

    def test_an_unknown_lockfile_is_rejected(self):
        with pytest.raises(tool_manifest.ManifestError, match="no reader for"):
            tool_manifest._resolve_version("x", {"version_from": {"file": "README.md"}})
