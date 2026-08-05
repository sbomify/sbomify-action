"""A manifest beside its lock file must be read as the lock file.

Both behaviours here were found by generating SBOMs for every lock file name
the README promises, against real projects. Half the names had never been
tested, and these were what that turned up: documents that were valid, exited
zero, and contained nothing worth having.
"""

from __future__ import annotations

import json

from sbomify_action._generation.generators.gradle_lockfile import GradleLockfileGenerator, parse_lockfile
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.registry import LOCKFILE_FOR_MANIFEST, promote_to_lockfile


class TestManifestsDeferToTheirLockFile:
    """pyproject.toml, package.json, composer.json, Package.swift, go.sum."""

    def test_the_lock_file_beside_a_manifest_is_what_gets_read(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "package-lock.json").write_text("{}")
        promoted = promote_to_lockfile(
            GenerationInput(lock_file=str(tmp_path / "package.json"), output_file="out.json")
        )
        assert promoted.lock_file == str(tmp_path / "package-lock.json")

    def test_a_manifest_alone_is_left_alone(self, tmp_path):
        """Promotion must not invent a file. Without the sibling, nothing changes."""
        (tmp_path / "package.json").write_text("{}")
        original = GenerationInput(lock_file=str(tmp_path / "package.json"), output_file="out.json")
        assert promote_to_lockfile(original).lock_file == original.lock_file

    def test_a_lock_file_is_never_demoted(self, tmp_path):
        """Only manifests are promoted; a lock file named directly stays put."""
        (tmp_path / "package-lock.json").write_text("{}")
        original = GenerationInput(lock_file=str(tmp_path / "package-lock.json"), output_file="out.json")
        assert promote_to_lockfile(original).lock_file == original.lock_file

    def test_the_first_present_candidate_wins(self, tmp_path):
        """Order matters: package-lock.json before yarn.lock, both present."""
        for name in ("package.json", "yarn.lock", "package-lock.json"):
            (tmp_path / name).write_text("{}")
        promoted = promote_to_lockfile(
            GenerationInput(lock_file=str(tmp_path / "package.json"), output_file="out.json")
        )
        assert promoted.lock_file.endswith("package-lock.json")

    def test_every_candidate_is_a_name_the_readme_documents(self):
        """A promotion target nothing else supports would route into a dead end."""
        from sbomify_action._generation.utils import CDXGEN_LOCK_FILES

        known = set(CDXGEN_LOCK_FILES) | {"go.mod", "Package.resolved", "poetry.lock", "uv.lock", "Pipfile.lock"}
        for manifest, candidates in LOCKFILE_FOR_MANIFEST.items():
            for candidate in candidates:
                assert candidate in known, f"{manifest} promotes to {candidate}, which nothing claims"


class TestGradleLockfileIsReadNotRebuilt:
    """gradle.lockfile is the resolved graph; running Gradle again is optional."""

    LOCKFILE = """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
ch.qos.logback:logback-classic:1.3.14=compileClasspath,runtimeClasspath
com.fasterxml.jackson.core:jackson-core:2.16.2=deps,runtimeClasspath
org.projectlombok:lombok:1.18.30=annotationProcessor
empty=testAnnotationProcessor
"""

    def test_it_reads_the_pinned_coordinates(self, tmp_path):
        path = tmp_path / "gradle.lockfile"
        path.write_text(self.LOCKFILE)
        found = parse_lockfile(path)
        assert ("ch.qos.logback", "logback-classic", "1.3.14") in found
        assert ("com.fasterxml.jackson.core", "jackson-core", "2.16.2") in found

    def test_build_only_configurations_are_left_out(self, tmp_path):
        """An annotation processor is not part of what ships."""
        path = tmp_path / "gradle.lockfile"
        path.write_text(self.LOCKFILE)
        assert not [entry for entry in parse_lockfile(path) if entry[1] == "lombok"]

    def test_the_empty_marker_is_not_a_dependency(self, tmp_path):
        """`empty=<configuration>` records a configuration that resolved to nothing."""
        path = tmp_path / "gradle.lockfile"
        path.write_text(self.LOCKFILE)
        assert not [entry for entry in parse_lockfile(path) if "empty" in entry]

    def test_it_produces_a_document_without_running_gradle(self, tmp_path):
        """No wrapper, no JDK, no network -- the file already has the answer."""
        path = tmp_path / "gradle.lockfile"
        path.write_text(self.LOCKFILE)
        output = tmp_path / "sbom.json"
        result = GradleLockfileGenerator().generate(
            GenerationInput(lock_file=str(path), output_file=str(output), output_format="cyclonedx")
        )
        assert result.success
        document = json.loads(output.read_text())
        purls = {component["purl"] for component in document["components"]}
        assert "pkg:maven/ch.qos.logback/logback-classic@1.3.14" in purls
        assert all(component["purl"].startswith("pkg:maven/") for component in document["components"])

    def test_it_claims_gradle_lockfile_and_nothing_else(self, tmp_path):
        generator = GradleLockfileGenerator()
        assert generator.supports(GenerationInput(lock_file=str(tmp_path / "gradle.lockfile"), output_file="o.json"))
        assert not generator.supports(GenerationInput(lock_file=str(tmp_path / "build.gradle"), output_file="o.json"))

    def test_it_outranks_the_plugin_that_has_to_run_the_build(self):
        """Reading the lock file is both cheaper and more reliable, so it goes first."""
        from sbomify_action._generation.generators.cyclonedx_jvm import CycloneDXGradleGenerator

        assert GradleLockfileGenerator().priority <= CycloneDXGradleGenerator().priority


class TestDirectoriesCanBeScanned:
    """The action had three input kinds and none of them was "a directory".

    That meant it could not describe an unpacked release bundle, a vendored
    tree, or any build output that is not a lock file, an SBOM or a container
    image -- and describing sbomify's own shipped bundles meant reaching past
    the action to raw syft. Syft treats a directory as its native subject.
    """

    def test_syft_claims_a_directory(self, tmp_path, monkeypatch):
        from sbomify_action._generation.generators import syft as syft_module
        from sbomify_action._generation.generators.syft import SyftFsGenerator

        # Whether syft is installed on the machine running the tests is not
        # what this asserts. It passed locally and failed in CI purely on that.
        monkeypatch.setattr(syft_module, "_SYFT_AVAILABLE", True)
        target = tmp_path / "unpacked"
        target.mkdir()
        assert SyftFsGenerator().supports(
            GenerationInput(lock_file=str(target), output_file="o.json", output_format="cyclonedx")
        )

    def test_an_unknown_file_is_still_declined(self, tmp_path, monkeypatch):
        """Claiming directories must not turn syft into a generator for anything."""
        from sbomify_action._generation.generators import syft as syft_module
        from sbomify_action._generation.generators.syft import SyftFsGenerator

        monkeypatch.setattr(syft_module, "_SYFT_AVAILABLE", True)
        stray = tmp_path / "notes.txt"
        stray.write_text("hello")
        assert not SyftFsGenerator().supports(
            GenerationInput(lock_file=str(stray), output_file="o.json", output_format="cyclonedx")
        )

    def test_the_subject_is_prefixed_so_syft_cannot_guess_wrong(self, tmp_path, monkeypatch):
        """A bare path that looks like an image reference gets fetched as one.

        That is how bun.lock was handed to a container registry: syft infers
        the source type from the string. `dir:` states it.
        """
        from sbomify_action._generation.generators import syft as syft_module

        recorded: dict = {}

        def fake_run(cmd, *args, **kwargs):
            recorded["cmd"] = cmd
            raise RuntimeError("stop here -- the argument is what matters")

        monkeypatch.setattr(syft_module, "run_command", fake_run)
        monkeypatch.setattr(syft_module, "ensure_runtime", lambda *_a, **_k: None)
        target = tmp_path / "bundle"
        target.mkdir()
        try:
            syft_module.SyftFsGenerator().generate(
                GenerationInput(lock_file=str(target), output_file=str(tmp_path / "o.json"))
            )
        except Exception:
            pass
        assert f"dir:{target}" in recorded.get("cmd", [])
