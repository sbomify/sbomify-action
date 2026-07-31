"""Tests for the CycloneDXCargoGenerator plugin."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sbomify_action._generation import (
    GenerationInput,
    GeneratorRegistry,
    create_default_registry,
)
from sbomify_action._generation.generators import (
    CdxgenFsGenerator,
    CycloneDXCargoGenerator,
    TrivyFsGenerator,
)
from sbomify_action._generation.protocol import (
    CARGO_CYCLONEDX_DEFAULT,
    CARGO_CYCLONEDX_VERSIONS,
)
from sbomify_action.exceptions import SBOMGenerationError


@patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", True)
class TestCycloneDXCargoGenerator(unittest.TestCase):
    """Tests for CycloneDXCargoGenerator.

    The class-level patch forces ``_CARGO_CYCLONEDX_AVAILABLE=True`` so the
    ``supports()`` tests exercise the lock-file/format/version logic regardless
    of whether cargo-cyclonedx happens to be installed in the test env (it
    usually isn't — it's a Rust tool). Mirrors the pattern used for the
    syft/cyclonedx-py generators in test_generation_plugin.py.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CycloneDXCargoGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "cyclonedx-cargo")
        self.assertEqual(self.generator.priority, 10)

    def test_supported_formats(self):
        """Test supported formats."""
        formats = self.generator.supported_formats
        self.assertEqual(len(formats), 1)
        self.assertEqual(formats[0].format, "cyclonedx")
        self.assertEqual(formats[0].versions, CARGO_CYCLONEDX_VERSIONS)
        self.assertEqual(formats[0].default_version, CARGO_CYCLONEDX_DEFAULT)

    def test_supports_cargo_lock(self):
        """Test support for Cargo.lock files."""
        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_format="cyclonedx")
        self.assertTrue(self.generator.supports(gen_input))

    def test_does_not_support_other_lock_files(self):
        """Test that other lock files are not supported."""
        for lock_file in ["requirements.txt", "poetry.lock", "package.json", "go.mod"]:
            gen_input = GenerationInput(lock_file=f"/path/{lock_file}", output_format="cyclonedx")
            self.assertFalse(self.generator.supports(gen_input), f"Should not support {lock_file}")

    def test_does_not_support_spdx(self):
        """Test that SPDX format is not supported."""
        gen_input = GenerationInput(lock_file="/path/Cargo.lock", output_format="spdx")
        self.assertFalse(self.generator.supports(gen_input))

    def test_does_not_support_docker_images(self):
        """Test that Docker images are not supported."""
        gen_input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(gen_input))

    def test_supports_version_1_4(self):
        """Test support for CycloneDX 1.4."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.4",
        )
        self.assertTrue(self.generator.supports(gen_input))

    def test_supports_version_1_5(self):
        """Test support for CycloneDX 1.5."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.5",
        )
        self.assertTrue(self.generator.supports(gen_input))

    def test_declines_version_1_6(self):
        """1.6 must be declined: cargo-cyclonedx cannot emit it.

        `cargo-cyclonedx --help` offers only 1.3, 1.4 and 1.5. Claiming 1.6 made
        supports() accept a request the binary then rejected with
        "invalid value '1.6' for '--spec-version'". Declining lets the
        orchestrator fall through to cdxgen, which does emit 1.6.
        """
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.6",
        )
        self.assertFalse(self.generator.supports(gen_input))

    def test_supports_version_1_3(self):
        """1.3 is supported by the tool and was previously not advertised."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.3",
        )
        self.assertTrue(self.generator.supports(gen_input))

    def test_default_version_is_one_the_tool_accepts(self):
        """The default is used when no spec_version is requested, so a default
        the binary rejects breaks every unqualified invocation."""
        from sbomify_action._generation.protocol import (
            CARGO_CYCLONEDX_DEFAULT,
            CARGO_CYCLONEDX_VERSIONS,
        )

        self.assertIn(CARGO_CYCLONEDX_DEFAULT, CARGO_CYCLONEDX_VERSIONS)
        self.assertEqual(CARGO_CYCLONEDX_VERSIONS, ("1.3", "1.4", "1.5"))

    def test_does_not_support_unsupported_versions(self):
        """Test that unsupported versions are rejected."""
        for version in ["1.0", "1.1", "1.2", "1.6", "1.7", "2.0"]:
            gen_input = GenerationInput(
                lock_file="/path/Cargo.lock",
                output_format="cyclonedx",
                spec_version=version,
            )
            self.assertFalse(
                self.generator.supports(gen_input),
                f"Should not support version {version}",
            )

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_generate_success(self, mock_run):
        """Test successful generation against a real directory.

        Uses a temp project rather than mocking Path: the generator moves the
        file cargo-cyclonedx writes into the project, and a mocked Path cannot
        exercise that.
        """
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "Cargo.lock").write_text("")
            output = Path(tmp) / "sbom.json"

            def _run(cmd, name, timeout=None, cwd=None):
                stem = cmd[cmd.index("--override-filename") + 1]
                (Path(cwd) / f"{stem}.json").write_text('{"bomFormat": "CycloneDX"}')
                return MagicMock(returncode=0)

            mock_run.side_effect = _run
            gen_input = GenerationInput(lock_file=str(project / "Cargo.lock"), output_file=str(output))
            result = self.generator.generate(gen_input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, CARGO_CYCLONEDX_DEFAULT)
        self.assertEqual(result.generator_name, "cyclonedx-cargo")

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_generate_failure(self, mock_run):
        """Test generation failure."""
        mock_run.return_value = MagicMock(returncode=1, stderr="Error message")

        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_file="sbom.json")
        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)
        self.assertEqual(result.generator_name, "cyclonedx-cargo")

    def test_unsupported_version_returns_failure(self):
        """Test that unsupported version returns failure result."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="2.0",  # Invalid version
        )

        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIn("Unsupported CycloneDX version", result.error_message)


@patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", True)
class TestCycloneDXCargoGeneratorPriority(unittest.TestCase):
    """Tests for CycloneDXCargoGenerator priority in registry.

    Forces ``_CARGO_CYCLONEDX_AVAILABLE=True`` so ``get_generators_for`` (which
    filters on ``supports()``) includes the cargo generator regardless of
    whether the Rust tool is installed in the test env.
    """

    def test_cargo_generator_is_registered(self):
        """Test that CycloneDXCargoGenerator is in default registry."""
        registry = create_default_registry()
        generators = registry.list_generators()

        names = [g["name"] for g in generators]
        self.assertIn("cyclonedx-cargo", names)

    def test_cargo_generator_priority_10(self):
        """Test that CycloneDXCargoGenerator has priority 10."""
        registry = create_default_registry()
        generators = registry.list_generators()

        cargo_gen = next(g for g in generators if g["name"] == "cyclonedx-cargo")
        self.assertEqual(cargo_gen["priority"], 10)

    def test_cargo_generator_preferred_for_cargo_lock(self):
        """Test that CycloneDXCargoGenerator is preferred over cdxgen/Trivy/Syft for Cargo.lock."""
        registry = create_default_registry()

        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
        )

        generators = registry.get_generators_for(gen_input)

        # First generator should be cyclonedx-cargo (priority 10)
        self.assertGreater(len(generators), 0)
        self.assertEqual(generators[0].name, "cyclonedx-cargo")

    @patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
    @patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
    def test_registry_order_for_cargo_lock(self):
        """Test the expected order of generators for Cargo.lock."""
        registry = GeneratorRegistry()
        registry.register(TrivyFsGenerator())  # Priority 30
        registry.register(CdxgenFsGenerator())  # Priority 20
        registry.register(CycloneDXCargoGenerator())  # Priority 10

        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
        )

        generators = registry.get_generators_for(gen_input)

        # Should be in priority order: cyclonedx-cargo (10), cdxgen (20), trivy (30)
        self.assertEqual(len(generators), 3)
        self.assertEqual(generators[0].name, "cyclonedx-cargo")
        self.assertEqual(generators[1].name, "cdxgen-fs")
        self.assertEqual(generators[2].name, "trivy-fs")


class TestCycloneDXCargoToolAvailability(unittest.TestCase):
    """Availability-guard regression tests (kept out of the class-patched
    classes so the False case isn't masked by a class-level True patch)."""

    @patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", False)
    def test_does_not_support_when_tool_missing(self):
        """When cargo-cyclonedx isn't installed, supports() must return False so
        the orchestrator falls through to a generic generator instead of
        picking cargo-cyclonedx and failing at generate() time with a spurious
        ERROR. Mirrors the cyclonedx-py / syft availability guards."""
        generator = CycloneDXCargoGenerator()
        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_format="cyclonedx")
        self.assertFalse(generator.supports(gen_input))

    @patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", True)
    def test_supports_when_tool_available(self):
        """Sanity: with the tool available, the Cargo.lock is supported."""
        generator = CycloneDXCargoGenerator()
        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_format="cyclonedx")
        self.assertTrue(generator.supports(gen_input))


class TestCycloneDXCargoGeneratorCommandLine(unittest.TestCase):
    """Tests for the cargo-cyclonedx invocation.

    These use a real temp directory rather than mocking ``Path``. cargo-cyclonedx
    has no --output-file: it writes into the project directory and names the file
    after the crate, so the generator passes --override-filename and moves the
    result to the caller's path. Mocking Path hid that contract entirely -- the
    old tests passed while the real invocation failed with
    "unexpected argument '--output-file'".
    """

    def setUp(self):
        self.generator = CycloneDXCargoGenerator()
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name) / "project"
        self.project.mkdir()
        (self.project / "Cargo.lock").write_text("")
        self.output = Path(self._tmp.name) / "out" / "sbom.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_run(self, produced_body='{"bomFormat": "CycloneDX"}'):
        """Stand in for cargo-cyclonedx, writing where the real tool would."""

        def _run(cmd, name, timeout=None, cwd=None):
            stem = cmd[cmd.index("--override-filename") + 1]
            (Path(cwd) / f"{stem}.json").write_text(produced_body)
            return MagicMock(returncode=0)

        return _run

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_command_shape(self, mock_run):
        mock_run.side_effect = self._fake_run()
        result = self.generator.generate(
            GenerationInput(
                lock_file=str(self.project / "Cargo.lock"),
                output_file=str(self.output),
                spec_version="1.5",
            )
        )

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[:2], ["cargo-cyclonedx", "cyclonedx"])
        self.assertIn("--spec-version", cmd)
        self.assertIn("1.5", cmd)
        self.assertIn("--format", cmd)
        self.assertIn("json", cmd)
        self.assertIn("--override-filename", cmd)
        # The flag the tool does not have.
        self.assertNotIn("--output-file", cmd)
        self.assertTrue(result.success)

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_runs_in_project_directory(self, mock_run):
        mock_run.side_effect = self._fake_run()
        self.generator.generate(
            GenerationInput(
                lock_file=str(self.project / "Cargo.lock"),
                output_file=str(self.output),
            )
        )
        self.assertEqual(mock_run.call_args[1]["cwd"], str(self.project.resolve()))

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_output_is_moved_to_requested_path(self, mock_run):
        """The tool writes into the project; the caller asked for somewhere else."""
        mock_run.side_effect = self._fake_run()
        result = self.generator.generate(
            GenerationInput(
                lock_file=str(self.project / "Cargo.lock"),
                output_file=str(self.output),
            )
        )

        self.assertTrue(result.success)
        self.assertTrue(self.output.exists(), "output should exist at the requested path")
        self.assertIn("CycloneDX", self.output.read_text())

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_scratch_file_is_not_left_in_the_repo(self, mock_run):
        """Generating must not litter the user's working tree."""
        mock_run.side_effect = self._fake_run()
        self.generator.generate(
            GenerationInput(
                lock_file=str(self.project / "Cargo.lock"),
                output_file=str(self.output),
            )
        )
        leftovers = [p.name for p in self.project.iterdir() if p.name != "Cargo.lock"]
        self.assertEqual(leftovers, [])

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_workspace_defers_to_another_generator(self, mock_run):
        """A cargo workspace yields one SBOM per member crate, not one document.

        cargo-cyclonedx writes into each member's own directory and nothing at
        the workspace root, so the naive "look next to Cargo.lock" approach both
        failed and left the per-crate files behind. Decline instead, so the
        orchestrator falls through to a generator that emits a single document.
        """

        def _workspace_run(cmd, name, timeout=None, cwd=None):
            stem = cmd[cmd.index("--override-filename") + 1]
            for member in ("alpha", "beta"):
                d = Path(cwd) / "crates" / member
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{stem}.json").write_text('{"bomFormat": "CycloneDX"}')
            return MagicMock(returncode=0)

        mock_run.side_effect = _workspace_run
        result = self.generator.generate(
            GenerationInput(
                lock_file=str(self.project / "Cargo.lock"),
                output_file=str(self.output),
            )
        )

        self.assertFalse(result.success)
        self.assertIn("workspace", result.error_message)
        # And nothing is left scattered through the member crates.
        self.assertEqual(list(self.project.rglob(".sbomify-cargo-cyclonedx.json")), [])

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_scratch_file_cleaned_up_when_the_tool_fails(self, mock_run):
        def _boom(cmd, name, timeout=None, cwd=None):
            stem = cmd[cmd.index("--override-filename") + 1]
            (Path(cwd) / f"{stem}.json").write_text("partial")
            raise SBOMGenerationError("cargo-cyclonedx blew up")

        mock_run.side_effect = _boom
        result = self.generator.generate(
            GenerationInput(
                lock_file=str(self.project / "Cargo.lock"),
                output_file=str(self.output),
            )
        )

        self.assertFalse(result.success)
        leftovers = [p.name for p in self.project.iterdir() if p.name != "Cargo.lock"]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
