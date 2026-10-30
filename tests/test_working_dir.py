"""Tests for the resolve_working_dir function."""

import os
import tempfile
from importlib import import_module
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner, Result

from sbomify_action._augmentation.providers.json_config import JsonConfigProvider
from sbomify_action.cli.main import cli, resolve_working_dir


def _not_in_gha():
    """Context manager that simulates running outside GitHub Actions."""
    return patch.dict(os.environ, {"GITHUB_ACTIONS": "", "GITHUB_WORKSPACE": ""}, clear=False)


def _in_gha(workspace: Path):
    """Context manager that simulates running inside GitHub Actions with a given workspace."""
    return patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(workspace)},
        clear=False,
    )


class TestResolveWorkingDir:
    """Test resolve_working_dir function."""

    def test_relative_path_resolves_to_cwd(self):
        """Relative path resolves against cwd when not in GHA."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            subdir = Path(tmp_dir).resolve() / "subproject"
            subdir.mkdir()
            with _not_in_gha(), patch.object(Path, "cwd", return_value=Path(tmp_dir).resolve()):
                result = resolve_working_dir("subproject")
                assert result == subdir

    def test_relative_path_resolves_to_github_workspace(self, tmp_path):
        """Relative path resolves against GITHUB_WORKSPACE when in GHA."""
        subdir = tmp_path / "packages" / "my-app"
        subdir.mkdir(parents=True)
        with _in_gha(tmp_path):
            result = resolve_working_dir("packages/my-app")
            assert result == subdir.resolve()

    def test_absolute_path_allowed_outside_gha(self):
        """Absolute path is allowed when not running in GitHub Actions."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with _not_in_gha():
                result = resolve_working_dir(tmp_dir)
                assert result == Path(tmp_dir).resolve()

    def test_absolute_path_under_workspace_allowed(self, tmp_path):
        """Absolute path under workspace is allowed in GHA."""
        subdir = tmp_path / "my-app"
        subdir.mkdir()
        with _in_gha(tmp_path):
            result = resolve_working_dir(str(subdir))
            assert result == subdir.resolve()

    def test_absolute_path_outside_workspace_rejected(self, tmp_path):
        """Absolute path outside workspace is rejected in GHA."""
        with tempfile.TemporaryDirectory() as outside_dir:
            with _in_gha(tmp_path):
                with pytest.raises(click.BadParameter, match="must be under"):
                    resolve_working_dir(outside_dir)

    def test_nonexistent_directory_raises_error(self):
        """Non-existent directory raises BadParameter."""
        with _not_in_gha():
            with pytest.raises(click.BadParameter, match="does not exist"):
                resolve_working_dir("/no/such/directory")

    def test_relative_path_traversal_rejected_in_gha(self, tmp_path):
        """Relative path with '..' that escapes workspace is rejected in GHA."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        with _in_gha(workspace):
            with pytest.raises(click.BadParameter, match="must be under"):
                resolve_working_dir("../../tmp")

    def test_symlink_escape_rejected_in_gha(self, tmp_path):
        """Symlink pointing outside workspace is rejected in GHA."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        link = workspace / "sneaky-link"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")
        with _in_gha(workspace):
            with pytest.raises(click.BadParameter, match="must be under"):
                resolve_working_dir(str(link))

    def test_flag_like_value_rejected(self):
        """Value starting with '-' is rejected as likely missing argument."""
        with _not_in_gha():
            with pytest.raises(click.BadParameter, match="looks like a CLI flag"):
                resolve_working_dir("--lock-file")

    def test_chdir_integration(self, tmp_path):
        """Verify os.chdir works with the resolved path."""
        subdir = tmp_path / "sub"
        subdir.mkdir()
        original = os.getcwd()
        try:
            with _not_in_gha(), patch.object(Path, "cwd", return_value=tmp_path.resolve()):
                resolved = resolve_working_dir("sub")
            os.chdir(resolved)
            assert Path.cwd() == subdir.resolve()
        finally:
            os.chdir(original)


class TestWorkingDirCliWiring:
    """Test that --working-dir CLI option triggers os.chdir."""

    def test_cli_working_dir_changes_cwd(self, tmp_path):
        """--working-dir option triggers os.chdir to the resolved directory."""
        subdir = tmp_path / "myapp"
        subdir.mkdir()
        runner = CliRunner()
        with _not_in_gha(), patch("sbomify_action.cli.main.os.chdir") as mock_chdir:
            # Invoke without input sources — cli shows help and exits, but chdir runs first
            result = runner.invoke(cli, ["--working-dir", str(subdir)])
            assert result.exit_code == 0
            mock_chdir.assert_called_once_with(subdir.resolve())

    def test_cli_working_dir_via_env_var(self, tmp_path):
        """WORKING_DIR env var triggers os.chdir to the resolved directory."""
        subdir = tmp_path / "myapp"
        subdir.mkdir()
        runner = CliRunner()
        env = {"WORKING_DIR": str(subdir), "GITHUB_ACTIONS": "", "GITHUB_WORKSPACE": ""}
        with patch.dict(os.environ, env, clear=False), patch("sbomify_action.cli.main.os.chdir") as mock_chdir:
            result = runner.invoke(cli, [])
            assert result.exit_code == 0
            mock_chdir.assert_called_once_with(subdir.resolve())


class TestPlatformIsResolvedOnce:
    """The confinement decision and the path it checks come from one platform.

    resolve_working_dir asks whether the platform confines the working
    directory, and separately for the workspace to confine it to. Resolving the
    platform twice means those two answers can come from different platforms if
    anything changes in between -- and this is a containment check, so a
    mismatch defeats the point of making it.
    """

    def test_the_workspace_comes_from_the_platform_that_demanded_the_check(self, tmp_path):
        """Only one platform resolution happens per call."""
        import sys
        from unittest.mock import patch

        # sys.modules, because `sbomify_action.cli` re-exports the click
        # command as `main` and shadows the submodule of the same name.
        _m = sys.modules["sbomify_action.cli.main"]

        workspace = tmp_path / "ws"
        (workspace / "sub").mkdir(parents=True)

        real = _m.get_platform()
        with patch.object(_m, "get_platform", wraps=lambda: real) as spy:
            with patch.dict(os.environ, {"GITHUB_ACTIONS": "", "GITHUB_WORKSPACE": ""}, clear=False):
                _m.resolve_working_dir(str(workspace / "sub"))
            assert spy.call_count == 1, f"platform resolved {spy.call_count} times, expected once"


_main = import_module("sbomify_action.cli.main")


@pytest.fixture
def monorepo(tmp_path, monkeypatch):
    """A workspace whose root holds a lock file and a config of its own."""
    root = tmp_path.resolve() / "repo"
    (root / "packages" / "api").mkdir(parents=True)
    (root / "uv.lock").write_text("version = 1\n")
    (root / "sbomify.json").write_text('{"supplier": {"name": "The whole repository"}}')
    monkeypatch.chdir(root)
    return root


def _run_action(root: Path, **env: str | None) -> tuple[Result, dict]:
    """Run the CLI the way the GitHub Action does, capturing what the pipeline is handed."""
    seen: dict = {}

    def pipeline(config):
        seen["lock_file"] = config.lock_file
        seen["source_dir"] = config.source_dir
        seen["sbomify_json"] = JsonConfigProvider()._find_config_file()

    with (
        patch.object(_main, "setup_dependencies"),
        patch.object(_main, "run_pipeline", side_effect=pipeline),
    ):
        result = CliRunner().invoke(
            cli,
            [],
            env={
                "GITHUB_ACTIONS": "true",
                "GITHUB_WORKSPACE": str(root),
                "WORKING_DIR": None,
                "UPLOAD": "false",
                **env,
            },
        )
    return result, seen


class TestInputsResolveInsideWorkingDir:
    """With WORKING_DIR set, a relative input is looked up only inside it.

    Lookups also try the checkout roots, because a runtime can mount the
    repository away from where the command runs. Under WORKING_DIR those roots
    are the repository around the chosen package, and in a uv, npm or Cargo
    workspace the lock file there lists every package's dependencies: an SBOM
    built from it describes the whole repository and passes every check.
    """

    def test_a_missing_lock_file_is_not_read_from_the_repository_root(self, monorepo):
        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert "lock_file" not in seen, f"built from {seen.get('lock_file')}"
        assert result.exit_code != 0

    def test_a_package_without_sbomify_json_falls_back_to_the_roots_and_says_so(self, monorepo, caplog):
        """Unlike a lock file, sbomify.json mostly carries supplier, authors and
        contacts, which are usually the same org-wide. One root file shared by
        every package is a sensible monorepo setup, so it stays the fallback --
        named in the log, so the run shows where that metadata came from."""
        (monorepo / "packages" / "api" / "uv.lock").write_text("version = 1\n")

        with caplog.at_level("INFO"):
            result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert result.exit_code == 0, result.output
        assert seen["sbomify_json"] == monorepo / "sbomify.json"
        assert f"Using '{monorepo / 'sbomify.json'}' from the repository root" in caplog.text

    def test_a_package_sbomify_json_beats_the_roots(self, monorepo, caplog):
        package = monorepo / "packages" / "api"
        (package / "uv.lock").write_text("version = 1\n")
        (package / "sbomify.json").write_text('{"supplier": {"name": "The API team"}}')

        with caplog.at_level("INFO"):
            result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert result.exit_code == 0, result.output
        assert seen["sbomify_json"] == package / "sbomify.json"
        assert "from the repository root" not in caplog.text

    def test_a_symlinked_root_sbomify_json_is_read(self, monorepo):
        """Linking the root file in is the package's own file, not a fallback."""
        package = monorepo / "packages" / "api"
        (package / "uv.lock").write_text("version = 1\n")
        (package / "sbomify.json").symlink_to("../../sbomify.json")

        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert result.exit_code == 0, result.output
        assert seen["sbomify_json"].resolve() == monorepo / "sbomify.json"

    def test_the_working_dirs_own_files_are_used(self, monorepo):
        package = monorepo / "packages" / "api"
        (package / "uv.lock").write_text("version = 1\n")
        (package / "sbomify.json").write_text("{}")

        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert result.exit_code == 0, result.output
        assert Path(seen["lock_file"]) == package / "uv.lock"
        assert seen["sbomify_json"] == package / "sbomify.json"

    def test_a_root_relative_path_that_lands_inside_still_resolves(self, monorepo):
        """A LOCK_FILE written against the repository root, from before
        working-dir was set, names the package's own file and keeps working."""
        package = monorepo / "packages" / "api"
        (package / "uv.lock").write_text("version = 1\n")

        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="packages/api/uv.lock")

        assert result.exit_code == 0, result.output
        assert Path(seen["lock_file"]) == package / "uv.lock"

    def test_without_working_dir_the_checkout_root_is_still_searched(self, monorepo, tmp_path, monkeypatch):
        """The case the root lookup exists for: the command runs somewhere other
        than where the repository is mounted."""
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        result, seen = _run_action(monorepo, LOCK_FILE="uv.lock")

        assert result.exit_code == 0, result.output
        assert Path(seen["lock_file"]) == monorepo / "uv.lock"
        assert seen["sbomify_json"] == monorepo / "sbomify.json"

    def test_the_failure_names_the_root_file_and_how_to_use_it(self, monorepo):
        result, _ = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        message = str(result.exception)
        assert str(monorepo / "packages" / "api") in message, "does not name the directory searched"
        assert f"'{monorepo / 'uv.lock'}'" in message, "does not name the root file it skipped"
        assert "'../../uv.lock'" in message, "does not say how to point at it relative to WORKING_DIR"

    def test_a_package_without_its_own_lock_file_is_not_substituted(self, monorepo):
        """The workspace layout: the package has a manifest, the lock file is at
        the root. The project did not change package manager, so swapping in
        the manifest would hide that the named file is right there."""
        (monorepo / "packages" / "api" / "pyproject.toml").write_text("[project]\nname = 'api'\n")

        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert "lock_file" not in seen, f"built from {seen.get('lock_file')}"
        assert "'../../uv.lock'" in str(result.exception)

    @pytest.mark.parametrize("spelling", ["../../uv.lock", "absolute"])
    def test_the_root_file_can_be_named_on_purpose(self, monorepo, spelling):
        lock_file = str(monorepo / "uv.lock") if spelling == "absolute" else spelling

        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE=lock_file)

        assert result.exit_code == 0, result.output
        assert Path(seen["lock_file"]).resolve() == monorepo / "uv.lock"

    def test_a_stale_lock_file_is_not_substituted_from_the_mount_point(self, monorepo):
        """Inside the action's container the mount point the substitution scans,
        /github/workspace, is the repository root. A stale LOCK_FILE in a
        package must not be answered by the root's lock file."""
        with patch.object(_main, "legacy_workspaces", return_value=(monorepo,)):
            result, seen = _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="poetry.lock")

        assert "lock_file" not in seen, f"built from {seen.get('lock_file')}"
        assert result.exit_code != 0

    def test_a_missing_source_dir_is_not_read_from_the_repository_root(self, monorepo):
        (monorepo / "dist").mkdir()

        result, seen = _run_action(monorepo, WORKING_DIR="packages/api", SOURCE_DIR="dist")

        assert "source_dir" not in seen, f"scanned {seen.get('source_dir')}"
        assert "'../../dist'" in str(result.exception)

    def test_the_confinement_ends_with_the_run(self, monorepo):
        """It is process state, so it must not outlive the invocation that set it."""
        from sbomify_action._runtime import inside_working_dir

        _run_action(monorepo, WORKING_DIR="packages/api", LOCK_FILE="uv.lock")

        assert inside_working_dir(monorepo / "uv.lock")
