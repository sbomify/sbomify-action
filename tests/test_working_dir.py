"""Tests for the resolve_working_dir function."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

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
