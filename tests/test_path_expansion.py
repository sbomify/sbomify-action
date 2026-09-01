"""Tests for the path_expansion function.

These tests verify that:
1. Files are found when they exist as direct paths
2. Files are found when they exist relative to current directory
3. Files are found when they exist in the active platform's workspace
4. FileProcessingError is raised with helpful message when file not found
"""

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from sbomify_action.cli.main import path_expansion
from sbomify_action.exceptions import FileProcessingError


@contextmanager
def change_directory(path):
    """Context manager to temporarily change the current working directory."""
    original_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(original_dir)


class TestPathExpansion(unittest.TestCase):
    """Test path_expansion function."""

    def test_file_exists_as_direct_path(self):
        """Test that absolute path to existing file is returned."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "test.txt"
            test_file.write_text("test content")

            # Use the absolute path
            result = path_expansion(str(test_file))

            # Should return the absolute path
            self.assertTrue(result.endswith("test.txt"))
            self.assertTrue(Path(result).is_file())

    def test_file_exists_relative_to_cwd(self):
        """Test that file relative to current directory is found."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir).resolve() / "relative_test.txt"
            test_file.write_text("test content")

            # Change to the temp directory and use relative path
            with change_directory(tmp_dir):
                result = path_expansion("relative_test.txt")

            # Should return the absolute path (resolve to handle macOS /var -> /private/var symlink)
            self.assertEqual(Path(result).resolve(), test_file)

    def test_file_not_found_raises_error_with_helpful_message(self):
        """Test that FileProcessingError includes file name and searched paths."""
        from sbomify_action._runtime import use_platform
        from sbomify_action._runtime.platforms import GitHubPlatform

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Pin GitHub Actions with no GITHUB_WORKSPACE set, so the fallback
            # probe is its container mount point and the message names it.
            with (
                change_directory(tmp_dir),
                patch.dict(os.environ, {"GITHUB_WORKSPACE": ""}, clear=False),
                use_platform(GitHubPlatform()),
            ):
                with self.assertRaises(FileProcessingError) as context:
                    path_expansion("nonexistent_file.txt")

                error_message = str(context.exception)

                # Verify error message includes the file name
                self.assertIn("nonexistent_file.txt", error_message)

                # Verify error message mentions searched paths
                self.assertIn("Searched in:", error_message)

                # Verify it mentions the workspace path
                self.assertIn("/github/workspace", error_message)

    def test_file_not_found_error_contains_relative_path(self):
        """Test that error message contains the relative path that was searched."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with change_directory(tmp_dir):
                with self.assertRaises(FileProcessingError) as context:
                    path_expansion("package-lock.json")

                error_message = str(context.exception)

                # Should contain the cwd-relative path
                self.assertIn(f"{tmp_dir}/package-lock.json", error_message)

    def test_nested_path_file_found(self):
        """Test that nested paths (e.g., frontend/package.json) are found."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            nested_dir = Path(tmp_dir).resolve() / "frontend"
            nested_dir.mkdir()
            test_file = nested_dir / "package.json"
            test_file.write_text('{"name": "test"}')

            with change_directory(tmp_dir):
                result = path_expansion("frontend/package.json")

            # Resolve to handle macOS /var -> /private/var symlink
            self.assertEqual(Path(result).resolve(), test_file)

    def test_returns_absolute_path(self):
        """Test that the returned path is always absolute."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "test.txt"
            test_file.write_text("test content")

            with change_directory(tmp_dir):
                result = path_expansion("test.txt")

            # Result should be an absolute path
            self.assertTrue(Path(result).is_absolute())


class TestPathExpansionEdgeCases(unittest.TestCase):
    """Test edge cases for path_expansion function."""

    def test_empty_string_raises_error(self):
        """Test that empty string raises FileProcessingError."""
        with self.assertRaises(FileProcessingError) as context:
            path_expansion("")

        error_message = str(context.exception)
        self.assertIn("not found", error_message.lower())

    def test_path_with_spaces(self):
        """Test that paths with spaces are handled correctly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir).resolve() / "file with spaces.txt"
            test_file.write_text("test content")

            with change_directory(tmp_dir):
                result = path_expansion("file with spaces.txt")

            # Resolve to handle macOS /var -> /private/var symlink
            self.assertEqual(Path(result).resolve(), test_file)

    def test_symlink_is_followed(self):
        """Test that symbolic links are followed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a real file
            real_file = Path(tmp_dir) / "real_file.txt"
            real_file.write_text("test content")

            # Create a symlink
            symlink = Path(tmp_dir) / "symlink.txt"
            symlink.symlink_to(real_file)

            with change_directory(tmp_dir):
                result = path_expansion("symlink.txt")

            # Should resolve to the symlink path (Path.is_file() returns True for symlinks)
            self.assertTrue(Path(result).is_file())

    def test_path_looks_like_cli_flag_raises_helpful_error(self):
        """Test that a path starting with '-' raises a helpful error message."""
        with self.assertRaises(FileProcessingError) as context:
            path_expansion("--no-augment")

        error_message = str(context.exception)
        self.assertIn("--no-augment", error_message)
        self.assertIn("looks like a CLI flag", error_message)
        self.assertIn("Did you forget to specify a file path?", error_message)
        self.assertIn("LOCK_FILE environment variable", error_message)

    def test_path_looks_like_short_cli_flag_raises_helpful_error(self):
        """Test that a path starting with single '-' raises a helpful error message."""
        with self.assertRaises(FileProcessingError) as context:
            path_expansion("-v")

        error_message = str(context.exception)
        self.assertIn("-v", error_message)
        self.assertIn("looks like a CLI flag", error_message)


class TestLegacyWorkspaceCompatibility(unittest.TestCase):
    """The well-known path stays searchable on every platform.

    Before platforms existed, /github/workspace was probed unconditionally, so
    `docker run -v "$PWD:/github/workspace"` with no -w resolved even though the
    working directory was /. Pipelines were written against that. Searching only
    the active platform's workspace would strand them, which is why the lookups
    keep the legacy roots as a tail.
    """

    def test_a_legacy_workspace_is_still_searched_off_platform(self):
        """A file only in the legacy workspace is still found on a local run."""
        with tempfile.TemporaryDirectory() as legacy_dir, tempfile.TemporaryDirectory() as elsewhere:
            legacy = Path(legacy_dir).resolve()
            (legacy / "requirements.txt").write_text("requests==2.32.3")

            with (
                change_directory(elsewhere),
                patch("sbomify_action.cli.main.legacy_workspaces", return_value=(legacy,)),
            ):
                result = path_expansion("requirements.txt")

            self.assertEqual(Path(result).resolve(), legacy / "requirements.txt")

    def test_the_working_directory_still_wins(self):
        """A legacy root is a fallback, never an override of the real cwd."""
        with tempfile.TemporaryDirectory() as legacy_dir, tempfile.TemporaryDirectory() as elsewhere:
            legacy = Path(legacy_dir).resolve()
            (legacy / "requirements.txt").write_text("from-legacy")
            here = Path(elsewhere).resolve()
            (here / "requirements.txt").write_text("from-cwd")

            with (
                change_directory(elsewhere),
                patch("sbomify_action.cli.main.legacy_workspaces", return_value=(legacy,)),
            ):
                result = path_expansion("requirements.txt")

            self.assertEqual(Path(result).read_text(), "from-cwd")

    def test_the_legacy_root_is_named_when_nothing_is_found(self):
        """The error lists every root actually tried."""
        with tempfile.TemporaryDirectory() as legacy_dir, tempfile.TemporaryDirectory() as elsewhere:
            legacy = Path(legacy_dir).resolve()
            with (
                change_directory(elsewhere),
                patch("sbomify_action.cli.main.legacy_workspaces", return_value=(legacy,)),
            ):
                with self.assertRaises(FileProcessingError) as context:
                    path_expansion("nonexistent.txt")

            self.assertIn(str(legacy / "nonexistent.txt"), str(context.exception))


if __name__ == "__main__":
    unittest.main()
