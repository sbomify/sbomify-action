"""Tests for license database cache directory configuration."""

import os
from pathlib import Path
from unittest.mock import patch

from sbomify_action._enrichment.sources.license_db import get_cache_dir


class TestLicenseDBCacheDir:
    """Test cache directory configuration."""

    def test_default_cache_dir_when_no_env_vars(self, tmp_path: Path):
        """Test default cache directory when no environment variables are set."""
        with patch.dict(os.environ, {}, clear=True):
            # Also need to patch home directory to avoid side effects
            with patch.object(Path, "home", return_value=tmp_path):
                # DEFAULT_CACHE_DIR is computed at import time, so we need to test
                # the function behavior
                cache_dir = get_cache_dir()
                # It should be under the home directory's .cache
                assert "license-db" in str(cache_dir)

    def test_sbomify_cache_dir_takes_precedence(self, tmp_path: Path):
        """Test that SBOMIFY_CACHE_DIR environment variable is used when set."""
        custom_cache = tmp_path / "custom-cache"
        with patch.dict(os.environ, {"SBOMIFY_CACHE_DIR": str(custom_cache)}, clear=False):
            cache_dir = get_cache_dir()
            assert cache_dir == custom_cache / "license-db"
            # Verify directory was created
            assert cache_dir.exists()

    def test_sbomify_cache_dir_creates_subdirectory(self, tmp_path: Path):
        """Test that license-db subdirectory is created under SBOMIFY_CACHE_DIR."""
        custom_cache = tmp_path / "my-cache"
        with patch.dict(os.environ, {"SBOMIFY_CACHE_DIR": str(custom_cache)}, clear=False):
            cache_dir = get_cache_dir()
            assert cache_dir.name == "license-db"
            assert cache_dir.parent == custom_cache
            assert cache_dir.exists()

    def test_xdg_cache_home_respected_when_sbomify_cache_dir_not_set(self, tmp_path: Path):
        """Test that XDG_CACHE_HOME is respected as fallback."""
        import importlib

        import sbomify_action._enrichment.sources.license_db as license_db_module

        xdg_cache = tmp_path / "xdg-cache"
        with patch.dict(os.environ, {"XDG_CACHE_HOME": str(xdg_cache)}, clear=False):
            # Clear SBOMIFY_CACHE_DIR to test fallback
            env = os.environ.copy()
            env.pop("SBOMIFY_CACHE_DIR", None)
            with patch.dict(os.environ, env, clear=True):
                # Reload the module to pick up new XDG_CACHE_HOME
                importlib.reload(license_db_module)
                try:
                    cache_dir = license_db_module.get_cache_dir()
                    assert "sbomify" in str(cache_dir)
                    assert "license-db" in str(cache_dir)
                finally:
                    # Restore module to original state
                    importlib.reload(license_db_module)

    def test_cache_directory_is_created_if_not_exists(self, tmp_path: Path):
        """Test that cache directory is created if it doesn't exist."""
        custom_cache = tmp_path / "new-cache-dir"
        assert not custom_cache.exists()
        with patch.dict(os.environ, {"SBOMIFY_CACHE_DIR": str(custom_cache)}, clear=False):
            cache_dir = get_cache_dir()
            assert cache_dir.exists()
            assert cache_dir.is_dir()

    def test_sbomify_cache_dir_works_with_nested_path(self, tmp_path: Path):
        """Test SBOMIFY_CACHE_DIR works with deeply nested paths."""
        nested_cache = tmp_path / "a" / "b" / "c" / "cache"
        with patch.dict(os.environ, {"SBOMIFY_CACHE_DIR": str(nested_cache)}, clear=False):
            cache_dir = get_cache_dir()
            assert cache_dir.exists()
            assert cache_dir == nested_cache / "license-db"

    def test_empty_sbomify_cache_dir_falls_back_to_default(self, tmp_path: Path):
        """Test that empty string SBOMIFY_CACHE_DIR falls back to default."""
        with patch.dict(os.environ, {"SBOMIFY_CACHE_DIR": ""}, clear=False):
            cache_dir = get_cache_dir()
            # Empty string is falsy, so should use DEFAULT_CACHE_DIR
            assert "license-db" in str(cache_dir)
            # Should NOT be empty string path
            assert str(cache_dir) != "/license-db"

    def test_unwritable_primary_falls_back_to_tempdir(self, tmp_path: Path):
        """An unwritable primary location costs the cache, not the run.

        This is the non-root container case: a uid with no passwd entry gets
        ``HOME=/``, so the default lands on ``/.cache`` and the mkdir raises.
        Enrichment must carry on with a cache somewhere else.

        ``mkdir`` is stubbed rather than relying on filesystem permissions so
        the test means the same thing when the suite happens to run as root,
        for whom mode 0o500 is no obstacle.
        """
        blocked = tmp_path / "unwritable"
        real_mkdir = Path.mkdir

        def fake_mkdir(self: Path, *args: object, **kwargs: object) -> None:
            if str(self).startswith(str(blocked)):
                raise PermissionError(13, "Permission denied", str(self))
            real_mkdir(self, *args, **kwargs)  # type: ignore[arg-type]

        with patch.dict(os.environ, {"SBOMIFY_CACHE_DIR": str(blocked)}, clear=False):
            with patch.object(Path, "mkdir", fake_mkdir):
                cache_dir = get_cache_dir()

        assert not str(cache_dir).startswith(str(blocked))
        assert cache_dir.name == "license-db"
        assert cache_dir.exists()
