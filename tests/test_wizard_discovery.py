"""Tests for sbomify_action.cli.wizard.discovery."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sbomify_action.cli.wizard import discovery


def _touch(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_slugify_strips_non_alphanumerics():
    assert discovery.slugify("My Component!") == "my-component"
    assert discovery.slugify("frontend/web app") == "frontend-web-app"
    assert discovery.slugify("___") == ""


def test_discover_returns_empty_for_empty_dir(tmp_path):
    assert discovery.discover(tmp_path) == []


def test_discover_walks_when_not_a_git_repo(tmp_path):
    _touch(tmp_path / "package.json")
    _touch(tmp_path / "package-lock.json")
    _touch(tmp_path / "subdir" / "requirements.txt")

    found = discovery.discover(tmp_path)

    rel_paths = sorted(str(item.rel_path) for item in found)
    assert "package-lock.json" in rel_paths
    assert "subdir/requirements.txt" in rel_paths
    # package-lock.json wins over package.json in the same directory.
    assert "package.json" not in rel_paths


def test_discover_dedup_python_priority(tmp_path):
    _touch(tmp_path / "pyproject.toml")
    _touch(tmp_path / "uv.lock")
    found = discovery.discover(tmp_path)
    assert [str(item.rel_path) for item in found] == ["uv.lock"]


def test_discover_skips_node_modules_in_walk(tmp_path):
    _touch(tmp_path / "package.json")
    _touch(tmp_path / "node_modules" / "thing" / "package.json")
    found = discovery.discover(tmp_path)
    assert all("node_modules" not in str(item.rel_path) for item in found)


def test_suggested_name_for_top_level_uses_repo_and_ecosystem(tmp_path):
    repo = tmp_path / "my-repo"
    repo.mkdir()
    _touch(repo / "uv.lock")
    found = discovery.discover(repo)
    assert found
    assert found[0].suggested_name == "my-repo-python"


def test_suggested_name_for_subdir_uses_directory_slug(tmp_path):
    _touch(tmp_path / "frontend" / "package-lock.json")
    found = discovery.discover(tmp_path)
    assert found
    assert found[0].suggested_name == "frontend"


def _git_available() -> bool:
    try:
        subprocess.run(
            ["git", "--version"],
            capture_output=True,
            timeout=5,
            check=True,
        )
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _git_available(), reason="git not installed")
def test_discover_respects_gitignore(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=tmp_path, check=True)
    _touch(tmp_path / ".gitignore", "ignored/\n")
    _touch(tmp_path / "uv.lock")
    _touch(tmp_path / "ignored" / "uv.lock")

    found = discovery.discover(tmp_path)
    rel_paths = {str(item.rel_path) for item in found}
    assert "uv.lock" in rel_paths
    assert "ignored/uv.lock" not in rel_paths
