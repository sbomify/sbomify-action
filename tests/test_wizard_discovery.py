"""Tests for wizard discovery, repo_facts, and existing-workflow detection."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sbomify_action.cli.wizard.discovery import discover, slugify
from sbomify_action.cli.wizard.existing import wizard_workflow_exists, workflow_path
from sbomify_action.cli.wizard.io import WIZARD_HEADER_SENTINEL
from sbomify_action.cli.wizard.repo_facts import _parse_owner_repo_slug, gather_repo_facts


# ----------------------------------------------------------------------
# discovery


def test_discover_finds_single_python_lockfile(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("# lockfile")
    found = discover(tmp_path)
    assert len(found) == 1
    assert found[0].rel_path == Path("uv.lock")
    assert found[0].ecosystem == "python"


def test_discover_picks_higher_priority_lockfile_per_directory(tmp_path: Path) -> None:
    # Both present — wizard should pick uv.lock (priority 10) over pyproject.toml (14).
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text("")
    found = discover(tmp_path)
    assert [lf.rel_path.name for lf in found] == ["uv.lock"]


def test_discover_recurses_into_subdirs(tmp_path: Path) -> None:
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "uv.lock").write_text("")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text("{}")

    found = discover(tmp_path)
    rels = {str(lf.rel_path) for lf in found}
    assert rels == {os.path.join("backend", "uv.lock"), os.path.join("frontend", "package.json")}


def test_discover_skips_node_modules_and_dotgit(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "package.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")

    found = discover(tmp_path)
    assert [str(lf.rel_path) for lf in found] == ["package.json"]


def test_discover_suggested_name_includes_repo_and_ecosystem(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("")
    found = discover(tmp_path, repo_name="My Widget!")
    assert found[0].suggested_name == "my-widget-python"


def test_slugify_strips_and_trims() -> None:
    assert slugify("Hello, World!") == "hello-world"
    assert slugify("___") == ""
    assert slugify("A" * 100).startswith("a" * 60)
    assert len(slugify("A" * 100)) == 60


# ----------------------------------------------------------------------
# repo_facts


def _init_git_repo(path: Path, *, remote: str = "git@github.com:acme/widget.git") -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True, env=env)
    subprocess.run(["git", "remote", "add", "origin", remote], cwd=path, check=True, env=env)
    (path / "README.md").write_text("# test")
    subprocess.run(["git", "add", "."], cwd=path, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=path, check=True, env=env)


def test_gather_repo_facts_parses_owner_repo(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    facts = gather_repo_facts(tmp_path)
    assert facts.is_git is True
    assert facts.owner_repo_slug == "acme/widget"
    assert facts.suggested_repo_name == "widget"
    assert facts.current_branch == "main"
    assert facts.has_release_tags is False


def test_gather_repo_facts_with_release_tags(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    subprocess.run(["git", "tag", "v1.0.0"], cwd=tmp_path, check=True, env=env)
    facts = gather_repo_facts(tmp_path)
    assert facts.has_release_tags is True


def test_gather_repo_facts_non_git_dir(tmp_path: Path) -> None:
    facts = gather_repo_facts(tmp_path)
    assert facts.is_git is False
    assert facts.owner_repo_slug is None
    # Falls back to the directory's basename.
    assert facts.suggested_repo_name == tmp_path.name


@pytest.mark.parametrize(
    "url, expected",
    [
        ("git@github.com:acme/widget.git", "acme/widget"),
        ("https://github.com/acme/widget.git", "acme/widget"),
        ("https://x:y@github.com/acme/widget", "acme/widget"),
        ("ssh://git@gitlab.example.com/acme/widget.git", "acme/widget"),
        ("not-a-url", None),
    ],
)
def test_parse_owner_repo_slug(url: str, expected: str | None) -> None:
    assert _parse_owner_repo_slug(url) == expected


# ----------------------------------------------------------------------
# existing


def test_wizard_workflow_exists_true_only_with_sentinel(tmp_path: Path) -> None:
    path = workflow_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(f"# header\n{WIZARD_HEADER_SENTINEL}\nname: sboms\n", encoding="utf-8")
    assert wizard_workflow_exists(tmp_path) is True


def test_wizard_workflow_exists_false_for_handwritten(tmp_path: Path) -> None:
    path = workflow_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("name: hand-authored\n", encoding="utf-8")
    assert wizard_workflow_exists(tmp_path) is False


def test_wizard_workflow_exists_false_when_missing(tmp_path: Path) -> None:
    assert wizard_workflow_exists(tmp_path) is False
