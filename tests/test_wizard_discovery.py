"""Tests for wizard discovery, repo_facts, and existing-workflow detection."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sbomify_action.cli.wizard.discovery import discover, slugify
from sbomify_action.cli.wizard.existing import wizard_workflow_exists, workflow_path
from sbomify_action.cli.wizard.io import WIZARD_HEADER_SENTINEL
from sbomify_action.cli.wizard.repo_facts import (
    _is_github_remote,
    _parse_owner_repo_slug,
    detect_visibility,
    gather_repo_facts,
    github_token,
    resolve_repo_ids,
)

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


@pytest.fixture(autouse=True)
def _stub_visibility(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent gather_repo_facts from hitting the real GitHub API.

    Tests using fake remotes (acme/widget) would otherwise trigger a
    live network call into api.github.com on every run — slow and
    flaky. The autouse here neutralises it for the entire module.
    """
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.detect_visibility",
        lambda _remote, _slug: "unknown",
    )


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
        # Non-github remotes return None: the slug is only used to render
        # OIDC binding instructions on the Done screen, and a wrong slug
        # (eg from a nested GitLab group URL like
        # ``https://git.example.com/team/group/subgroup/repo.git`` which
        # would otherwise resolve to ``subgroup/repo``) is worse than
        # no slug.
        ("ssh://git@gitlab.example.com/acme/widget.git", None),
        ("https://git.example.com/team/group/subgroup/repo.git", None),
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


# ----------------------------------------------------------------------
# detect_visibility


@pytest.mark.parametrize(
    "url, expected",
    [
        ("git@github.com:acme/widget.git", True),
        ("https://github.com/acme/widget.git", True),
        ("https://x:y@github.com/acme/widget", True),
        ("git@gitlab.com:acme/widget.git", False),
        ("https://bitbucket.org/acme/widget.git", False),
        ("git@github-enterprise.example.com:acme/widget.git", False),
        ("not-a-url", False),
    ],
)
def test_is_github_remote(url: str, expected: bool) -> None:
    assert _is_github_remote(url) is expected


class _FakeResponse:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def test_detect_visibility_public(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.requests.get",
        lambda *args, **kwargs: _FakeResponse(200, {"private": False}),
    )
    assert detect_visibility("git@github.com:acme/widget.git", "acme/widget") == "public"


def test_detect_visibility_404_means_private(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.requests.get",
        lambda *args, **kwargs: _FakeResponse(404, {}),
    )
    assert detect_visibility("git@github.com:acme/widget.git", "acme/widget") == "private"


def test_detect_visibility_non_github_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, bool] = {"hit": False}

    def fail(*_args: object, **_kwargs: object) -> object:
        called["hit"] = True
        raise AssertionError("requests.get must not be called for non-github remotes")

    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.requests.get", fail)
    assert detect_visibility("git@gitlab.com:acme/widget.git", "acme/widget") == "unknown"
    assert called["hit"] is False


def test_detect_visibility_network_failure_returns_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    def boom(*_args: object, **_kwargs: object) -> object:
        raise requests.ConnectionError("offline")

    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.requests.get", boom)
    assert detect_visibility("git@github.com:acme/widget.git", "acme/widget") == "unknown"


def test_detect_visibility_rate_limit_returns_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.requests.get",
        lambda *args, **kwargs: _FakeResponse(403, {"message": "rate limit"}),
    )
    assert detect_visibility("git@github.com:acme/widget.git", "acme/widget") == "unknown"


# ----------------------------------------------------------------------
# github_token (used only to resolve private-repo IDs)


def _no_github_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


def test_github_token_prefers_gh_token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "from-gh-token")
    monkeypatch.setenv("GITHUB_TOKEN", "from-github-token")
    assert github_token() == "from-gh-token"


def test_github_token_falls_back_to_github_token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "from-github-token")
    assert github_token() == "from-github-token"


def test_github_token_uses_gh_cli_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_github_env(monkeypatch)
    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.shutil.which", lambda _name: "/usr/bin/gh")

    class _Result:
        returncode = 0
        stdout = "cli-token\n"

    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.subprocess.run", lambda *a, **k: _Result())
    assert github_token() == "cli-token"


def test_github_token_none_when_no_env_and_no_gh(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_github_env(monkeypatch)
    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.shutil.which", lambda _name: None)
    assert github_token() is None


def test_github_token_none_when_gh_cli_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_github_env(monkeypatch)
    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.shutil.which", lambda _name: "/usr/bin/gh")

    class _Result:
        returncode = 1
        stdout = ""

    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.subprocess.run", lambda *a, **k: _Result())
    assert github_token() is None


# ----------------------------------------------------------------------
# resolve_repo_ids (authenticated — works for private repos)


def test_resolve_repo_ids_returns_ids_on_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.requests.get",
        lambda *a, **k: _FakeResponse(200, {"id": 1296269, "owner": {"id": 583231}}),
    )
    assert resolve_repo_ids("aurangzaib048/rwaj-assessment", "tok") == (1296269, 583231)


def test_resolve_repo_ids_none_on_non_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.requests.get",
        lambda *a, **k: _FakeResponse(404, {}),
    )
    assert resolve_repo_ids("acme/widget", "tok") is None


def test_resolve_repo_ids_none_on_malformed_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.repo_facts.requests.get",
        lambda *a, **k: _FakeResponse(200, {"id": 1296269}),  # missing owner.id
    )
    assert resolve_repo_ids("acme/widget", "tok") is None


def test_resolve_repo_ids_none_on_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    def boom(*_a: object, **_k: object) -> object:
        raise requests.ConnectionError("offline")

    monkeypatch.setattr("sbomify_action.cli.wizard.repo_facts.requests.get", boom)
    assert resolve_repo_ids("acme/widget", "tok") is None
