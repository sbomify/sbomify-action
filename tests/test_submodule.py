"""Tests for submodule pin resolution and the pipeline's submodule mode."""

from __future__ import annotations

import os
import subprocess
from importlib import import_module
from pathlib import Path

import pytest

from sbomify_action.cli.main import (
    Config,
    _find_existing_submodule_sbom,
    _prepare_submodule_mode,
)
from sbomify_action.submodule import SubmodulePin, _pick_version_tag, resolve_submodule_pin

# `sbomify_action.cli.main` the *attribute* is shadowed by a function
# export, so monkeypatch string paths can't reach the module — import it
# explicitly (same workaround as tests/test_config.py).
cli_main_module = import_module("sbomify_action.cli.main")
submodule_module = import_module("sbomify_action.submodule")

# ----------------------------------------------------------------------
# git fixtures


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@t",
        # Never pick up the developer's/CI's global config.
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }


def _git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=_git_env(),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _make_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", "-b", "main"], cwd=path)
    (path / "README.md").write_text("# repo")
    _git(["add", "."], cwd=path)
    _git(["commit", "-q", "-m", "initial"], cwd=path)


@pytest.fixture
def parent_with_submodule(tmp_path: Path) -> tuple[Path, Path]:
    """A parent repo with ``extern/lib`` as a real git submodule.

    The submodule's pinned commit carries tag ``v1.2.3``.
    """
    sub = tmp_path / "sub-remote"
    _make_repo(sub)
    _git(["tag", "v1.2.3"], cwd=sub)

    parent = tmp_path / "parent"
    _make_repo(parent)
    # protocol.file.allow: git >= 2.38 blocks file-protocol submodules by default.
    _git(
        ["-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "extern/lib"],
        cwd=parent,
    )
    _git(["commit", "-q", "-m", "add submodule"], cwd=parent)
    return parent, sub


# ----------------------------------------------------------------------
# resolve_submodule_pin


def test_resolves_version_tag_at_pin(parent_with_submodule: tuple[Path, Path]) -> None:
    parent, sub = parent_with_submodule
    pin = resolve_submodule_pin(parent, "extern/lib")
    assert pin is not None
    assert pin.path == "extern/lib"
    assert pin.version == "v1.2.3"
    assert pin.version_source == "tag"
    assert pin.sha == _git(["rev-parse", "HEAD"], cwd=sub)


def test_resolves_short_sha_for_untagged_pin(parent_with_submodule: tuple[Path, Path]) -> None:
    parent, sub = parent_with_submodule
    # Advance the submodule remote past the tag and re-pin the parent.
    (sub / "new.txt").write_text("x")
    _git(["add", "."], cwd=sub)
    _git(["commit", "-q", "-m", "untagged"], cwd=sub)
    new_sha = _git(["rev-parse", "HEAD"], cwd=sub)
    checkout = parent / "extern" / "lib"
    _git(["fetch", "-q", "origin"], cwd=checkout)
    _git(["checkout", "-q", new_sha], cwd=checkout)
    _git(["add", "extern/lib"], cwd=parent)
    _git(["commit", "-q", "-m", "bump submodule"], cwd=parent)

    pin = resolve_submodule_pin(parent, "extern/lib")
    assert pin is not None
    assert pin.sha == new_sha
    assert pin.version == new_sha[:7]
    assert pin.version_source == "sha"


def test_pin_read_from_tree_without_initialized_submodule(parent_with_submodule: tuple[Path, Path]) -> None:
    """The gitlink lives in the parent tree — a fresh clone without
    ``submodule update`` must still resolve (the attach path needs no
    submodule checkout at all)."""
    parent, sub = parent_with_submodule
    clone = parent.parent / "fresh-clone"
    _git(["clone", "-q", str(parent), str(clone)], cwd=parent.parent)

    pin = resolve_submodule_pin(clone, "extern/lib")
    assert pin is not None
    assert pin.sha == _git(["rev-parse", "HEAD"], cwd=sub)
    # .gitmodules still points at the sub remote, so the tag resolves too.
    assert pin.version == "v1.2.3"


def test_resolves_vendored_clone_without_gitmodules(tmp_path: Path) -> None:
    """A plain checked-in clone (own .git dir, no gitlink) resolves via
    its embedded repo, including local tags."""
    sub = tmp_path / "sub-remote"
    _make_repo(sub)
    _git(["tag", "2026.7.1"], cwd=sub)

    parent = tmp_path / "parent"
    _make_repo(parent)
    _git(["clone", "-q", str(sub), str(parent / "third_party" / "libfoo")], cwd=parent)

    pin = resolve_submodule_pin(parent, "third_party/libfoo")
    assert pin is not None
    assert pin.version == "2026.7.1"
    assert pin.version_source == "tag"


def test_returns_none_for_plain_directory(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    _make_repo(parent)
    (parent / "just-a-dir").mkdir()
    assert resolve_submodule_pin(parent, "just-a-dir") is None
    assert resolve_submodule_pin(parent, "missing/path") is None


def test_resolves_pin_when_run_from_a_subdirectory(parent_with_submodule: tuple[Path, Path]) -> None:
    """``SUBMODULE_PATH`` is repo-root-relative, but the caller passes
    the process cwd. From a subdirectory, ``ls-tree`` would resolve the
    pathspec against that subdirectory and ``.gitmodules`` would be
    missing entirely — resolution must normalise to the worktree root
    first."""
    parent, sub = parent_with_submodule
    workdir = parent / "services" / "api"
    workdir.mkdir(parents=True)

    pin = resolve_submodule_pin(workdir, "extern/lib")
    assert pin is not None
    assert pin.path == "extern/lib"
    assert pin.sha == _git(["rev-parse", "HEAD"], cwd=sub)
    # .gitmodules was found, so the tag resolved rather than degrading to a SHA.
    assert pin.version == "v1.2.3"
    assert pin.version_source == "tag"


def test_submodule_url_is_redacted_before_logging(
    parent_with_submodule: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``.gitmodules`` URL may embed credentials, so the no-tags debug
    line must not carry them."""
    parent, _sub = parent_with_submodule
    gitmodules = parent / ".gitmodules"
    original = gitmodules.read_text()
    url_line = [line for line in original.splitlines() if "url =" in line][0]
    gitmodules.write_text(original.replace(url_line, "\turl = https://x-access-token:s3cr3t@example.invalid/o/l.git"))

    # No network: the point is what reaches the log, not the lookup.
    monkeypatch.setattr(submodule_module, "_tags_at_sha_remote", lambda *_args, **_kwargs: [])
    messages: list[str] = []
    monkeypatch.setattr(submodule_module.logger, "debug", lambda msg: messages.append(str(msg)))

    resolve_submodule_pin(parent, "extern/lib")

    logged = "\n".join(messages)
    assert "s3cr3t" not in logged
    assert "***@example.invalid" in logged


def test_redact_url_leaves_ordinary_urls_intact() -> None:
    redact = submodule_module._redact_url
    assert redact("https://github.com/org/repo.git") == "https://github.com/org/repo.git"
    # scp-style: a username, not a secret.
    assert redact("git@github.com:org/repo.git") == "git@github.com:org/repo.git"
    assert redact("../sibling-repo") == "../sibling-repo"
    # An @ in the path is not userinfo.
    assert redact("https://host/org/repo@v1.git") == "https://host/org/repo@v1.git"
    assert redact("ssh://user:pw@host:22/o/l.git") == "ssh://***@host:22/o/l.git"


def test_gitmodules_url_cannot_inject_git_options(tmp_path: Path) -> None:
    """A leading-dash ``.gitmodules`` URL must never be read as an option.

    ``.gitmodules`` belongs to the scanned repo, so it is untrusted (fork
    PRs, third-party code). Without an end-of-options marker,
    ``--upload-pack=<cmd>`` makes ``git ls-remote`` *execute* ``<cmd>``
    against the default remote — and git's non-zero exit hides it, since
    ``_run_git`` returns None on any failure.
    """
    sub = tmp_path / "sub-remote"
    _make_repo(sub)

    parent = tmp_path / "parent"
    _make_repo(parent)
    _git(
        ["-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "extern/lib"],
        cwd=parent,
    )
    _git(["commit", "-q", "-m", "add submodule"], cwd=parent)
    # actions/checkout leaves an origin behind; ls-remote falls back to it
    # when its repository argument is swallowed as an option.
    _git(["remote", "add", "origin", str(sub)], cwd=parent)

    canary = tmp_path / "canary"
    gitmodules = parent / ".gitmodules"
    gitmodules.write_text(gitmodules.read_text().replace(str(sub), f"--upload-pack=touch {canary}"))

    # Resolution still succeeds (untagged pin → short SHA); the point is
    # what did *not* happen.
    pin = resolve_submodule_pin(parent, "extern/lib")
    assert pin is not None
    assert not canary.exists(), "git executed the injected --upload-pack command"


def test_pick_version_tag_prefers_v_prefixed() -> None:
    assert _pick_version_tag(["1.2.3", "v1.2.3"]) == "v1.2.3"
    assert _pick_version_tag(["2026.7.1"]) == "2026.7.1"
    # Non-version tags (release names, "latest") never win.
    assert _pick_version_tag(["latest", "rc-final"]) is None
    assert _pick_version_tag([]) is None


# ----------------------------------------------------------------------
# pipeline submodule mode


def _submodule_config(**overrides: object) -> Config:
    defaults: dict[str, object] = {
        "token": "t",
        "component_id": "c1",
        "lock_file": "extern/lib/Cargo.lock",
        "submodule_path": "extern/lib",
        "sbom_format": "cyclonedx",
    }
    defaults.update(overrides)
    return Config(**defaults)  # type: ignore[arg-type]


def test_prepare_submodule_mode_attaches_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin resolves + SBOM exists → returns its id and overrides the
    component version with the pin-derived one."""
    monkeypatch.setattr(
        "sbomify_action.submodule.resolve_submodule_pin",
        lambda _root, path: SubmodulePin(path=path, sha="a" * 40, version="v1.2.3", version_source="tag"),
    )
    monkeypatch.setattr(cli_main_module, "_find_existing_submodule_sbom", lambda _config, _fmt: "sbom-42")
    config = _submodule_config(component_version="parent-version")
    assert _prepare_submodule_mode(config) == "sbom-42"
    assert config.component_version == "v1.2.3"


def test_prepare_submodule_mode_falls_back_to_backfill(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sbomify_action.submodule.resolve_submodule_pin",
        lambda _root, path: SubmodulePin(path=path, sha="b" * 40, version="bbbbbbb", version_source="sha"),
    )
    monkeypatch.setattr(cli_main_module, "_find_existing_submodule_sbom", lambda _config, _fmt: None)
    config = _submodule_config()
    assert _prepare_submodule_mode(config) is None
    assert config.component_version == "bbbbbbb"


def test_prepare_submodule_mode_exits_on_unresolvable_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sbomify_action.submodule.resolve_submodule_pin", lambda _root, _path: None)
    with pytest.raises(SystemExit):
        _prepare_submodule_mode(_submodule_config())


def test_find_existing_submodule_sbom_soft_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """API errors during the lookup mean backfill, not a crashed run."""
    from sbomify_action.exceptions import APIError

    class _BoomClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def find_component_sbom(self, *args: object) -> str:
            raise APIError("down")

    monkeypatch.setattr("sbomify_action.sbomify_api.SbomifyApiClient", _BoomClient)
    config = _submodule_config(component_version="v1.2.3")
    assert _find_existing_submodule_sbom(config, "cyclonedx") is None


def test_find_existing_submodule_sbom_requires_credentials() -> None:
    config = _submodule_config(token="", component_version="v1.2.3")
    assert _find_existing_submodule_sbom(config, "cyclonedx") is None
