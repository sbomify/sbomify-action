"""Tests for the PR-creation phase of the wizard."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

from sbomify_action.cli.wizard import wizard_runner
from sbomify_action.cli.wizard.state import (
    Plan,
    RepoFacts,
    WizardState,
    WorkspaceSnapshot,
)
from sbomify_action.cli.wizard.wizard_runner import WizardOptions, _phase_open_pr


def _facts(repo_root: Path, *, remote_url: str | None = "git@github.com:acme/repo.git") -> RepoFacts:
    return RepoFacts(
        repo_root=repo_root,
        is_git=True,
        remote_url=remote_url,
        suggested_repo_name="repo",
        default_branch="main",
        current_branch="main",
        has_release_tags=False,
    )


def _state(
    tmp_path: Path, *, written: list[Path], remote_url: str | None = "git@github.com:acme/repo.git"
) -> WizardState:
    state = WizardState(
        facts=_facts(tmp_path, remote_url=remote_url),
        api=MagicMock(),
        workspace=WorkspaceSnapshot(user={}),
        plan=Plan(),
    )
    state.written_files = written
    return state


def _opts(tmp_path: Path, *, dry_run: bool = False) -> WizardOptions:
    return WizardOptions(
        token="tok",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=dry_run,
    )


def test_dry_run_skips_pr_phase(monkeypatch, tmp_path):
    state = _state(tmp_path, written=[tmp_path / "x.yml"])
    # Should never get to gh check
    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: (_ for _ in ()).throw(AssertionError()))
    _phase_open_pr(state, _opts(tmp_path, dry_run=True))


def test_no_written_files_skips(monkeypatch, tmp_path):
    state = _state(tmp_path, written=[])
    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: (_ for _ in ()).throw(AssertionError()))
    _phase_open_pr(state, _opts(tmp_path))


def test_no_remote_url_skips(monkeypatch, tmp_path):
    state = _state(tmp_path, written=[tmp_path / "x.yml"], remote_url=None)
    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: (_ for _ in ()).throw(AssertionError()))
    _phase_open_pr(state, _opts(tmp_path))


def test_gh_not_authenticated_skips(monkeypatch, tmp_path):
    state = _state(tmp_path, written=[tmp_path / "x.yml"])
    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: False)
    # Should not invoke prompts at all; sentinel ensures that.
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    _phase_open_pr(state, _opts(tmp_path))


def test_dirty_tree_skips_pr(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(
        wizard_runner,
        "_git_check",
        lambda args, cwd: " M unrelated.py\n M wrote.yml" if args[0] == "status" else "",
    )
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    _phase_open_pr(state, _opts(tmp_path))


def test_decline_pr_prompt_does_not_invoke_git(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: False)

    def explode(*_a, **_kw):
        raise AssertionError("should not run subprocess when user declines")

    monkeypatch.setattr(wizard_runner, "_run_subprocess", explode)
    _phase_open_pr(state, _opts(tmp_path))


def test_branch_name_collision_with_target_aborts(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "main")  # same as target

    def explode(*_a, **_kw):
        raise AssertionError("should not invoke subprocess if branch == target")

    monkeypatch.setattr(wizard_runner, "_run_subprocess", explode)
    _phase_open_pr(state, _opts(tmp_path))


def test_happy_path_runs_git_and_gh(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "sbomify-setup")

    calls: list[list[str]] = []

    def fake_run(cmd, cwd, **kwargs):
        calls.append(cmd)
        result = subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "gh":
            result.stdout = "https://github.com/acme/repo/pull/123\n"
        return result

    monkeypatch.setattr(wizard_runner, "_run_subprocess", fake_run)
    _phase_open_pr(state, _opts(tmp_path))

    git_calls = [c for c in calls if c[0] == "git"]
    gh_calls = [c for c in calls if c[0] == "gh"]
    assert ["git", "checkout", "-b", "sbomify-setup"] in git_calls
    assert any(c[:3] == ["git", "add", "--"] for c in git_calls)
    assert any(c[:3] == ["git", "commit", "-m"] for c in git_calls)
    assert ["git", "push", "-u", "origin", "sbomify-setup"] in git_calls
    assert gh_calls and gh_calls[0][1] == "pr"
    assert "--base" in gh_calls[0] and "main" in gh_calls[0]
    assert "--head" in gh_calls[0] and "sbomify-setup" in gh_calls[0]


def _state_on_branch(tmp_path: Path, *, current: str, written: list[Path]) -> WizardState:
    state = _state(tmp_path, written=written)
    state.facts = RepoFacts(
        repo_root=tmp_path,
        is_git=True,
        remote_url="git@github.com:acme/repo.git",
        suggested_repo_name="repo",
        default_branch="main",
        current_branch=current,
        has_release_tags=False,
    )
    return state


def test_off_target_branch_skip_choice_does_not_invoke_git(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state_on_branch(tmp_path, current="feature", written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "sbomify-setup")
    monkeypatch.setattr(wizard_runner, "ask_select", lambda *a, **k: "Skip PR creation")

    def explode(*_a, **_kw):
        raise AssertionError("git/gh should not run when user picks Skip")

    monkeypatch.setattr(wizard_runner, "_run_subprocess", explode)
    _phase_open_pr(state, _opts(tmp_path))


def test_off_target_branch_switch_choice_checks_out_target(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state_on_branch(tmp_path, current="feature", written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "sbomify-setup")
    monkeypatch.setattr(wizard_runner, "ask_select", lambda *a, **k: "Switch to `main` first (recommended)")

    calls: list[list[str]] = []

    def fake_run(cmd, cwd, **kwargs):
        calls.append(cmd)
        result = subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "gh":
            result.stdout = "https://github.com/acme/repo/pull/9\n"
        return result

    monkeypatch.setattr(wizard_runner, "_run_subprocess", fake_run)
    _phase_open_pr(state, _opts(tmp_path))

    git_cmds = [c for c in calls if c[0] == "git"]
    assert ["git", "checkout", "main"] in git_cmds
    # Branch is still created on top of (now-checked-out) target.
    assert ["git", "checkout", "-b", "sbomify-setup"] in git_cmds


def test_subprocess_failure_is_reported_not_raised(monkeypatch, tmp_path):
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "sbomify-setup")

    def fake_run(cmd, cwd, **kwargs):
        if cmd[0] == "git" and "push" in cmd:
            raise subprocess.CalledProcessError(1, cmd, stderr="rejected")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(wizard_runner, "_run_subprocess", fake_run)
    # Should not raise — failure becomes a warning.
    _phase_open_pr(state, _opts(tmp_path))


def test_subprocess_timeout_is_reported_not_raised(monkeypatch, tmp_path, capsys):
    """`git push` / `gh pr create` on slow links can hit the timeout. The
    wizard must degrade to a warning, not propagate `TimeoutExpired`."""
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "sbomify-setup")

    def fake_run(cmd, cwd, **kwargs):
        if cmd[0] == "git" and "push" in cmd:
            raise subprocess.TimeoutExpired(cmd, timeout=300, stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(wizard_runner, "_run_subprocess", fake_run)
    _phase_open_pr(state, _opts(tmp_path))

    # Should print a friendly warning mentioning the command and timeout.
    captured = capsys.readouterr().out
    assert "timed out" in captured
    assert "git" in captured


def test_network_subprocesses_get_extended_timeout(monkeypatch, tmp_path):
    """`git push` and `gh pr create` must be invoked with the longer
    network-bound timeout, not the default 60s."""
    written = [tmp_path / "wrote.yml"]
    written[0].write_text("yml")
    state = _state(tmp_path, written=written)

    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: True)
    monkeypatch.setattr(wizard_runner, "_has_unrelated_dirty_files", lambda *_: False)
    monkeypatch.setattr(wizard_runner, "ask_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard_runner, "ask_text", lambda *a, **k: "sbomify-setup")

    timeouts: dict[str, int | None] = {}

    def fake_run(cmd, cwd, **kwargs):
        if cmd[0] == "git" and "push" in cmd:
            timeouts["push"] = kwargs.get("timeout")
        elif cmd[0] == "gh" and "pr" in cmd:
            timeouts["gh"] = kwargs.get("timeout")
        result = subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "gh":
            result.stdout = "https://github.com/acme/repo/pull/1\n"
        return result

    monkeypatch.setattr(wizard_runner, "_run_subprocess", fake_run)
    _phase_open_pr(state, _opts(tmp_path))

    # Both network calls must opt into the longer timeout; the exact value
    # is the `_NETWORK_TIMEOUT` constant, but assert it's well above 60s
    # to leave room to tune.
    assert timeouts.get("push") is not None and timeouts["push"] > 60
    assert timeouts.get("gh") is not None and timeouts["gh"] > 60
