"""Tests for the optional final wizard step: generate + upload SBOMs now.

Covers the non-UI ``generate`` module (job expansion, the availability
gate, and the subprocess-driven run) plus a smoke test of the
GenerateScreen's skip path.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard import generate as gen
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
    PlannedComponent,
    RepoFacts,
    WizardState,
)


def _facts(tmp_path: Path) -> RepoFacts:
    return RepoFacts(
        repo_root=tmp_path,
        is_git=True,
        remote_url="git@github.com:acme/widget.git",
        suggested_repo_name="widget",
        default_branch="main",
        current_branch="main",
        has_release_tags=False,
        owner_repo_slug="acme/widget",
    )


def _lockfile(tmp_path: Path, name: str = "uv.lock", ecosystem: str = "python") -> DiscoveredLockfile:
    return DiscoveredLockfile(
        path=tmp_path / name,
        rel_path=Path(name),
        ecosystem=ecosystem,
        suggested_name="widget-py",
    )


def _state(tmp_path: Path, *, formats: list[str] | None = None, with_id: bool = True) -> WizardState:
    lock = _lockfile(tmp_path)
    state = WizardState(facts=_facts(tmp_path))
    state.plan.create_components = [PlannedComponent(lockfile=lock, name="widget-py")]
    state.plan.sbom_formats = formats or ["cyclonedx"]
    if with_id:
        state.component_ids[lock.rel_path] = "comp-123"
    state.api = MagicMock()
    state.api.token = "t-secret"
    return state


def _all_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gen, "check_tool_for_input", lambda _input, _name: (["syft"], []))


def _none_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gen, "check_tool_for_input", lambda _input, _name: ([], ["syft"]))


# ----- plan_generation_jobs -------------------------------------------


def test_jobs_expand_per_component_and_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _all_available(monkeypatch)
    state = _state(tmp_path, formats=["cyclonedx", "spdx"])
    jobs = gen.plan_generation_jobs(state)
    assert len(jobs) == 2
    assert {j.sbom_format for j in jobs} == {"cyclonedx", "spdx"}
    assert all(j.component_id == "comp-123" for j in jobs)
    assert all(j.available for j in jobs)


def test_jobs_skip_components_without_resolved_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A planned component apply never produced an id for (eg it failed)
    has nothing to upload against, so it yields no job."""
    _all_available(monkeypatch)
    state = _state(tmp_path, with_id=False)
    assert gen.plan_generation_jobs(state) == []


def test_jobs_mark_unavailable_when_no_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _none_available(monkeypatch)
    jobs = gen.plan_generation_jobs(_state(tmp_path))
    assert len(jobs) == 1
    assert jobs[0].available is False


# ----- generation_available -------------------------------------------


def test_available_true_when_tool_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _all_available(monkeypatch)
    assert gen.generation_available(_state(tmp_path)) is True


def test_available_false_when_no_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _none_available(monkeypatch)
    assert gen.generation_available(_state(tmp_path)) is False


def test_available_false_on_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _all_available(monkeypatch)
    state = _state(tmp_path)
    state.is_dry_run = True
    assert gen.generation_available(state) is False


def test_available_false_without_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _all_available(monkeypatch)
    state = _state(tmp_path)
    state.api = None
    assert gen.generation_available(state) is False


# ----- run_generation -------------------------------------------------


class _FakeProc:
    def __init__(self, lines: list[str], returncode: int) -> None:
        self.stdout = iter(lines)
        self.returncode = returncode
        self.waited = False

    def wait(self) -> None:
        self.waited = True


def test_run_generation_invokes_pipeline_per_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _all_available(monkeypatch)
    monkeypatch.setattr(gen, "_detect_version", lambda _root: "abc1234")
    state = _state(tmp_path, formats=["cyclonedx", "spdx"])

    calls: list[dict[str, str]] = []

    def fake_popen(cmd, *, cwd, env, stdout, stderr, text, bufsize):  # noqa: ANN001
        calls.append(env)
        return _FakeProc(["generating…", "uploaded ✓"], 0)

    monkeypatch.setattr(gen.subprocess, "Popen", fake_popen)

    logs: list[tuple[str, str]] = []
    succeeded, total = gen.run_generation(
        state, api_base_url="https://app.sbomify.test", repo_root=tmp_path, log=lambda k, m: logs.append((k, m))
    )

    assert (succeeded, total) == (2, 2)
    assert len(calls) == 2
    env = calls[0]
    assert env["TOKEN"] == "t-secret"
    assert env["SBOMIFY_TOKEN"] == "t-secret"
    assert env["COMPONENT_ID"] == "comp-123"
    assert env["LOCK_FILE"] == "uv.lock"
    assert env["UPLOAD"] == "true"
    assert env["COMPONENT_VERSION"] == "abc1234"
    assert env["API_BASE_URL"] == "https://app.sbomify.test"
    # Child stdout lines were streamed through the log callback.
    assert any("uploaded" in m for _k, m in logs)


def test_run_generation_counts_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _all_available(monkeypatch)
    monkeypatch.setattr(gen, "_detect_version", lambda _root: None)
    state = _state(tmp_path)
    monkeypatch.setattr(gen.subprocess, "Popen", lambda *a, **k: _FakeProc(["boom"], 1))

    succeeded, total = gen.run_generation(state, api_base_url="https://x.test", repo_root=tmp_path)
    assert (succeeded, total) == (0, 1)


def test_run_generation_skips_unavailable_and_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _none_available(monkeypatch)
    state = _state(tmp_path)
    popen = MagicMock()
    monkeypatch.setattr(gen.subprocess, "Popen", popen)

    logs: list[tuple[str, str]] = []
    succeeded, total = gen.run_generation(
        state, api_base_url="https://x.test", repo_root=tmp_path, log=lambda k, m: logs.append((k, m))
    )

    assert (succeeded, total) == (0, 0)
    popen.assert_not_called()
    assert any(kind == "warning" for kind, _ in logs)


# ----- apply → generate routing ---------------------------------------


def _stub_wizard(monkeypatch: pytest.MonkeyPatch, screen_cls: type, state: WizardState) -> list[object]:
    """Override the ``.wizard`` property so a screen built via ``__new__``
    can drive navigation without a live Textual app."""
    pushed: list[object] = []
    fake_wizard = MagicMock()
    fake_wizard.state = state
    fake_wizard.push_screen = pushed.append
    monkeypatch.setattr(screen_cls, "wizard", property(lambda _self: fake_wizard))
    return pushed


def test_apply_routes_to_generate_when_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbomify_action.cli.wizard.screens.apply import ApplyScreen
    from sbomify_action.cli.wizard.screens.generate import GenerateScreen

    _all_available(monkeypatch)
    state = _state(tmp_path)
    pushed = _stub_wizard(monkeypatch, ApplyScreen, state)

    screen = ApplyScreen.__new__(ApplyScreen)
    screen._advance_after_apply()

    assert len(pushed) == 1 and isinstance(pushed[0], GenerateScreen)


def test_apply_routes_to_done_when_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbomify_action.cli.wizard.screens.apply import ApplyScreen
    from sbomify_action.cli.wizard.screens.done import DoneScreen

    _none_available(monkeypatch)
    state = _state(tmp_path)
    pushed = _stub_wizard(monkeypatch, ApplyScreen, state)

    screen = ApplyScreen.__new__(ApplyScreen)
    screen._advance_after_apply()

    assert len(pushed) == 1 and isinstance(pushed[0], DoneScreen)


# ----- GenerateScreen smoke -------------------------------------------


def _live_opts(tmp_path: Path):  # noqa: ANN202
    from sbomify_action.cli.wizard.options import WizardOptions

    return WizardOptions(
        token="t-fake",
        api_base_url="https://app.sbomify.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=False,
    )


def _seed_app_state(app, tmp_path: Path) -> None:  # noqa: ANN001
    lock = _lockfile(tmp_path)
    app.state.plan.create_components = [PlannedComponent(lockfile=lock, name="widget-py")]
    app.state.component_ids[lock.rel_path] = "comp-123"
    app.state.api = MagicMock()
    app.state.api.token = "t-fake"


async def test_generate_screen_skip_goes_to_done(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbomify_action.cli.wizard.app import WizardApp
    from sbomify_action.cli.wizard.screens.done import DoneScreen
    from sbomify_action.cli.wizard.screens.generate import GenerateScreen

    monkeypatch.setattr("sbomify_action.cli.wizard.app.discovery.discover", lambda _root, repo_name=None: [])
    _all_available(monkeypatch)

    app = WizardApp(_live_opts(tmp_path))
    async with app.run_test() as pilot:
        _seed_app_state(app, tmp_path)
        await app.push_screen(GenerateScreen())
        await pilot.pause()
        assert isinstance(app.screen, GenerateScreen)
        await pilot.press("escape")  # Skip
        await pilot.pause()
        assert isinstance(app.screen, DoneScreen)


async def test_generate_screen_runs_and_records_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pressing Generate runs the (mocked) pipeline, records the outcome on
    state, and Continue advances to Done."""
    from textual.widgets import Button

    from sbomify_action.cli.wizard.app import WizardApp
    from sbomify_action.cli.wizard.screens.done import DoneScreen
    from sbomify_action.cli.wizard.screens.generate import GenerateScreen

    monkeypatch.setattr("sbomify_action.cli.wizard.app.discovery.discover", lambda _root, repo_name=None: [])
    _all_available(monkeypatch)
    # Mock the actual subprocess-driven run so the worker finishes instantly.
    monkeypatch.setattr(gen, "run_generation", lambda *a, **k: (1, 1))

    app = WizardApp(_live_opts(tmp_path))
    async with app.run_test() as pilot:
        _seed_app_state(app, tmp_path)
        await app.push_screen(GenerateScreen())
        await pilot.pause()
        app.screen.query_one("#generate", Button).press()
        await pilot.pause()
        await pilot.pause()

        assert app.state.generated_ok == 1
        assert app.state.generated_total == 1
        # Continue is revealed; pressing it lands on Done.
        app.screen.query_one("#continue", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, DoneScreen)
