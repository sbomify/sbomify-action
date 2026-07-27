"""Tests for the wizard's Publish step (local generate-and-upload).

Covers the pure planning helpers (``matrix_rows`` / ``build_publish_runs`` /
``_build_env``), the ``run_publish`` orchestration with the subprocess
boundary stubbed out, and the Done screen's published-SBOMs summary text
(same ``__new__`` + stubbed ``wizard`` property pattern as
test_wizard_done.py — full composition is covered by the Textual smoke
tests).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sbomify_action.cli.wizard import publish as publish_mod
from sbomify_action.cli.wizard.ci_emitter import matrix_rows
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.screens.done import DoneScreen
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
    Plan,
    PlannedComponent,
    PublishOutcome,
    RepoFacts,
    WizardState,
)


def _facts(repo_root: Path) -> RepoFacts:
    return RepoFacts(
        repo_root=repo_root,
        is_git=True,
        remote_url="git@github.com:acme/widget.git",
        suggested_repo_name="widget",
        default_branch="main",
        current_branch="main",
        has_release_tags=False,
        owner_repo_slug="acme/widget",
    )


def _lockfile(tmp_path: Path, rel: str, ecosystem: str = "python") -> DiscoveredLockfile:
    return DiscoveredLockfile(
        path=tmp_path / rel,
        rel_path=Path(rel),
        ecosystem=ecosystem,
        suggested_name=rel.split("/")[-1],
    )


def _state(tmp_path: Path, *, formats: list[str] | None = None, augmentation: str = "skip") -> WizardState:
    lock = _lockfile(tmp_path, "uv.lock")
    state = WizardState(facts=_facts(tmp_path))
    state.plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=lock, name="widget-py")],
        sbom_formats=formats or ["cyclonedx"],  # type: ignore[arg-type]
        augmentation=augmentation,  # type: ignore[arg-type]
    )
    state.component_ids = {Path("uv.lock"): "comp-1"}
    state.api = SimpleNamespace(token="sess-token")  # type: ignore[assignment]
    return state


def _opts(tmp_path: Path, *, dry_run: bool = False) -> WizardOptions:
    return WizardOptions(
        token="sess-token",
        api_base_url="https://app.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=dry_run,
    )


@pytest.fixture()
def out_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Route run_publish's mkdtemp into the test's tmp_path."""
    target = tmp_path / "publish-out"
    target.mkdir()
    monkeypatch.setattr(publish_mod.tempfile, "mkdtemp", lambda prefix: str(target))
    return target


# ----------------------------------------------------------------------
# matrix_rows / build_publish_runs


def test_matrix_rows_single_component_single_format(tmp_path: Path) -> None:
    rows = matrix_rows(
        [PlannedComponent(lockfile=_lockfile(tmp_path, "uv.lock"), name="widget-py")],
        ["cyclonedx"],
        {"uv.lock": "comp-1"},
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.name == "widget-py"
    assert row.component_id == "comp-1"
    assert row.lockfile == "uv.lock"
    assert row.output_file == "widget-py.cdx.json"


def test_matrix_rows_multi_format_suffixes_name_and_extension(tmp_path: Path) -> None:
    rows = matrix_rows(
        [PlannedComponent(lockfile=_lockfile(tmp_path, "uv.lock"), name="widget-py")],
        ["cyclonedx", "spdx"],
        {"uv.lock": "comp-1"},
    )
    assert [r.name for r in rows] == ["widget-py-cyclonedx", "widget-py-spdx"]
    assert [r.output_file for r in rows] == ["widget-py.cdx.json", "widget-py.spdx.json"]


def test_matrix_rows_duplicate_names_disambiguated_by_lockfile_slug(tmp_path: Path) -> None:
    rows = matrix_rows(
        [
            PlannedComponent(lockfile=_lockfile(tmp_path, "a/uv.lock"), name="widget"),
            PlannedComponent(lockfile=_lockfile(tmp_path, "b/uv.lock"), name="widget"),
        ],
        ["cyclonedx"],
        {"a/uv.lock": "c1", "b/uv.lock": "c2"},
    )
    outputs = [r.output_file for r in rows]
    assert len(set(outputs)) == 2, f"duplicate output files: {outputs}"


def test_build_publish_runs_places_outputs_in_output_dir(tmp_path: Path) -> None:
    state = _state(tmp_path, formats=["cyclonedx", "spdx"])
    runs = publish_mod.build_publish_runs(state, tmp_path / "out")
    assert [r.output_path for r in runs] == [
        tmp_path / "out" / "widget-py.cdx.json",
        tmp_path / "out" / "widget-py.spdx.json",
    ]
    # Real IDs from apply, never the placeholder.
    assert all(r.row.component_id == "comp-1" for r in runs)


# ----------------------------------------------------------------------
# _build_env


def test_build_env_mirrors_workflow_env_with_session_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A stray pipeline var in the caller's environment must not leak in.
    monkeypatch.setenv("DOCKER_IMAGE", "nginx:latest")
    monkeypatch.setenv("SBOM_FILE", "stale.json")
    monkeypatch.setenv("HOME", str(tmp_path))  # unrelated vars survive

    state = _state(tmp_path, augmentation="profile")
    state.plan.enrich = False
    runs = publish_mod.build_publish_runs(state, tmp_path / "out")
    env = publish_mod._build_env(runs[0], state, _opts(tmp_path), version="abc1234")

    assert env["TOKEN"] == "sess-token"
    assert env["COMPONENT_ID"] == "comp-1"
    assert env["COMPONENT_NAME"] == "widget-py"
    assert env["COMPONENT_VERSION"] == "abc1234"
    assert env["LOCK_FILE"] == "uv.lock"
    assert env["UPLOAD"] == "true"
    assert env["AUGMENT"] == "true"  # profile → AUGMENT=true, same as the emitter
    assert env["ENRICH"] == "false"
    assert env["SBOM_FORMAT"] == "cyclonedx"
    assert env["OUTPUT_FILE"] == str(tmp_path / "out" / "widget-py.cdx.json")
    assert env["API_BASE_URL"] == "https://app.test"
    assert "DOCKER_IMAGE" not in env
    assert "SBOM_FILE" not in env
    assert "PRODUCT_RELEASE" not in env  # releases stay CI's job
    assert env["HOME"] == str(tmp_path)


def test_build_env_omits_version_when_unknown(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runs = publish_mod.build_publish_runs(state, tmp_path / "out")
    env = publish_mod._build_env(runs[0], state, _opts(tmp_path), version=None)
    assert "COMPONENT_VERSION" not in env


# ----------------------------------------------------------------------
# component_version


def test_component_version_returns_short_sha(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        publish_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="abc1234\n"),
    )
    assert publish_mod.component_version(tmp_path) == "abc1234"


def test_component_version_none_when_git_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        publish_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=128, stdout=""),
    )
    assert publish_mod.component_version(tmp_path) is None


def test_component_version_none_when_git_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise OSError("git not found")

    monkeypatch.setattr(publish_mod.subprocess, "run", _boom)
    assert publish_mod.component_version(tmp_path) is None


# ----------------------------------------------------------------------
# _stream_subprocess — the real subprocess boundary


def test_stream_subprocess_forwards_merged_output_and_exit_code(tmp_path: Path) -> None:
    import sys

    lines: list[str] = []
    code = publish_mod._stream_subprocess(
        [
            sys.executable,
            "-c",
            "import sys; print('to stdout'); print('to stderr', file=sys.stderr); sys.exit(3)",
        ],
        env={"PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        on_line=lines.append,
    )
    assert code == 3
    assert "to stdout" in lines
    assert "to stderr" in lines  # stderr merged into stdout


# ----------------------------------------------------------------------
# run_publish


def test_run_publish_success_records_ok_outcomes(
    tmp_path: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(tmp_path)
    calls: list[dict] = []

    def fake_stream(cmd: list[str], *, env: dict, cwd: Path, on_line) -> int:
        calls.append({"cmd": cmd, "env": env, "cwd": cwd})
        on_line("step 1 ok")
        return 0

    monkeypatch.setattr(publish_mod, "_stream_subprocess", fake_stream)
    monkeypatch.setattr(publish_mod, "component_version", lambda _root: "abc1234")
    logs: list[tuple[str, str]] = []

    all_ok = publish_mod.run_publish(state, _opts(tmp_path), log=lambda k, m: logs.append((k, m)))

    assert all_ok is True
    assert state.publish_output_dir == out_dir
    assert len(calls) == 1
    assert calls[0]["cwd"] == tmp_path  # repo root: LOCK_FILE + sbomify.json resolve from here
    assert calls[0]["cmd"][1:] == ["-c", publish_mod._PIPELINE_BOOTSTRAP]
    assert calls[0]["env"]["TOKEN"] == "sess-token"
    assert state.publish_outcomes == [
        PublishOutcome(
            rel_path="uv.lock",
            sbom_format="cyclonedx",
            output_file=out_dir / "widget-py.cdx.json",
            ok=True,
        )
    ]
    # Raw subprocess lines are forwarded with the "output" kind.
    assert ("output", "step 1 ok") in logs
    assert any(k == "success" and "Published" in m for k, m in logs)


def test_run_publish_failure_continues_to_next_run(
    tmp_path: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(tmp_path, formats=["cyclonedx", "spdx"])
    exit_codes = iter([1, 0])
    monkeypatch.setattr(
        publish_mod,
        "_stream_subprocess",
        lambda cmd, *, env, cwd, on_line: next(exit_codes),
    )
    monkeypatch.setattr(publish_mod, "component_version", lambda _root: None)
    logs: list[tuple[str, str]] = []

    all_ok = publish_mod.run_publish(state, _opts(tmp_path), log=lambda k, m: logs.append((k, m)))

    assert all_ok is False
    assert [o.ok for o in state.publish_outcomes] == [False, True]
    assert state.publish_outcomes[0].error == "pipeline exited with code 1"
    assert any(k == "warning" and "1 of 2" in m for k, m in logs)


def test_run_publish_spawn_error_is_recorded_not_raised(
    tmp_path: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(tmp_path)

    def _boom(cmd: list[str], *, env: dict, cwd: Path, on_line) -> int:
        raise OSError("exec format error")

    monkeypatch.setattr(publish_mod, "_stream_subprocess", _boom)
    monkeypatch.setattr(publish_mod, "component_version", lambda _root: None)

    all_ok = publish_mod.run_publish(state, _opts(tmp_path))

    assert all_ok is False
    assert state.publish_outcomes[0].ok is False
    assert "exec format error" in (state.publish_outcomes[0].error or "")


def test_run_publish_dry_run_spawns_nothing(tmp_path: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(tmp_path)
    state.is_dry_run = True
    state.api = None  # dry-run must not need the API client

    def _fail(*a: object, **k: object) -> int:
        raise AssertionError("dry-run must not spawn a subprocess")

    monkeypatch.setattr(publish_mod, "_stream_subprocess", _fail)
    logs: list[tuple[str, str]] = []

    all_ok = publish_mod.run_publish(state, _opts(tmp_path, dry_run=True), log=lambda k, m: logs.append((k, m)))

    assert all_ok is True
    assert [o.ok for o in state.publish_outcomes] == [True]
    assert any("Would generate" in m for _k, m in logs)


def test_run_publish_with_no_components_is_a_noop(
    tmp_path: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(tmp_path)
    state.plan.create_components = []
    state.component_ids = {}
    monkeypatch.setattr(
        publish_mod,
        "_stream_subprocess",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("nothing to run")),
    )
    logs: list[tuple[str, str]] = []

    assert publish_mod.run_publish(state, _opts(tmp_path), log=lambda k, m: logs.append((k, m))) is True
    assert state.publish_outcomes == []
    assert any(k == "warning" for k, _m in logs)


def test_reset_apply_artifacts_clears_publish_state(tmp_path: Path) -> None:
    state = _state(tmp_path)
    state.publish_outcomes = [
        PublishOutcome(rel_path="uv.lock", sbom_format="cyclonedx", output_file=tmp_path / "x.json", ok=True)
    ]
    state.publish_output_dir = tmp_path

    state.reset_apply_artifacts()

    assert state.publish_outcomes == []
    assert state.publish_output_dir is None


# ----------------------------------------------------------------------
# Publish screen — planned-runs text


def test_publish_screen_planned_markup_lists_each_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from sbomify_action.cli.wizard.screens.publish import PublishScreen

    state = _state(tmp_path, formats=["cyclonedx", "spdx"])
    screen = PublishScreen.__new__(PublishScreen)  # bypass Textual Screen.__init__ (needs an app)
    fake_wizard = SimpleNamespace(state=state, opts=_opts(tmp_path))
    monkeypatch.setattr(PublishScreen, "wizard", property(lambda self: fake_wizard))

    text = screen._planned_markup()

    assert text.count("widget-py") == 2  # one line per (lockfile, format) row
    assert "→ cyclonedx" in text
    assert "→ spdx" in text
    assert "Skipping is fine" in text


# ----------------------------------------------------------------------
# Done screen — published panel text


def _done_screen(monkeypatch: pytest.MonkeyPatch, state: WizardState) -> DoneScreen:
    screen = DoneScreen.__new__(DoneScreen)  # bypass Textual Screen.__init__ (needs an app)
    fake_wizard = SimpleNamespace(state=state, opts=SimpleNamespace(api_base_url="https://app.test"))
    monkeypatch.setattr(DoneScreen, "wizard", property(lambda self: fake_wizard))
    return screen


def test_published_summary_lists_successes_and_output_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _state(tmp_path)
    state.publish_output_dir = tmp_path / "out"
    state.publish_outcomes = [
        PublishOutcome(rel_path="uv.lock", sbom_format="cyclonedx", output_file=tmp_path / "w.cdx.json", ok=True)
    ]

    text = _done_screen(monkeypatch, state)._published_summary()

    assert "Published" in text
    assert "uv.lock" in text
    assert str(tmp_path / "out") in text


def test_published_summary_shows_failure_reason_and_ci_note(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _state(tmp_path)
    state.publish_outcomes = [
        PublishOutcome(
            rel_path="uv.lock",
            sbom_format="cyclonedx",
            output_file=tmp_path / "w.cdx.json",
            ok=False,
            error="pipeline exited with code 1",
        )
    ]

    text = _done_screen(monkeypatch, state)._published_summary()

    assert "Failed" in text
    assert "pipeline exited with code 1" in text
    assert "CI retries on the next push" in text


def test_published_summary_dry_run_uses_would_publish_phrasing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _state(tmp_path)
    state.is_dry_run = True
    state.publish_outcomes = [
        PublishOutcome(rel_path="uv.lock", sbom_format="cyclonedx", output_file=tmp_path / "w.cdx.json", ok=True)
    ]

    text = _done_screen(monkeypatch, state)._published_summary()

    assert "would publish" in text
    assert "--dry-run" in text
