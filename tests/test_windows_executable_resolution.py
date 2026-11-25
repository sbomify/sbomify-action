"""run_command must hand Windows a full path, or npm's .cmd shims are never found."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from sbomify_action._generation import utils
from sbomify_action._generation.utils import resolve_windows_executable, run_command

SHIM = r"C:\Users\dev\AppData\Roaming\npm\cdxgen.CMD"


def test_posix_commands_pass_through_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(utils.os, "name", "posix")
    monkeypatch.setattr(utils.shutil, "which", lambda *a, **k: pytest.fail("which must not run off Windows"))
    assert resolve_windows_executable(["cdxgen", "-o", "out.json"]) == ["cdxgen", "-o", "out.json"]


def test_windows_resolves_the_cmd_shim(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def which(name: str, path: str | None = None) -> str:
        seen.update(name=name, path=path)
        return SHIM

    monkeypatch.setattr(utils.os, "name", "nt")
    monkeypatch.setattr(utils.shutil, "which", which)
    assert resolve_windows_executable(["cdxgen", "-t", "dart", "."], r"C:\npm") == [SHIM, "-t", "dart", "."]
    assert seen == {"name": "cdxgen", "path": r"C:\npm"}


def test_windows_leaves_an_unknown_command_for_the_not_found_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(utils.os, "name", "nt")
    monkeypatch.setattr(utils.shutil, "which", lambda *a, **k: None)
    assert resolve_windows_executable(["cdxgen", "."]) == ["cdxgen", "."]


def test_windows_handles_an_empty_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(utils.os, "name", "nt")
    assert resolve_windows_executable([]) == []


def test_run_command_executes_the_resolved_path_with_the_child_path(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}

    def which(name: str, path: str | None = None) -> str:
        calls["which_path"] = path
        return SHIM

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls["cmd"] = cmd
        calls["env_path"] = kwargs["env"].get("PATH")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(utils.os, "name", "nt")
    monkeypatch.setattr(utils.shutil, "which", which)
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    run_command(["cdxgen", "."], "cdxgen", env={"PATH": r"C:\tools"})

    assert calls["cmd"] == [SHIM, "."]
    # Resolved against the PATH the child will actually see, not ours.
    assert calls["which_path"] == calls["env_path"] == r"C:\tools"
