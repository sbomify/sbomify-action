"""Tests for the Components screen's Reload.

Components are prefetched once, during authentication. If someone creates a
component in the sbomify UI while sitting on this screen, the list is stale and
the only remedy was restarting the wizard. Reload refetches just that list.

The interesting behaviour is not the fetch, it is that a refetch must not throw
away choices the user has already made on the screen.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from textual.widgets import Input, OptionList

from sbomify_action.cli.wizard.app import WizardApp
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.screens.components import ComponentsScreen
from sbomify_action.cli.wizard.state import WorkspaceSnapshot
from sbomify_action.cli.wizard.widgets import PickOrCreate

EXISTING = [{"id": "c1", "name": "Existing JS Component"}]
AFTER_RELOAD = EXISTING + [{"id": "c2", "name": "Created While You Waited"}]


def _app(tmp_path: Path) -> WizardApp:
    for name in ("Cargo.lock", "bun.lock"):
        (tmp_path / name).write_text("")
    opts = WizardOptions(
        token="x",
        api_base_url="https://app.sbomify.invalid",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github/workflows",
        dry_run=True,
    )
    os.environ.pop("CI", None)
    os.environ.pop("GITHUB_ACTIONS", None)
    app = WizardApp(opts)
    app.state.selected = list(app.state.discovered)
    app.state.workspace = WorkspaceSnapshot(products=[], components=list(EXISTING), contact_profiles=[], team_key="t")
    return app


async def _settle(screen, pilot, tries: int = 60) -> None:
    for _ in range(tries):
        await pilot.pause(0.05)
        if not screen._reloading:
            break
    await pilot.pause(0.1)


def _rows(screen, idx: int) -> int:
    picker = screen.query_one(f"#component-{idx}", PickOrCreate)
    return picker.query_one(f"#{picker._list_id}", OptionList).option_count


@pytest.mark.parametrize("_", [0])
def test_reload_pulls_in_server_side_changes(tmp_path: Path, _):
    app = _app(tmp_path)
    api = MagicMock()
    api.list_components.return_value = AFTER_RELOAD
    app.state.api = api

    async def scenario():
        async with app.run_test() as pilot:
            screen = ComponentsScreen()
            await app.push_screen(screen)
            await pilot.pause()

            # "Create new" + one existing component
            assert _rows(screen, 0) == 2

            screen.action_reload()
            await _settle(screen, pilot)

            assert api.list_components.call_count == 1
            assert len(app.state.workspace.components) == 2
            # The newly created component is now offered.
            assert _rows(screen, 0) == 3

    asyncio.run(scenario())


@pytest.mark.parametrize("_", [0])
def test_reload_preserves_what_the_user_already_chose(tmp_path: Path, _):
    """The point of the feature is lost if reloading resets the form."""
    app = _app(tmp_path)
    api = MagicMock()
    api.list_components.return_value = AFTER_RELOAD
    app.state.api = api

    async def scenario():
        async with app.run_test() as pilot:
            screen = ComponentsScreen()
            await app.push_screen(screen)
            await pilot.pause()

            first = screen.query_one("#component-0", PickOrCreate)
            second = screen.query_one("#component-1", PickOrCreate)
            # Point the first lockfile at the existing component, and type a
            # deliberate name for the second.
            first.query_one(f"#{first._list_id}", OptionList).highlighted = 1
            second.query_one(f"#{second._input_id}", Input).value = "hand-picked-name"
            await pilot.pause()
            assert first.picked_id == "c1"

            screen.action_reload()
            await _settle(screen, pilot)

            first = screen.query_one("#component-0", PickOrCreate)
            second = screen.query_one("#component-1", PickOrCreate)
            assert first.picked_id == "c1", "explicit pick must survive a reload"
            assert second.new_value == "hand-picked-name", "typed name must survive a reload"

    asyncio.run(scenario())


@pytest.mark.parametrize("_", [0])
def test_reload_reports_api_failure_without_losing_state(tmp_path: Path, _):
    """A failed refetch must leave the existing list intact, not blank it."""
    from sbomify_action.exceptions import APIError

    app = _app(tmp_path)
    api = MagicMock()
    api.list_components.side_effect = APIError("boom [503]")
    app.state.api = api

    async def scenario():
        async with app.run_test() as pilot:
            screen = ComponentsScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.action_reload()
            await _settle(screen, pilot)

            assert app.state.workspace.components == EXISTING
            assert _rows(screen, 0) == 2
            status = str(screen.query_one("#components-status").visual)
            assert "failed" in status.lower()

    asyncio.run(scenario())


@pytest.mark.parametrize("_", [0])
def test_reload_without_authentication_is_a_no_op(tmp_path: Path, _):
    app = _app(tmp_path)
    app.state.api = None

    async def scenario():
        async with app.run_test() as pilot:
            screen = ComponentsScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.action_reload()
            await pilot.pause(0.1)

            status = str(screen.query_one("#components-status").visual)
            assert "not authenticated" in status.lower()

    asyncio.run(scenario())
