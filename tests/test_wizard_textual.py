"""Integration tests for the Textual wizard, driven via `App.run_test()`.

These tests exercise the user-visible flow (welcome → discover → product →
configure → review → done) using Textual's Pilot API. They are deliberately
end-to-end-flavoured rather than per-screen unit tests because the wizard's
contract is "the user can move forward and the state accumulates correctly" —
small per-widget tests would lock in implementation details.

Per-screen rendering / styling is verified visually by the maintainer; we
only assert that screens push the next screen and that wizard state is
mutated as expected.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard.app import WizardApp
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
)


def _opts(tmp_path: Path, *, dry_run: bool = True) -> WizardOptions:
    return WizardOptions(
        token="t-fake",
        api_base_url="https://app.sbomify.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=dry_run,
    )


def _stub_discovery(monkeypatch: pytest.MonkeyPatch, lockfiles: list[DiscoveredLockfile]) -> None:
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.discover.discovery.discover",
        lambda _root: lockfiles,
    )


def _stub_client(monkeypatch: pytest.MonkeyPatch, *, products=None, components=None, profiles=None) -> MagicMock:
    """Replace SbomifyClient in authenticate.py with a stub that succeeds."""
    products = products or []
    components = components or []
    profiles = profiles or []

    instance = MagicMock()
    instance.whoami.return_value = {"authenticated": True}
    instance.list_products.return_value = products
    instance.list_components.return_value = components
    instance.list_contact_profiles.return_value = profiles

    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.authenticate.SbomifyClient",
        lambda *_a, **_kw: instance,
    )
    return instance


@pytest.mark.asyncio
async def test_welcome_screen_mounts_with_repo_facts(tmp_path):
    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.pause()
        # Welcome screen is the entry point.
        from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

        assert isinstance(app.screen, WelcomeScreen)
        # Facts were gathered synchronously before run().
        assert app.state.facts.repo_root == tmp_path.resolve()


@pytest.mark.asyncio
async def test_welcome_enter_advances_to_discover(tmp_path):
    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        assert isinstance(app.screen, DiscoverScreen)


@pytest.mark.asyncio
async def test_discover_with_no_lockfiles_disables_continue(tmp_path, monkeypatch):
    _stub_discovery(monkeypatch, [])
    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")  # advance to discover
        await pilot.pause()
        from textual.widgets import Button

        cont = app.screen.query_one("#continue", Button)
        assert cont.disabled is True


@pytest.mark.asyncio
async def test_discover_continue_pushes_authenticate(tmp_path, monkeypatch):
    lockfile = DiscoveredLockfile(
        path=tmp_path / "uv.lock",
        rel_path=Path("uv.lock"),
        ecosystem="python",
        suggested_name="my-svc",
    )
    _stub_discovery(monkeypatch, [lockfile])
    _stub_client(monkeypatch, products=[{"id": "p1", "name": "demo"}])

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")  # welcome → discover
        await pilot.pause()
        await pilot.press("enter")  # confirm picker selections
        # Authenticate screen kicks off a worker; wait for it to finish.
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        # After auth, ProductScreen is on top.
        from sbomify_action.cli.wizard.screens.product import ProductScreen

        assert isinstance(app.screen, ProductScreen)
        assert app.state.api is not None
        assert app.state.workspace is not None
        assert len(app.state.selected) == 1


@pytest.mark.asyncio
async def test_authenticate_reports_bad_token(tmp_path, monkeypatch):
    """A 401 from whoami must surface as an inline error, not crash."""
    from sbomify_action.cli.wizard.client import SbomifyAuthError

    lockfile = DiscoveredLockfile(
        path=tmp_path / "uv.lock",
        rel_path=Path("uv.lock"),
        ecosystem="python",
        suggested_name="my-svc",
    )
    _stub_discovery(monkeypatch, [lockfile])

    bad = MagicMock()
    bad.whoami.side_effect = SbomifyAuthError(401, "Token rejected")
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.authenticate.SbomifyClient",
        lambda *_a, **_kw: bad,
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")  # discover → authenticate
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        # Still on authenticate screen — status shows the rejection.
        from textual.widgets import Static

        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen

        assert isinstance(app.screen, AuthenticateScreen)
        # Render the status widget to plaintext and confirm the error text shows.
        status = app.screen.query_one("#auth-status", Static)
        rendered = str(status.render()).lower()
        assert "rejected" in rendered or "token" in rendered


@pytest.mark.asyncio
async def test_existing_workflow_prefills_configure_screen(tmp_path, monkeypatch):
    """A pre-existing sbomify workflow for the discovered lockfile should
    make the configure screen pre-fill the name + release strategy from it
    instead of falling back to the lockfile-derived suggestion."""
    import textwrap

    from textual.widgets import Input, RadioButton

    # Lockfile the wizard will discover.
    lockfile = DiscoveredLockfile(
        path=tmp_path / "uv.lock",
        rel_path=Path("uv.lock"),
        ecosystem="python",
        suggested_name="default-suggestion",
    )
    _stub_discovery(monkeypatch, [lockfile])

    # Workspace component the workflow points at — name comes from here.
    components = [{"id": "comp_abc", "name": "service-from-existing-workflow"}]
    _stub_client(
        monkeypatch,
        products=[{"id": "p1", "name": "demo"}],
        components=components,
    )

    # Plant a pre-existing tag-strategy workflow on disk before the wizard
    # gathers state.
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "sbomify-svc.yml").write_text(
        textwrap.dedent(
            """
            name: sbomify - svc
            on:
              push:
                branches: [main]
                tags: ['v*']
              workflow_dispatch:
            jobs:
              sbom:
                runs-on: ubuntu-latest
                steps:
                  - uses: sbomify/sbomify-action@master
                    env:
                      COMPONENT_ID: comp_abc
                      LOCK_FILE: uv.lock
                      AUGMENT: 'false'
            """
        ).lstrip()
    )

    app = WizardApp(_opts(tmp_path, dry_run=True))
    async with app.run_test() as pilot:
        await pilot.pause()
        # Detection ran at App construction time.
        assert len(app.state.existing_workflows) == 1
        await pilot.press("enter")  # welcome → discover
        await pilot.pause()
        await pilot.press("enter")  # discover → authenticate
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        await pilot.press("enter")  # product → configure
        await pilot.pause()

        # Name is pre-filled from the workspace component (lookup by ID),
        # not from the lockfile's suggested name.
        name_input = app.screen.query_one("#name", Input)
        assert name_input.value == "service-from-existing-workflow"
        # Release strategy radio reflects the workflow's `tags: ['v*']` trigger.
        assert app.screen.query_one("#rel-tag", RadioButton).value is True
        assert app.screen.query_one("#rel-latest", RadioButton).value is False
        # AUGMENT='false' in the workflow → "Skip metadata" wins.
        assert app.screen.query_one("#aug-skip", RadioButton).value is True


@pytest.mark.asyncio
async def test_full_dry_run_lands_on_done(tmp_path, monkeypatch):
    """Walk the entire happy path end-to-end in dry-run mode."""
    lockfile = DiscoveredLockfile(
        path=tmp_path / "uv.lock",
        rel_path=Path("uv.lock"),
        ecosystem="python",
        suggested_name="my-svc",
    )
    _stub_discovery(monkeypatch, [lockfile])
    _stub_client(monkeypatch, products=[{"id": "p1", "name": "demo"}])

    app = WizardApp(_opts(tmp_path, dry_run=True))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")  # welcome → discover
        await pilot.pause()
        await pilot.press("enter")  # discover → authenticate
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        # ProductScreen: defaults to existing product radio, hit enter.
        await pilot.press("enter")
        await pilot.pause()
        # ConfigureScreen: skip augmentation, default release strategy, hit enter.
        await pilot.press("enter")
        await pilot.pause()
        # ReviewScreen: apply (dry-run lands directly on DoneScreen).
        await pilot.press("enter")
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.done import DoneScreen

        assert isinstance(app.screen, DoneScreen)
        # Plan was committed.
        assert len(app.state.plan.create_components) == 1
        assert app.state.plan.create_components[0].name == "my-svc"
