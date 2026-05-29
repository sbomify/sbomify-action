"""Smoke tests for the Textual wizard via App.run_test().

These tests confirm screens compose without exceptions and that state
advances correctly between phases. Per-screen styling / rendering is
verified by maintainers manually — Pilot is not the right tool for
visual fidelity checks.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard.app import WizardApp
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import DiscoveredLockfile


def _opts(tmp_path: Path, *, dry_run: bool = True) -> WizardOptions:
    return WizardOptions(
        token="t-fake",
        api_base_url="https://app.sbomify.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=dry_run,
    )


def _stub_discovery(monkeypatch: pytest.MonkeyPatch, lockfiles: list[DiscoveredLockfile]) -> None:
    """Replace lockfile discovery so each test owns the lockfile set."""
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.app.discovery.discover",
        lambda _root, repo_name=None: lockfiles,
    )


def _stub_client(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> MagicMock:
    """Replace SbomifyApiClient at the authenticate screen's import site."""
    products = kwargs.get("products") or []
    components = kwargs.get("components") or []
    profiles = kwargs.get("profiles") or []
    # Stub list_teams too — the auth worker calls it first to derive
    # team_key, which then scopes list_contact_profiles. Without a
    # real list here, the worker can't find a team key and the
    # contact-profiles prefetch is skipped (returns []), which would
    # make the augmentation profile radio appear disabled in tests.
    teams = kwargs.get("teams") or [{"key": "acme", "name": "Acme Inc"}]

    instance = MagicMock()
    instance.whoami.return_value = None
    instance.list_teams.return_value = teams
    instance.list_products.return_value = products
    instance.list_components.return_value = components
    instance.list_contact_profiles.return_value = profiles

    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.authenticate.SbomifyApiClient",
        lambda *args, **kwargs: instance,
    )
    return instance


async def test_app_starts_and_renders_welcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_discovery(monkeypatch, [])

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        # Welcome should be on the stack.
        from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

        assert isinstance(app.screen, WelcomeScreen)
        await pilot.pause()


async def test_escape_from_authenticate_returns_to_discover(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the password Input on AuthenticateScreen must not eat
    Escape. Without priority=True on the screen's Escape binding the
    user gets stuck with no way back to Discover."""
    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        )
    ]
    _stub_discovery(monkeypatch, lockfiles)

    # No token in opts so authenticate doesn't auto-start the worker.
    opts = WizardOptions(
        token=None,
        api_base_url="https://app.sbomify.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=True,
    )
    app = WizardApp(opts)
    async with app.run_test() as pilot:
        await pilot.press("enter")  # welcome → discover
        await pilot.pause()
        await pilot.press("enter")  # discover → authenticate
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen
        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        assert isinstance(app.screen, AuthenticateScreen)
        # Escape with the password Input focused — must still go back.
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, DiscoverScreen)


async def test_welcome_to_discover_navigates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        )
    ]
    _stub_discovery(monkeypatch, lockfiles)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.press("enter")
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        assert isinstance(app.screen, DiscoverScreen)
        assert len(app.state.discovered) == 1


async def test_enter_on_focused_radio_set_toggles_radio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: Enter while a RadioSet has focus must commit the
    highlighted radio (not skip past the whole screen).

    Hitting this on the augmentation RadioSet was the symptom that
    exposed the priority-Enter bug: pressing Enter to pick 'Use a
    contact profile' advanced the screen without ever changing the
    radio, so the inline profile picker never appeared. ``route_enter``
    on ``WizardScreen`` now detects RadioSet focus and toggles the
    highlighted button instead of forwarding.
    """
    from textual.widgets import OptionList, RadioButton, RadioSet

    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        )
    ]
    _stub_discovery(monkeypatch, lockfiles)
    _stub_client(
        monkeypatch,
        products=[{"id": "p1", "name": "alpha"}],
        components=[{"id": "c1", "name": "widget-py"}],
        profiles=[
            {"id": "cp1", "name": "Acme Engineering"},
            {"id": "cp2", "name": "Acme Security"},
        ],
    )

    from textual.widgets import Button

    app = WizardApp(_opts(tmp_path))
    # Larger viewport so the augmentation panel + profile picker + Next
    # button all render — Textual focus/visibility behaviour can shift
    # when widgets are clipped on tiny pilot terminals.
    async with app.run_test(size=(120, 60)) as pilot:
        # Walk to ConfigureSbom (where Augmentation now lives — moved
        # off ConfigureWorkflow so Enrichment + Augmentation, both
        # metadata-source controls, sit together).
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()
        await pilot.press("space")  # select lockfile
        await pilot.pause()
        await pilot.press("enter")  # Discover -> Authenticate (auto-auth)
        await pilot.pause(1.0)
        await pilot.press("enter")  # Product -> Components
        await pilot.pause()
        await pilot.press("enter")  # Components -> ConfigureWorkflow
        await pilot.pause()

        # ConfigureWorkflow auto-focuses the release RadioSet, so Enter
        # would toggle the highlighted radio (the right UX for picking)
        # instead of advancing. Focus the Next button to advance.
        from sbomify_action.cli.wizard.screens.configure_workflow import (
            ConfigureWorkflowScreen,
        )

        assert isinstance(app.screen, ConfigureWorkflowScreen)
        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")  # ConfigureWorkflow -> ConfigureSbom
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen

        assert isinstance(app.screen, ConfigureSbomScreen)

        # Focus the augmentation RadioSet; arrow down to highlight the
        # profile radio; press Enter to commit. Without route_enter's
        # RadioSet branch this advances to Review and the profile
        # picker never becomes visible. RadioSet's own bindings consume
        # Down (move) and Enter (commit highlighted) while the screen's
        # Enter binding falls through via route_enter.
        aug = app.screen.query_one("#augmentation", RadioSet)
        aug.focus()
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        # Drop the unused RadioButton import warning by referencing it.
        _ = RadioButton

        assert isinstance(app.screen, ConfigureSbomScreen), (
            "Enter on focused RadioSet must NOT advance — should toggle radio"
        )
        pressed = aug.pressed_button
        assert pressed is not None and pressed.id == "aug-profile", (
            f"Expected aug-profile after down+enter, got {pressed.id if pressed else None}"
        )

        picker = app.screen.query_one("#profile-picker", OptionList)
        assert picker.display is True, "Profile picker must appear after selecting profile radio"
        assert picker.option_count == 2


async def test_escape_from_components_goes_back_in_any_focus_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: Escape from ComponentsScreen pops back to Product no
    matter which inner widget has focus.

    The Components screen mounts one PickOrCreate per lockfile; depending
    on auto-match the user may be focused on the OptionList (existing
    picked) or the "Create new" Input (no auto-match). Both paths must
    honour the screen's Escape binding so Back navigation isn't trapped
    by whichever widget happened to take focus.
    """
    from textual.widgets import Input, OptionList

    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        )
    ]
    _stub_discovery(monkeypatch, lockfiles)
    # No matching component → Input visible, "Create new" sentinel
    # highlighted; this exercises the trickier focus path where Input
    # could in theory swallow Escape.
    _stub_client(
        monkeypatch,
        products=[{"id": "p1", "name": "alpha"}],
        components=[{"id": "c1", "name": "OtherProject"}],
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        # Walk to Components. Auto-auth (token preset on opts) pushes
        # ProductScreen automatically after the workspace prefetch
        # completes, so we DON'T press Enter at Authenticate.
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()
        await pilot.press("space")  # select lockfile
        await pilot.pause()
        await pilot.press("enter")  # Discover -> Authenticate (auto-auth)
        await pilot.pause(1.0)  # wait for auth + auto-push to Product
        await pilot.press("enter")  # Product -> Components
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.components import ComponentsScreen
        from sbomify_action.cli.wizard.screens.product import ProductScreen

        assert isinstance(app.screen, ComponentsScreen)

        # Case 1: focus on OptionList → escape pops back to Product.
        app.screen.query_one("#component-0-list", OptionList).focus()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, ProductScreen), "Escape on OptionList must pop to Product"

        # Forward to Components again, focus the Input this time.
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ComponentsScreen)
        app.screen.query_one("#component-0-input", Input).focus()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, ProductScreen), "Escape on Input must pop to Product"


async def test_enter_on_focused_back_button_goes_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: pressing Enter while the Back button is focused must
    pop the screen, not trigger the screen's forward ``action_submit``.

    The screen-level Enter binding is ``priority=True`` so Input fields
    can't swallow it (eg the token Input on AuthenticateScreen).
    Without explicit routing, that priority also wins when the user
    has Tabbed over to a non-primary button — pressing Enter on the
    focused Back button would jump forward instead of back. Every
    screen's ``action_submit`` / ``action_apply`` defers to
    ``WizardScreen.route_enter`` to fix this.
    """
    from textual.widgets import Button

    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        )
    ]
    _stub_discovery(monkeypatch, lockfiles)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen
        from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

        assert isinstance(app.screen, DiscoverScreen)

        # Walk focus until the Back button is focused.
        for _ in range(8):
            focused = app.focused
            if isinstance(focused, Button) and focused.id == "back":
                break
            await pilot.press("shift+tab")
            await pilot.pause()
        else:
            raise AssertionError("never focused the Back button via shift+tab")

        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, WelcomeScreen), (
            "Enter on focused Back button must pop the screen, not advance forward"
        )
