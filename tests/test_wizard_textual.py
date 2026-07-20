"""Smoke tests for the Textual wizard via App.run_test().

These tests confirm screens compose without exceptions and that state
advances correctly between phases. Per-screen styling / rendering is
verified by maintainers manually — Pilot is not the right tool for
visual fidelity checks.
"""

from __future__ import annotations

import json
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
    # Stub list_workspaces too — the auth worker calls it first to
    # derive team_key, which then scopes list_contact_profiles. Without
    # a real list here, the worker can't find a team key and the
    # contact-profiles prefetch is skipped (returns []), which would
    # make the augmentation profile radio appear disabled in tests.
    workspaces = kwargs.get("workspaces") or [{"key": "acme", "name": "Acme Inc"}]

    instance = MagicMock()
    instance.whoami.return_value = None
    instance.list_workspaces.return_value = workspaces
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


async def test_configure_sbomify_json_prefills_from_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P1: when the repo already ships a sbomify.json, the Configure
    (sbomify.json) form seeds itself from that file instead of opening blank."""
    from textual.widgets import Input, RadioSet

    from sbomify_action.cli.wizard.screens.configure_sbomify_json import ConfigureSbomifyJsonScreen

    _stub_discovery(monkeypatch, [])
    (tmp_path / "sbomify.json").write_text(
        json.dumps(
            {
                "supplier": {
                    "name": "Lithium Project",
                    "url": ["https://example.com"],
                    "contacts": [{"name": "Lithium Project", "email": "sec@example.com"}],
                },
                "authors": [{"name": "Rana", "email": "rana@example.com"}],
                "security_contact": "https://example.com/security",
                "lifecycle_phase": "build",
                "licenses": ["MIT"],  # a field the form doesn't render — must not crash prefill
            }
        ),
        encoding="utf-8",
    )

    # WizardApp.__init__ runs gather_repo_facts → has_sbomify_json=True.
    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(120, 60)) as pilot:
        assert app.state.facts.has_sbomify_json is True
        await app.push_screen(ConfigureSbomifyJsonScreen())
        await pilot.pause()

        screen = app.screen
        assert isinstance(screen, ConfigureSbomifyJsonScreen)
        assert screen.query_one("#sup-name", Input).value == "Lithium Project"
        assert screen.query_one("#sup-url", Input).value == "https://example.com"
        assert screen.query_one("#sup-email", Input).value == "sec@example.com"
        assert screen.query_one("#author-name", Input).value == "Rana"
        assert screen.query_one("#author-email", Input).value == "rana@example.com"
        assert screen.query_one("#security-contact", Input).value == "https://example.com/security"
        # The lifecycle RadioSet branch of _populate_from is exercised too:
        # the on-disk "build" phase must be the pressed radio.
        pressed = screen.query_one("#lifecycle", RadioSet).pressed_button
        assert pressed is not None and pressed.id == "phase-build"


async def test_configure_sbomify_json_tolerates_unreadable_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P1 robustness: a malformed / non-object sbomify.json must NOT crash the
    Configure form — _load_from_disk returns None and the form opens blank."""
    from textual.widgets import Input

    from sbomify_action.cli.wizard.screens.configure_sbomify_json import ConfigureSbomifyJsonScreen

    for bad_content in ("this is not json", "[1, 2, 3]"):  # malformed, then a JSON array (non-dict)
        _stub_discovery(monkeypatch, [])
        (tmp_path / "sbomify.json").write_text(bad_content, encoding="utf-8")

        app = WizardApp(_opts(tmp_path))
        async with app.run_test(size=(120, 60)) as pilot:
            assert app.state.facts.has_sbomify_json is True  # the (bad) file exists
            await app.push_screen(ConfigureSbomifyJsonScreen())
            await pilot.pause()

            screen = app.screen
            assert isinstance(screen, ConfigureSbomifyJsonScreen)
            # No crash, and nothing got pre-filled from the unreadable file.
            assert screen.query_one("#sup-name", Input).value == ""


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


async def test_discover_deselects_nested_repo_lockfiles_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Submodule / vendored-repo lockfiles are annotated and start
    deselected — they belong to another repository and should get their
    own SBOM setup there."""
    from textual.widgets import SelectionList

    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        ),
        DiscoveredLockfile(
            path=tmp_path / "extern" / "lib" / "Cargo.lock",
            rel_path=Path("extern") / "lib" / "Cargo.lock",
            ecosystem="rust",
            suggested_name="widget-rust",
            nested_repo="extern/lib",
            nested_repo_kind="submodule",
        ),
    ]
    _stub_discovery(monkeypatch, lockfiles)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.press("enter")  # welcome → discover
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        assert isinstance(app.screen, DiscoverScreen)
        sel = app.screen.query_one("#lockfile-list", SelectionList)
        # Only the top-level lockfile is pre-selected.
        assert list(sel.selected) == [0]
        # The submodule row carries the annotation, and the explanatory
        # note is present.
        labels = [str(sel.get_option_at_index(i).prompt) for i in range(sel.option_count)]
        assert any("submodule: extern/lib" in label for label in labels)
        app.screen.query_one("#nested-repo-note")


async def test_enter_on_focused_radio_set_toggles_radio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: Enter while a RadioSet has focus must commit the
    highlighted radio (not skip past the whole screen).

    Hitting this on the augmentation RadioSet was the symptom that
    exposed the priority-Enter bug: pressing Enter to pick 'Use a
    contact profile' advanced the screen without ever changing the
    radio, so the inline profile picker never appeared. ``route_enter``
    on ``WizardScreen`` now detects RadioSet focus and toggles the
    highlighted button instead of forwarding.

    Also pins the augmentation defaults: the recommended 'Use a contact
    profile' radio is pressed at mount, the picker is visible, and the
    first REAL profile (not the '+ Create new' sentinel) is highlighted.
    """
    from textual.widgets import OptionList, RadioSet

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

        # Defaults: the recommended profile radio is pressed at mount,
        # the picker is visible, and the highlight sits on the first
        # REAL profile — index 0 is the "+ Create new" sentinel.
        aug = app.screen.query_one("#augmentation", RadioSet)
        pressed = aug.pressed_button
        assert pressed is not None and pressed.id == "aug-profile", (
            f"Recommended aug-profile must be the default, got {pressed.id if pressed else None}"
        )
        picker = app.screen.query_one("#profile-picker", OptionList)
        assert picker.display is True, "Profile picker must be visible for the default profile radio"
        assert picker.highlighted == 1, "First REAL profile must be highlighted by default, not the sentinel"
        # Picker shows the two stub profiles plus the "+ Create new"
        # sentinel row that hands off to CreateProfileScreen.
        assert picker.option_count == 3

        # Focus the augmentation RadioSet; arrow down twice to highlight
        # the Skip radio; press Enter to commit. Without route_enter's
        # RadioSet branch this advances to Review instead of toggling.
        # RadioSet's own bindings consume Down (move) while the screen's
        # Enter binding falls through via route_enter.
        aug.focus()
        await pilot.pause()
        await pilot.press("down")  # -> aug-json_config
        await pilot.pause()
        await pilot.press("down")  # -> aug-skip
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        assert isinstance(app.screen, ConfigureSbomScreen), (
            "Enter on focused RadioSet must NOT advance — should toggle radio"
        )
        pressed = aug.pressed_button
        assert pressed is not None and pressed.id == "aug-skip", (
            f"Expected aug-skip after down+down+enter, got {pressed.id if pressed else None}"
        )
        assert picker.display is False, "Profile picker must hide when Skip is selected"

        # Arrow back up to the profile radio — the picker reappears.
        await pilot.press("up")
        await pilot.pause()
        await pilot.press("up")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        pressed = aug.pressed_button
        assert pressed is not None and pressed.id == "aug-profile"
        assert picker.display is True, "Profile picker must reappear after re-selecting profile radio"


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


async def test_components_picker_lists_existing_alphabetically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing components render alphabetically (case-insensitive) in the
    picker regardless of the order the API returned them in."""
    from textual.widgets import OptionList

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
        components=[
            {"id": "c-zeta", "name": "zeta"},
            {"id": "c-alpha", "name": "Alpha"},
            {"id": "c-mid", "name": "midway"},
        ],
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()
        await pilot.press("space")  # select lockfile
        await pilot.pause()
        await pilot.press("enter")  # Discover -> Authenticate (auto-auth)
        await pilot.pause(1.0)  # wait for auth + auto-push to Product
        await pilot.press("enter")  # Product -> Components
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.components import ComponentsScreen
        from sbomify_action.cli.wizard.widgets import NEW_SENTINEL

        assert isinstance(app.screen, ComponentsScreen)
        picker = app.screen.query_one("#component-0-list", OptionList)
        option_ids = [picker.get_option_at_index(i).id for i in range(picker.option_count)]
        assert option_ids == [NEW_SENTINEL, "c-alpha", "c-mid", "c-zeta"]


async def test_product_picker_lists_existing_alphabetically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing products render alphabetically (case-insensitive) in the
    picker regardless of the order the API returned them in, and the
    pre-selected product is the first visible row."""
    from textual.widgets import OptionList

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
        products=[
            {"id": "p-zeta", "name": "zeta"},
            {"id": "p-alpha", "name": "Alpha"},
            {"id": "p-mid", "name": "midway"},
        ],
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()
        await pilot.press("space")  # select lockfile
        await pilot.pause()
        await pilot.press("enter")  # Discover -> Authenticate (auto-auth)
        await pilot.pause(1.0)  # wait for auth + auto-push to Product

        from sbomify_action.cli.wizard.screens.product import ProductScreen
        from sbomify_action.cli.wizard.widgets import NEW_SENTINEL, PickOrCreate

        assert isinstance(app.screen, ProductScreen)
        picker = app.screen.query_one("#product-picker-list", OptionList)
        option_ids = [picker.get_option_at_index(i).id for i in range(picker.option_count)]
        assert option_ids == [NEW_SENTINEL, "p-alpha", "p-mid", "p-zeta"]
        # Pre-selection tracks the sorted order: the alphabetically first
        # product, not whichever the API happened to return first.
        assert app.screen.query_one("#product-picker", PickOrCreate).picked_id == "p-alpha"


async def test_enter_on_create_profile_sentinel_pushes_create_screen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: highlighting the '+ Create new' sentinel on the
    profile picker and pressing Enter must push CreateProfileScreen,
    not advance to Review.

    The screen's priority Enter binding consumes the keystroke before
    Textual fires OptionList.OptionSelected, so the sentinel detection
    happens in _advance via _picker_sentinel_highlighted — this test
    pins that path.
    """
    from textual.widgets import Button, OptionList, RadioSet

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
        profiles=[{"id": "cp1", "name": "Acme Engineering"}],
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(120, 60)) as pilot:
        # Walk to ConfigureSbom.
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()
        await pilot.press("space")
        await pilot.pause()
        await pilot.press("enter")  # Discover -> Auth (auto-auth)
        await pilot.pause(1.0)
        await pilot.press("enter")  # Product -> Components
        await pilot.pause()
        await pilot.press("enter")  # Components -> ConfigureWorkflow
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.configure_workflow import (
            ConfigureWorkflowScreen,
        )

        assert isinstance(app.screen, ConfigureWorkflowScreen)
        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")  # ConfigureWorkflow -> ConfigureSbom
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen
        from sbomify_action.cli.wizard.screens.create_profile import CreateProfileScreen

        assert isinstance(app.screen, ConfigureSbomScreen)

        # "Use a contact profile" is the default radio, so the picker
        # is already visible; highlight the + Create new sentinel
        # (index 0) and press Enter.
        aug = app.screen.query_one("#augmentation", RadioSet)
        assert aug.pressed_button is not None and aug.pressed_button.id == "aug-profile"
        picker = app.screen.query_one("#profile-picker", OptionList)
        assert picker.display is True
        picker.highlighted = 0  # + Create new sentinel
        await pilot.pause()
        # Move focus to the Next button so route_enter advances via _advance
        # rather than letting OptionList's own Enter handler fire.
        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        assert isinstance(app.screen, CreateProfileScreen), (
            "Enter with the + Create new sentinel highlighted must push CreateProfileScreen, not advance to Review"
        )


async def test_augmentation_default_with_no_profiles_bootstraps_create_and_cancel_reverts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With zero workspace profiles, the default recommended 'profile'
    strategy highlights the '+ Create new' sentinel, so Enter routes to
    CreateProfileScreen (the bootstrap path). Cancelling that form must
    revert augmentation to Skip — otherwise the screen's own defaults
    put the user in an Enter→Escape→Enter loop.
    """
    from textual.widgets import Button, OptionList, RadioSet

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
        profiles=[],
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(120, 60)) as pilot:
        # Walk to ConfigureSbom.
        await pilot.press("enter")  # Welcome -> Discover
        await pilot.pause()
        await pilot.press("space")
        await pilot.pause()
        await pilot.press("enter")  # Discover -> Auth (auto-auth)
        await pilot.pause(1.0)
        await pilot.press("enter")  # Product -> Components
        await pilot.pause()
        await pilot.press("enter")  # Components -> ConfigureWorkflow
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.configure_workflow import (
            ConfigureWorkflowScreen,
        )

        assert isinstance(app.screen, ConfigureWorkflowScreen)
        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")  # ConfigureWorkflow -> ConfigureSbom
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen
        from sbomify_action.cli.wizard.screens.create_profile import CreateProfileScreen

        assert isinstance(app.screen, ConfigureSbomScreen)
        configure_screen = app.screen
        picker = configure_screen.query_one("#profile-picker", OptionList)
        # Zero profiles: only the sentinel row exists, and it's highlighted.
        assert picker.option_count == 1
        assert picker.highlighted == 0

        # Advance — the sentinel routes to CreateProfileScreen.
        configure_screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, CreateProfileScreen)

        # Cancel the form — back on ConfigureSbom, augmentation must
        # have reverted to Skip so Enter doesn't re-push the form.
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is configure_screen
        pressed = configure_screen.query_one("#augmentation", RadioSet).pressed_button
        assert pressed is not None and pressed.id == "aug-skip", (
            f"Cancelled CreateProfile must revert augmentation to Skip, got {pressed.id if pressed else None}"
        )
        assert picker.display is False


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
