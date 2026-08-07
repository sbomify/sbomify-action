"""Layout / responsive regression tests for the Textual wizard.

The wizard is driven entirely by keyboard, and its action row (Back /
Next / Apply) is the only way forward on every screen. Before the
scrolling-body refactor, several screens rendered that row *below* the
bottom of the terminal at common sizes — Configure (SBOM) did it at
80x24, the out-of-the-box default of xterm, gnome-terminal,
Terminal.app, Konsole and Alacritty — leaving the user with no visible
way to continue. Nothing in the suite noticed, because every existing
test asserts on widget state rather than on where widgets land.

These tests close that gap: they walk the real screens at a matrix of
real terminal sizes and assert the action row is inside the viewport.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from textual.widgets import Button

from sbomify_action.cli.wizard.app import WizardApp
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import DiscoveredLockfile

# Real defaults, not round numbers:
#   80x24  — xterm, gnome-terminal/VTE, Terminal.app, Konsole, Alacritty
#   80x25  — iTerm2 / DOS heritage
#   96x26  — Ghostty (sizes by pixels, so this varies with font size)
#  120x30  — Windows Terminal / a small tmux pane
#  200x20  — an IDE's integrated terminal panel: wide and short
#  160x48  — maximized on a 14" laptop
#  100x63  — the ROOMY breakpoint's lower bound
SIZES = [(80, 24), (80, 25), (96, 26), (120, 30), (200, 20), (160, 48), (100, 63)]

_LOCKFILE_SPECS = [
    ("uv.lock", "python", "widget-py"),
    ("frontend/package-lock.json", "javascript", "widget-frontend"),
    ("services/api/go.sum", "go", "widget-api"),
    ("Cargo.lock", "rust", "widget-rust"),
]


def _lockfiles(root: Path, count: int) -> list[DiscoveredLockfile]:
    return [
        DiscoveredLockfile(path=root / rel, rel_path=Path(rel), ecosystem=eco, suggested_name=name)
        for rel, eco, name in _LOCKFILE_SPECS[:count]
    ]


def _stub_wizard(monkeypatch: pytest.MonkeyPatch, root: Path, count: int) -> None:
    """Point discovery at a fixed lockfile set and stub the API client."""
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.app.discovery.discover",
        lambda _root, repo_name=None: _lockfiles(root, count),
    )
    client = MagicMock()
    client.whoami.return_value = None
    client.list_workspaces.return_value = [{"key": "acme", "name": "Acme Inc"}]
    client.list_products.return_value = [{"id": "p1", "name": "Acme Platform"}]
    client.list_components.return_value = [{"id": "c1", "name": "widget-py"}]
    client.list_contact_profiles.return_value = [{"id": "cp1", "name": "Acme Engineering"}]
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.authenticate.SbomifyApiClient",
        lambda *args, **kwargs: client,
    )


def _opts(root: Path) -> WizardOptions:
    return WizardOptions(
        token="t-fake",
        api_base_url="https://app.sbomify.test",
        repo_root=root,
        output_dir=root / ".github" / "workflows",
        dry_run=True,
    )


def _offscreen_buttons(screen) -> list[str]:  # noqa: ANN001
    """IDs of action buttons that render outside the visible viewport."""
    height = screen.size.height
    offscreen: list[str] = []
    for button in screen.query(Button):
        geometry = screen._compositor.full_map.get(button)
        region = geometry.region if geometry else None
        if region is None or region.bottom > height or region.height == 0:
            offscreen.append(button.id or button.__class__.__name__)
    return offscreen


@pytest.mark.parametrize(("width", "height"), SIZES)
@pytest.mark.parametrize("lockfile_count", [1, 3])
async def test_action_row_stays_on_screen_through_the_whole_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    width: int,
    height: int,
    lockfile_count: int,
) -> None:
    """Every screen keeps its Back/Next row inside the viewport.

    Cold-started at each size (no resize), because that's what a user
    actually gets: the terminal is already 80x24 when the wizard launches.
    """
    _stub_wizard(monkeypatch, tmp_path, lockfile_count)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()

        async def check(label: str) -> None:
            missing = _offscreen_buttons(app.screen)
            assert not missing, f"{label} at {width}x{height} ({lockfile_count} lockfiles): {missing} off-screen"

        await check("Welcome")
        await pilot.press("enter")
        await pilot.pause()
        await check("Discover")

        await pilot.press("a")  # select all lockfiles
        await pilot.pause()
        await pilot.press("enter")  # -> Authenticate, which auto-advances to Product
        await pilot.pause(1.0)
        await check("Product")

        await pilot.press("enter")
        await pilot.pause()
        await check("Components")

        await pilot.press("enter")
        await pilot.pause()
        await check("Configure (workflow)")

        # This screen focuses a RadioSet on mount, where Enter toggles the
        # radio rather than advancing — press Next directly.
        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await check("Configure (SBOM)")

        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await check("Review")


@pytest.mark.parametrize(("width", "height"), [(80, 24), (200, 20), (160, 48)])
async def test_body_scrolls_rather_than_clipping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, width: int, height: int
) -> None:
    """Overflowing content is reachable by scrolling, not silently cut.

    Configure (SBOM) is the tallest screen in the wizard; on a short
    terminal its scroll region must actually be scrollable rather than
    clipping the attestation radio out of existence.
    """
    from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen

    _stub_wizard(monkeypatch, tmp_path, 1)
    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause(1.0)
        await pilot.press("enter")  # -> Components
        await pilot.pause()
        await pilot.press("enter")  # -> Configure (workflow)
        await pilot.pause()
        app.screen.query_one("#next", Button).focus()
        await pilot.pause()
        await pilot.press("enter")  # -> Configure (SBOM)
        await pilot.pause()

        assert isinstance(app.screen, ConfigureSbomScreen)
        scroll = app.screen.query_one(".wizard-scroll")
        # Either everything fits, or the region can scroll to reach the rest.
        # What must never happen is content taller than the region with no
        # way to reach it.
        if scroll.virtual_size.height > scroll.size.height:
            assert scroll.allow_vertical_scroll, "overflowing body must be scrollable, not clipped"


async def test_too_small_guard_only_fires_below_the_supported_minimum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resize prompt is a genuine floor, not a refusal to render.

    An IDE terminal panel is wide but short; before the scrolling body it
    was rejected outright at 200x20 despite having ample room.
    """
    from sbomify_action.cli.wizard.screens._base import MIN_HEIGHT, MIN_WIDTH

    _stub_wizard(monkeypatch, tmp_path, 1)

    for (width, height), expected_tiny in [
        ((200, 20), False),
        ((120, 15), False),
        ((MIN_WIDTH, MIN_HEIGHT), False),
        ((MIN_WIDTH - 1, MIN_HEIGHT), True),
        ((MIN_WIDTH, MIN_HEIGHT - 1), True),
    ]:
        app = WizardApp(_opts(tmp_path))
        async with app.run_test(size=(width, height)) as pilot:
            await pilot.pause()
            assert app.screen.has_class("-tiny") is expected_tiny, (
                f"{width}x{height} should {'' if expected_tiny else 'not '}show the resize prompt"
            )


@pytest.mark.parametrize(("width", "height"), [(80, 24), (80, 25), (120, 30), (160, 48)])
async def test_help_modal_always_shows_how_to_close_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, width: int, height: int
) -> None:
    """The dismiss hint is pinned, not the last line of a clipped card.

    The help card sized itself to its content, so on a terminal shorter
    than the cheat sheet it overflowed and the bottom — the only place
    that says how to close it — was cut off.
    """
    from textual.widgets import Static

    _stub_wizard(monkeypatch, tmp_path, 1)
    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.help import HelpScreen

        assert isinstance(app.screen, HelpScreen)
        dismiss = app.screen.query_one("#help-dismiss", Static)
        geometry = app.screen._compositor.full_map.get(dismiss)
        assert geometry is not None, "dismiss hint is not rendered at all"
        assert geometry.region.bottom <= height, f"dismiss hint runs past the bottom of a {width}x{height} terminal"

        # And Escape still closes it.
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpScreen)


def test_mascot_renders_without_leaking_markup() -> None:
    """The ASCII art survives both markup dialects.

    The hat is drawn with backslashes, and a backslash adjacent to a tag
    is an escape character — as hand-written markup the top two rows
    rendered as ``/[/]`` (right edge eaten, closing tag printed as text).
    The art is now a styled Text, so there's no markup to mis-parse.
    """
    from textual.content import Content

    from sbomify_action.cli.wizard.screens.welcome import ASCII_WIZARD

    rows = ASCII_WIZARD.plain.split("\n")
    assert "[/]" not in ASCII_WIZARD.plain, "closing tag leaked into the rendered art"
    # Both sides of the hat are present on every hat row.
    assert rows[1].strip() == "/\\"
    assert rows[2].strip() == "/  \\"
    # The brim (with the staff trailing it further right on this row).
    assert rows[8].strip().startswith("/______________\\")
    # And the staff lines up in a single column on every row that has one.
    staff_rows = [row for row in rows if row.rstrip().endswith("|")]
    assert staff_rows, "expected the wizard to be holding a staff"
    assert len({len(row.rstrip()) for row in staff_rows}) == 1, "staff column is ragged"
    # Textual's parser must not find anything to interpret either.
    assert Content.from_markup(ASCII_WIZARD.plain).plain == ASCII_WIZARD.plain


def test_progress_crumb_numbering_is_unique_and_ordered() -> None:
    """Each phase advances the crumb; the final phases don't all read 08/08.

    Review, Apply and Done previously shared ``step_index = 8``, so the
    progress track showed every dot filled — "finished" — with two screens
    still to go, and the Welcome screen's own "what we'll do" list used a
    different numbering again.
    """
    from sbomify_action.cli.wizard.screens._base import TOTAL_STEPS
    from sbomify_action.cli.wizard.screens.apply import ApplyScreen
    from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen
    from sbomify_action.cli.wizard.screens.components import ComponentsScreen
    from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen
    from sbomify_action.cli.wizard.screens.configure_workflow import ConfigureWorkflowScreen
    from sbomify_action.cli.wizard.screens.discover import DiscoverScreen
    from sbomify_action.cli.wizard.screens.done import DoneScreen
    from sbomify_action.cli.wizard.screens.product import ProductScreen
    from sbomify_action.cli.wizard.screens.review import ReviewScreen
    from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

    flow = [
        WelcomeScreen,
        DiscoverScreen,
        AuthenticateScreen,
        ProductScreen,
        ComponentsScreen,
        ConfigureWorkflowScreen,
        ConfigureSbomScreen,
        ReviewScreen,
        ApplyScreen,
    ]
    assert [screen.step_index for screen in flow] == list(range(1, TOTAL_STEPS + 1))
    # Done reports the same (final) step Apply performed, rather than
    # inventing a tenth.
    assert DoneScreen.step_index == TOTAL_STEPS


def test_welcome_step_list_matches_the_crumb_numbering() -> None:
    """The "what we'll do" preview and the progress crumb agree."""
    from sbomify_action.cli.wizard.screens._base import TOTAL_STEPS
    from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

    numbers = [line.split("]")[1].split("[")[0] for line in WelcomeScreen._steps_list(None)]  # type: ignore[arg-type]
    # Welcome itself is 01, so the work ahead runs 02..TOTAL_STEPS.
    assert numbers == [f"{n:02d}" for n in range(2, TOTAL_STEPS + 1)]


def test_ellipsize_truncates_rather_than_wrapping() -> None:
    from sbomify_action.cli.wizard.screens._base import ellipsize

    assert ellipsize("short", 10) == "short"
    assert ellipsize("exactlyten", 10) == "exactlyten"
    assert ellipsize("a-very-long-product-name", 10) == "a-very-lo…"
    assert len(ellipsize("a-very-long-product-name", 10)) == 10
    # Degenerate limits are returned untouched rather than mangled.
    assert ellipsize("abc", 1) == "abc"
