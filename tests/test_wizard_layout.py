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


async def _advance(pilot, button_id: str = "next", wait: float = 0.0) -> None:
    """Press a screen's primary button directly.

    Navigation by Enter is focus-sensitive (``route_enter``), so tests that
    move focus around can't also use Enter to advance without accidentally
    pressing whatever they happened to land on.
    """
    pilot.app.screen.query_one(f"#{button_id}", Button).press()
    await pilot.pause(wait) if wait else await pilot.pause()


async def _walk_to_configure_sbom(pilot) -> None:  # noqa: ANN001
    """Drive the flow as far as the tallest screen in the wizard."""
    from textual.widgets import SelectionList

    await _advance(pilot, "start")
    pilot.app.screen.query_one("#lockfile-list", SelectionList).select_all()
    await pilot.pause()
    await _advance(pilot, "next", wait=1.0)  # Authenticate auto-advances to Product
    await _advance(pilot)  # -> Components
    await _advance(pilot)  # -> Configure (workflow)
    await _advance(pilot)  # -> Configure (SBOM)


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


@pytest.mark.parametrize(("width", "height"), [(80, 24), (120, 30), (160, 48)])
@pytest.mark.parametrize("lockfile_count", [1, 3])
async def test_every_screen_opens_at_the_top_of_its_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    width: int,
    height: int,
    lockfile_count: int,
) -> None:
    """A screen never opens already scrolled past its own first panel.

    Review's diff panel takes ``1fr``, and once its min-height pushed the
    body past the viewport the initial layout settled at the *bottom* — so
    the confirmation screen opened with the plan summary (product, release
    strategy, credentials) scrolled off the top, which is exactly what the
    user is on that screen to check. Components did the same from three
    lockfiles up.
    """
    _stub_wizard(monkeypatch, tmp_path, lockfile_count)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()

        def at_top(label: str) -> None:
            offset = app.screen.query_one(".wizard-scroll").scroll_offset.y
            assert offset == 0, f"{label} at {width}x{height} opened scrolled to y={offset}"

        at_top("Welcome")
        await _walk_to_configure_sbom(pilot)
        at_top("Configure (SBOM)")
        await _advance(pilot)
        at_top("Review")
        await _advance(pilot, "apply")
        await app.workers.wait_for_complete()
        await pilot.pause()
        at_top("Apply")
        await _advance(pilot, "continue")
        at_top("Done")


@pytest.mark.parametrize(("width", "height"), [(80, 24), (80, 12), (200, 20), (160, 48)])
async def test_tabbing_never_lands_on_something_invisible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, width: int, height: int
) -> None:
    """Focus stays inside the viewport as the user tabs.

    The scrolling body trades "the control is off-screen" for "the control
    is below the fold", which is only an improvement if tabbing to it
    scrolls it into view. If it doesn't, the focus ring is invisible and
    the user is just as stuck as before.
    """
    _stub_wizard(monkeypatch, tmp_path, 3)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        await _walk_to_configure_sbom(pilot)

        screen = app.screen
        seen: list[str] = []
        for _ in range(25):
            await pilot.press("tab")
            await pilot.pause()
            focused = app.focused
            if focused is None:
                continue
            key = f"{type(focused).__name__}#{focused.id}"
            if key in seen:
                break
            seen.append(key)

            geometry = screen._compositor.full_map.get(focused)
            assert geometry is not None, f"{key} is focused but not composited"
            region = geometry.region
            assert region.height > 0, f"{key} focused with zero height"
            assert region.y >= 0 and region.bottom <= height, (
                f"{key} focused at rows {region.y}..{region.bottom}, outside a {width}x{height} viewport"
            )
            clip = geometry.clip
            assert not (clip.height and (region.y >= clip.bottom or region.bottom <= clip.y)), (
                f"{key} focused but scrolled out of its own container"
            )

        assert len(seen) >= 4, f"expected several tab stops on Configure (SBOM), got {seen}"


async def test_scroll_region_is_only_a_tab_stop_when_it_can_scroll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The body container doesn't add a dead tab stop.

    Textual makes scrollable containers focusable so keyboard users can pan
    text no widget owns — which the wizard needs. But when the content
    already fits there's nothing to pan and no visible focus change, so the
    stop reads as "Tab did nothing".
    """
    from sbomify_action.cli.wizard.screens._base import WizardScroll

    _stub_wizard(monkeypatch, tmp_path, 1)

    # Roomy: Welcome fits, so the body must not be focusable.
    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        scroll = app.screen.query_one(WizardScroll)
        assert not scroll.show_vertical_scrollbar
        assert not scroll.focusable, "body should not be a tab stop when nothing can scroll"

    # Cramped: the same screen overflows, so panning must stay reachable.
    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(80, 12)) as pilot:
        await pilot.pause()
        scroll = app.screen.query_one(WizardScroll)
        assert scroll.show_vertical_scrollbar
        assert scroll.focusable, "body must be a tab stop when there is content to pan"


async def test_wizard_survives_being_resized_across_every_breakpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dragging the window around mid-flow doesn't strand the user.

    Every other test cold-starts at a fixed size. This one sits on the
    tallest screen and crosses each breakpoint in both directions,
    including in and out of the too-small guard.
    """
    from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen
    from sbomify_action.cli.wizard.screens.review import ReviewScreen

    _stub_wizard(monkeypatch, tmp_path, 2)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _walk_to_configure_sbom(pilot)
        assert isinstance(app.screen, ConfigureSbomScreen)

        for width, height in [
            (100, 63),  # roomy
            (80, 24),  # compact
            (60, 11),  # below the floor
            (40, 10),  # far below
            (200, 20),  # IDE panel
            (250, 70),  # ultrawide
            (80, 24),  # back to the default
        ]:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            await pilot.pause()
            if app.screen.has_class("-tiny"):
                continue
            missing = _offscreen_buttons(app.screen)
            assert not missing, f"after resizing to {width}x{height}: {missing} off-screen"

        # Still interactive after the round trip.
        await _advance(pilot)
        assert isinstance(app.screen, ReviewScreen), "Next stopped working after resizing"


async def test_whole_wizard_is_completable_by_keyboard_at_80x24(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end on a default terminal, keyboard only.

    This is the scenario the layout bug actually broke: at 80x24 the user
    could reach Configure (SBOM) and then had no visible way onward.
    """
    _stub_wizard(monkeypatch, tmp_path, 2)

    app = WizardApp(_opts(tmp_path))
    trail: list[str] = []

    async def key(name: str, wait: float = 0.0) -> None:
        await pilot.press(name)
        await pilot.pause(wait) if wait else await pilot.pause()
        current = type(app.screen).__name__
        if not trail or trail[-1] != current:
            trail.append(current)

    async def tab_to(button_id: str) -> None:
        for _ in range(10):
            focused = app.focused
            if focused is not None and getattr(focused, "id", None) == button_id:
                return
            await pilot.press("tab")
            await pilot.pause()
        raise AssertionError(f"could not reach #{button_id} by tabbing on {type(app.screen).__name__}")

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        trail.append(type(app.screen).__name__)
        await key("enter")  # Welcome -> Discover
        await key("a")  # select every lockfile
        await key("enter", 1.0)  # -> Authenticate -> Product
        await key("enter")  # -> Components
        await key("enter")  # -> Configure (workflow)
        # These two screens focus a RadioSet, where Enter commits the radio
        # rather than advancing — the user tabs to Next, so the test does too.
        await tab_to("next")
        await key("enter")  # -> Configure (SBOM)
        await tab_to("next")
        await key("enter")  # -> Review
        await key("enter")  # -> Apply
        await app.workers.wait_for_complete()
        await pilot.pause()
        await key("enter")  # -> Done

    assert trail == [
        "WelcomeScreen",
        "DiscoverScreen",
        "ProductScreen",
        "ComponentsScreen",
        "ConfigureWorkflowScreen",
        "ConfigureSbomScreen",
        "ReviewScreen",
        "ApplyScreen",
        "DoneScreen",
    ], trail


async def test_double_width_and_markup_in_api_names_render_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CJK, emoji and square brackets in workspace names survive the trip.

    Names come from the API, so they can contain anything. Brackets are
    Rich/Textual markup delimiters and CJK glyphs occupy two cells — both
    can corrupt a layout that assumes one cell per character.
    """
    from sbomify_action.cli.wizard.state import DiscoveredLockfile

    monkeypatch.setattr(
        "sbomify_action.cli.wizard.app.discovery.discover",
        lambda _root, repo_name=None: [
            DiscoveredLockfile(
                path=tmp_path / "サービス" / "uv.lock",
                rel_path=Path("サービス/uv.lock"),
                ecosystem="python",
                suggested_name="サービス-py",
            )
        ],
    )
    client = MagicMock()
    client.whoami.return_value = None
    client.list_workspaces.return_value = [{"key": "acme", "name": "Acme Inc"}]
    client.list_products.return_value = [{"id": "p1", "name": "株式会社テスト [内部] 🚀"}]
    client.list_components.return_value = [{"id": "c1", "name": "コンポーネント [beta] 🎉"}]
    client.list_contact_profiles.return_value = [{"id": "cp1", "name": "連絡先 [prod]"}]
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.authenticate.SbomifyApiClient",
        lambda *args, **kwargs: client,
    )

    app = WizardApp(_opts(tmp_path))
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _advance(pilot, "start")
        from textual.widgets import SelectionList

        app.screen.query_one("#lockfile-list", SelectionList).select_all()
        await pilot.pause()
        await _advance(pilot, "next", wait=1.0)

        # The bracketed segment must reach the screen as literal text rather
        # than being parsed away as a markup tag.
        rendered = "\n".join(strip.text for strip in app.screen._compositor.render_strips())
        assert "[内部]" in rendered, "bracketed segment of the product name was eaten by the markup parser"

        await _advance(pilot)  # Components
        await _advance(pilot)  # Configure (workflow)
        await _advance(pilot)  # Configure (SBOM)
        await _advance(pilot)  # Review

        from sbomify_action.cli.wizard.screens.review import ReviewScreen

        assert isinstance(app.screen, ReviewScreen), "non-ASCII names derailed the flow"
        assert not _offscreen_buttons(app.screen)


@pytest.mark.parametrize(("width", "height"), [(80, 24), (80, 12), (160, 48)])
@pytest.mark.parametrize("failure", ["plan-limit", "generic"])
async def test_apply_failure_keeps_the_error_and_the_recovery_on_screen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, width: int, height: int, failure: str
) -> None:
    """A failed apply shows what went wrong and what to do about it.

    The error banner is mounted above the log precisely so it survives the
    log scrolling — but the whole panel now lives in a scroll region, so
    both the banner and the recovery buttons have to be checked for real.
    """
    from unittest.mock import MagicMock as _MagicMock

    from sbomify_action.cli.wizard import apply as apply_mod
    from sbomify_action.cli.wizard.screens.apply import ApplyScreen
    from sbomify_action.cli.wizard.state import WorkspaceSnapshot
    from sbomify_action.exceptions import PlanLimitError

    monkeypatch.setattr(
        "sbomify_action.cli.wizard.app.discovery.discover",
        lambda _root, repo_name=None: [],
    )

    def fake_apply(state, opts, *, log=None):  # noqa: ANN001, ANN202
        # Enough log lines that a naive layout would push the banner away.
        for index in range(15):
            log("info", f"step {index}: preparing something with a reasonably long description")
        if failure == "plan-limit":
            raise PlanLimitError(
                "Could not create product 'Notipus': you have reached the maximum 1 "
                "products allowed by your plan. [403]",
                resource="product",
            )
        raise RuntimeError("the upstream service returned an unexpected response")

    monkeypatch.setattr(apply_mod, "apply_plan", fake_apply)

    options = WizardOptions(
        token="t-fake",
        api_base_url="https://app.sbomify.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=False,
    )
    app = WizardApp(options)
    async with app.run_test(size=(width, height)) as pilot:
        app.state.api = _MagicMock()
        app.state.workspace = WorkspaceSnapshot(products=[{"id": "p1", "name": "Existing Product"}], team_key="acme")
        app.state.plan.create_product = "Notipus"
        app.push_screen(ApplyScreen())
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        await pilot.pause()

        screen = app.screen
        assert isinstance(screen, ApplyScreen)

        banner = screen.query_one("#apply-error-banner")
        geometry = screen._compositor.full_map.get(banner)
        assert geometry is not None and geometry.region.height > 0, "error banner never rendered"
        assert geometry.region.bottom <= height, (
            f"error banner at rows {geometry.region.y}..{geometry.region.bottom} on a {width}x{height} terminal"
        )

        assert not _offscreen_buttons(screen), "recovery buttons are off-screen after a failure"

        rendered = "\n".join(strip.text for strip in screen._compositor.render_strips())
        assert "[403]" not in rendered, "HTTP status code leaked into the UI"
        # The hourglass must not still be hovering over a finished, failed run.
        assert "Applying" not in rendered, "panel still claims the apply is in progress"


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
