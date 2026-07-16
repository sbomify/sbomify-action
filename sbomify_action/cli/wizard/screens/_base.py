"""Shared screen scaffolding for the wizard.

``WizardScreen`` provides the consistent visual frame every screen
uses: a Textual ``Header``, a body region the subclass fills, and a
``Footer`` with keybind hints. Subclasses override
``compose_body`` and the ``step_index`` / ``step_title`` class vars.

The crumb at the top of every screen renders the wizard's progress
as a connected segmented track + a numbered position chip + the
current step title. Keeping it consistent across screens means users
always see where they are without needing to re-orient.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, ClassVar

from textual import events
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, RadioSet, Static

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.app import WizardApp


TOTAL_STEPS = 9

# Responsive breakpoints (terminal cells). The wizard is a fit-to-viewport
# TUI — nothing scrolls — so every screen has to render inside whatever the
# terminal gives us. Three tiers, each guaranteed to fit at its lower bound:
#
#   * Below MIN_* even the fully-compacted layout can't fit, so we replace
#     the body with a "resize your terminal" prompt (k9s / lazygit do the
#     same). 80x24 is the classic default terminal size.
#   * Below ROOMY_* we shed the roomy "comfortable" layout: the welcome
#     "what we'll do" preview (redundant with the progress crumb) is
#     dropped and paddings tighten, via the ``-compact`` class.
#   * The welcome mascot is governed separately by ART_* — it's the single
#     tallest element, but it still fits in far more terminals than the
#     full comfortable layout does, so we keep showing the art whenever
#     there's room for it (its own ``-no-art`` opt-out below the bound).
MIN_WIDTH = 80
MIN_HEIGHT = 24
ART_WIDTH = 100
ART_HEIGHT = 42
PREVIEW_HEIGHT = 48
ROOMY_WIDTH = 100
ROOMY_HEIGHT = 63


class WizardScreen(Screen[None]):
    """Common header + body + footer frame for every wizard phase."""

    step_index: ClassVar[int] = 0
    step_title: ClassVar[str] = ""

    # Plain instance attribute so screens that compute the subtitle from
    # constructor args can assign in __init__ without mypy complaints.
    step_subtitle: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(classes="wizard-body"):
            yield Static(self._crumb_markup(), classes="wizard-step-crumb")
            if self.step_subtitle:
                yield Static(self.step_subtitle, classes="wizard-subtitle")
            yield from self.compose_body()
        # Shown (and the body hidden) only when the terminal is below the
        # minimum supported size — see ``_apply_responsive``. The text is
        # filled in on resize so it can quote the live dimensions.
        yield Static("", id="too-small")
        yield Footer()

    def on_resize(self, event: events.Resize) -> None:
        self._apply_responsive(event.size.width, event.size.height)

    def _apply_responsive(self, width: int, height: int) -> None:
        """Toggle responsive classes from the current terminal size.

        Three independent toggles (CSS in ``styles.tcss`` keys off them):

        * ``-tiny`` — below the supported minimum: swap the whole body for
          a resize prompt.
        * ``-compact`` — below the roomy bound: drop the "what we'll do"
          preview and tighten padding so the content still fits.
        * ``-no-art`` — below the art bound: hide the welcome mascot. Kept
          separate from ``-compact`` because the art fits in many terminals
          that are still too short for the full comfortable layout, so a
          "compact but show the art" middle tier is the common case.
        * ``-no-preview`` — below the preview bound: hide the welcome "what
          we'll do" list. Also its own bound (the list is short text that
          fits well below the roomy layout) so we keep showing it rather
          than leaving the screen half-empty on a medium-tall terminal.
        """
        too_small = width < MIN_WIDTH or height < MIN_HEIGHT
        roomy = width >= ROOMY_WIDTH and height >= ROOMY_HEIGHT
        show_art = width >= ART_WIDTH and height >= ART_HEIGHT
        show_preview = height >= PREVIEW_HEIGHT
        self.set_class(too_small, "-tiny")
        self.set_class(not too_small and not roomy, "-compact")
        self.set_class(not too_small and not show_art, "-no-art")
        self.set_class(not too_small and not show_preview, "-no-preview")
        if too_small:
            try:
                self.query_one("#too-small", Static).update(self._too_small_markup(width, height))
            except NoMatches:
                # The guard node isn't mounted yet (resize fired mid-compose);
                # the next resize repaints. Narrow to NoMatches so a real
                # rendering/markup error still surfaces instead of being swallowed.
                pass

    @staticmethod
    def _too_small_markup(width: int, height: int) -> str:
        """Centered 'please resize' notice quoting the live terminal size."""
        return (
            "[b #F4B57F]⚠  Terminal too small[/]\n\n"
            f"[#CBCCCE]Current size[/]  [b]{width}×{height}[/]\n"
            f"[#CBCCCE]Minimum size[/]  [b]{MIN_WIDTH}×{MIN_HEIGHT}[/]\n\n"
            "[#8A7DFF]Resize this window to continue.[/]"
        )

    def compose_body(self) -> ComposeResult:
        """Override to yield body widgets (panels, inputs, tables, …)."""
        return iter(())

    def route_enter(self, forward: Callable[[], None]) -> None:
        """Route a screen-level Enter to the right action based on focus.

        Every wizard screen declares ``Binding("enter", "submit", priority=True)``
        so an ``Input`` or ``SelectionList`` can't swallow Enter and strand
        the user (eg the password Input on Authenticate). But that same
        priority binding hijacks Enter from focused widgets that DO want
        to own it:

        - Focused non-primary ``Button`` (Back, Cancel) → press it
          instead of advancing forward.
        - Focused ``RadioSet`` → commit the highlighted radio. Without
          this, Enter inside a RadioSet skips past the radio selection
          entirely and jumps to the next screen (see the profile-picker
          regression: pressing Enter on the augmentation RadioSet to
          select 'Use a contact profile' advanced the screen before the
          radio could change).
        - Anything else → run ``forward`` (the screen's advance action).

        Primary buttons fall through too, so Enter on a focused primary
        button still does what the same screen action does anyway.
        """
        focused = self.focused
        if isinstance(focused, Button) and focused.variant != "primary":
            focused.press()
            return
        if isinstance(focused, RadioSet):
            action = getattr(focused, "action_toggle_button", None)
            if callable(action):
                action()
                return
        forward()

    def _crumb_markup(self) -> str:
        """Numbered position chip + connected segment track + step title.

        Visually:

            01 / 08  │  ●━━━○━━━○━━━○━━━○━━━○━━━○━━━○  │  Welcome
            03 / 08  │  ●━━━●━━━●━━━○━━━○━━━○━━━○━━━○  │  Authenticate

        - Filled purple dots are completed steps.
        - The current dot is bolded so it stands out from past steps.
        - Connector glyphs darken between unfinished steps to hint at
          progress direction.
        """
        chips: list[str] = []
        for i in range(1, TOTAL_STEPS + 1):
            if i < self.step_index:
                chips.append("[#8A7DFF]●[/]")
            elif i == self.step_index:
                chips.append("[b #8A7DFF]●[/]")
            else:
                chips.append("[#37306B]○[/]")
        connector_done = "[#8A7DFF]━━[/]"
        connector_pending = "[#37306B]━━[/]"
        track_parts: list[str] = []
        for i, chip in enumerate(chips, start=1):
            track_parts.append(chip)
            if i < TOTAL_STEPS:
                track_parts.append(connector_done if i < self.step_index else connector_pending)
        track = "".join(track_parts)
        position = f"[b #8A7DFF]{self.step_index:02d}[/][#5E5E5E] / {TOTAL_STEPS:02d}[/]"
        divider = "[#37306B]│[/]"
        return f"  {position}  {divider}  {track}  {divider}  [b]{self.step_title}[/]"

    @property
    def wizard(self) -> "WizardApp":
        """Typed accessor for the app — avoids cast boilerplate at call sites."""
        from sbomify_action.cli.wizard.app import WizardApp

        app = self.app
        assert isinstance(app, WizardApp)
        return app
