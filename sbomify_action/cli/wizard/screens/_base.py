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

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, RadioSet, Static

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.app import WizardApp


TOTAL_STEPS = 8


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
        yield Footer()

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
