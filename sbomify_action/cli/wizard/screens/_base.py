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

from typing import TYPE_CHECKING, ClassVar

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.app import WizardApp


TOTAL_STEPS = 7


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

    def _crumb_markup(self) -> str:
        """Numbered position chip + connected segment track + step title.

        Visually:

            01 / 06  │  ●━━━○━━━○━━━○━━━○━━━○  │  Welcome
            03 / 06  │  ●━━━●━━━●━━━○━━━○━━━○  │  Authenticate

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
