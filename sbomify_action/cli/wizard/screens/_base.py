"""Shared screen scaffolding for the wizard.

``WizardScreen`` provides the consistent visual frame every screen
uses: a Textual ``Header``, a body region the subclass fills, and a
``Footer`` with the keybind hints. Subclasses override
``compose_body`` and the ``step_index`` / ``step_title`` class vars.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.app import WizardApp


TOTAL_STEPS = 6
"""Number of user-facing wizard steps (the apply / done phases share
the last step in the crumb, so we display 6 not 8)."""


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
        # 6-dot progress bar: filled past + current, empty future.
        dots = "".join("[#8A7DFF]●[/]" if i <= self.step_index else "[#37306B]○[/]" for i in range(1, TOTAL_STEPS + 1))
        return f"{dots}  [b]Step {self.step_index} of {TOTAL_STEPS}[/b]  ·  {self.step_title}"

    @property
    def wizard(self) -> "WizardApp":
        """Typed accessor for the app — avoids cast boilerplate at call sites."""
        from sbomify_action.cli.wizard.app import WizardApp

        app = self.app
        assert isinstance(app, WizardApp)
        return app
