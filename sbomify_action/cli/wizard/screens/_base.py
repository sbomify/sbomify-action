"""Shared scaffolding for wizard screens.

`WizardScreen` provides the consistent visual frame every screen uses:

  ┌─ Header ─────────────────────────────────────────────────────────┐
  │ sbomify wizard                       From zero to SBOM hero       │
  └───────────────────────────────────────────────────────────────────┘
  ▌ Step N of M · <title>
  ▌ <subtitle>

    <body — supplied by subclass via `compose_body()`>

  ┌─ Footer ─────────────────────────────────────────────────────────┐
  │  ↑/↓ navigate · enter select · ctrl-c cancel                      │
  └───────────────────────────────────────────────────────────────────┘

Subclasses override `compose_body()` and `step_index` / `step_title`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.app import WizardApp


class WizardScreen(Screen[None]):
    """Common header + body + footer layout for every wizard phase."""

    #: 1-indexed step ordinal shown in the progress crumb. Override.
    step_index: ClassVar[int] = 0
    #: Short title shown in the progress crumb. Override.
    step_title: ClassVar[str] = ""
    #: Optional one-line description rendered under the crumb. Override.
    step_subtitle: ClassVar[str] = ""

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
        app = self.app
        total = getattr(app, "total_steps", 6)
        # 6-dot progress bar: filled past + current, empty future
        dots = "".join("[#8A7DFF]●[/]" if i < self.step_index else "[#37306B]○[/]" for i in range(1, total + 1))
        return f"{dots}  [b]Step {self.step_index} of {total}[/b]  ·  {self.step_title}"

    @property
    def wizard(self) -> "WizardApp":
        """Typed accessor for the app (avoids `cast` clutter in subclasses)."""
        from sbomify_action.cli.wizard.app import WizardApp

        app = self.app
        assert isinstance(app, WizardApp)
        return app
