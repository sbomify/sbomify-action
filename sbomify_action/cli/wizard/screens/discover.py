"""Discover screen — multi-select lockfiles to track."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, SelectionList, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class DiscoverScreen(WizardScreen):
    """Phase 2 — multi-select discovered lockfiles."""

    step_index = 2
    step_title = "Discover lockfiles"
    step_subtitle = "Pick the lockfiles the SBOM workflow should track."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("space", "toggle_selection", "Toggle", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Lockfiles"
        panel.border_subtitle = f"{len(self.wizard.state.discovered)} found"
        with panel:
            yield Static(
                "Use [b]Space[/] to toggle each lockfile, [b]Enter[/] when you're done.",
                classes="wizard-muted",
            )
            yield SelectionList[int](id="lockfile-list")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        sel = self.query_one("#lockfile-list", SelectionList)
        for idx, lf in enumerate(self.wizard.state.discovered):
            label = f"{lf.rel_path}  [#5E5E5E]({lf.ecosystem})[/]"
            sel.add_option((label, idx, True))  # default-selected
        sel.focus()

    def action_toggle_selection(self) -> None:
        """Custom toggle action — Textual's built-in `action_toggle` is generic."""
        self.query_one("#lockfile-list", SelectionList).action_select()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        sel = self.query_one("#lockfile-list", SelectionList)
        indices = list(sel.selected)
        if not indices:
            self.app.bell()
            return
        self.wizard.state.selected = [self.wizard.state.discovered[i] for i in indices]
        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen

        self.wizard.push_screen(AuthenticateScreen())
